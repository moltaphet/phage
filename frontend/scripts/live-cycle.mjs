// One real end-to-end cycle against the live PhageSentinel deployment.
//
// Every other script in this directory is read-only or a dry run. This one actually
// spends: it escrows the 0.1 GEN reporter bond, runs the non-deterministic consensus
// engine for real, and lets the resulting tier decide whether the bond is refunded,
// slashed, or paid out as a bounty. That is the only way to prove the consensus path
// works on-chain — `simulateWriteContract` never reaches `run_nondet`.
//
// It drives the contract through the frontend's own write helpers (`reportPathogen`,
// `evaluatePathogen`, `waitForReceipt`), so the fee derivation and receipt handling
// under test are the same code the dApp runs. The one difference is the signer: the
// dApp routes eth_sendTransaction to MetaMask, while this signs locally from a private
// key in GL_PK, so it can run headless.
//
//   GL_PK=$(security find-generic-password -s genlayer-cli -a account:<name> -w) \
//     node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs \
//     ./scripts/live-cycle.mjs [--dry] [--report-id <id>] [--platform <p>] [--trace <id>]
//
// The default platform is EVM_ADDRESS, whose evidence identifier *is* the reported
// target — the contract requires them to match — and which resolves to a live record
// for any address. Pass `--platform EVM_TX --trace 0x<64 hex>` to drive it from a
// transaction instead; the target must then be a party to that transaction, which the
// contract checks before the model is consulted.
import { createClient } from 'genlayer-js';
import { privateKeyToAccount } from 'viem/accounts';
import { PHAGE_CONTRACT_ADDRESS, STUDIO_DEV_CHAIN, STUDIONET_RPC } from '../src/lib/contract.ts';
import * as fe from '../src/lib/genlayer.ts';
import { describeError } from '../src/lib/errors.ts';
import { installRateLimit } from './pace.mjs';

installRateLimit();

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const DRY = argv.includes('--dry');

const PK = process.env.GL_PK;
if (!PK) {
  console.error('GL_PK is not set. See the header of this file for how to pass it.');
  process.exit(2);
}

const REPORT_ID = flag('report-id', 'live-cycle-1');
// A burn address: quarantining it is the intended effect and affects nobody real.
const TARGET = flag('target', '0x000000000000000000000000000000000000dEaD');
const PLATFORM = flag('platform', 'EVM_ADDRESS');
// EVM_ADDRESS evidence has to name the target, so the trace defaults to the target
// itself. A transaction platform needs a real 32-byte hash instead.
const TRACE_ID = flag('trace', PLATFORM === 'EVM_ADDRESS' ? TARGET : '');
const BOND = 100_000_000_000_000_000n; // 0.1 GEN — MIN_REPORTER_BOND
const J = (_k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v);

const account = privateKeyToAccount(PK.startsWith('0x') ? PK : `0x${PK}`);
const client = createClient({ chain: STUDIO_DEV_CHAIN, endpoint: STUDIONET_RPC, account });

console.log(`contract : ${PHAGE_CONTRACT_ADDRESS}`);
console.log(`signer   : ${account.address}`);
console.log(`report   : ${REPORT_ID}  target=${TARGET}`);
console.log(`platform : ${PLATFORM}  trace=${TRACE_ID}`);
console.log(`mode     : ${DRY ? 'DRY RUN — simulates only, spends nothing' : `LIVE — escrows ${BOND} atto`}\n`);

async function step(label, fn) {
  process.stdout.write(`── ${label}\n`);
  const t0 = Date.now();
  try {
    const out = await fn();
    if (out !== undefined) console.log(`   ${JSON.stringify(out, J)?.slice(0, 300) ?? out}`);
    console.log(`   ok (${((Date.now() - t0) / 1000).toFixed(1)}s)\n`);
    return out;
  } catch (e) {
    console.log(`   FAILED after ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    console.log(`   ${describeError(e)}\n`);
    throw e;
  }
}

// Phase 0 — what we are starting from, so the deltas below are verifiable.
const before = await step('read state before', () => fe.loadProtocolState());

// Phase 1 — escrow the bond and register the report. This is a payable call, which is
// why `genlayer write` cannot drive it: the CLI hardcodes value 0.
if (DRY) {
  await step('simulate report_pathogen', async () => {
    const out = await client.simulateWriteContract({
      address: PHAGE_CONTRACT_ADDRESS,
      functionName: 'report_pathogen',
      args: [REPORT_ID, TARGET, PLATFORM, TRACE_ID],
      value: BOND,
    });
    return out === null || out === undefined ? 'accepted' : out;
  });
  // A simulation does not persist, so the report the previous call "created" is not
  // there to evaluate. That failure is the expected shape of a dry run, not a problem
  // with the contract — it is reported rather than thrown.
  try {
    await step('simulate evaluate_pathogen', async () => {
      const out = await client.simulateWriteContract({
        address: PHAGE_CONTRACT_ADDRESS,
        functionName: 'evaluate_pathogen',
        args: [REPORT_ID],
      });
      return out === null || out === undefined ? 'accepted' : out;
    });
  } catch {
    console.log('   (expected: the simulated report was never persisted, so there is');
    console.log('    nothing to evaluate. Only a real report — no --dry — reaches run_nondet.)\n');
  }
  console.log('Dry run complete — nothing was spent and no state changed.');
  process.exit(0);
}

const reportHash = await step('report_pathogen (escrow 0.1 GEN)', () =>
  fe.reportPathogen(client, {
    reportId: REPORT_ID,
    targetAgent: TARGET,
    platform: PLATFORM,
    traceId: TRACE_ID,
    bondAtto: BOND,
  }),
);
console.log(`   tx ${reportHash}\n`);
await step('wait for receipt', () => fe.waitForReceipt(client, reportHash));
const pending = await step('read report (expect PENDING)', () => fe.getReport(REPORT_ID));

// Phase 2 — the actual point of this script. `evaluate_pathogen` fetches the trace,
// runs leader_fn, and reaches consensus through run_nondet. This is the one call that
// no dry run can exercise.
const evalHash = await step('evaluate_pathogen (multi-LLM consensus)', () =>
  fe.evaluatePathogen(client, REPORT_ID),
);
console.log(`   tx ${evalHash}\n`);
await step('wait for receipt', () => fe.waitForReceipt(client, evalHash));

// Phase 3 — the verdict and everything it implies.
await step('read report (expect RESOLVED)', () => fe.getReport(REPORT_ID));
const resolved = await fe.getReport(REPORT_ID);
const tier = String(resolved?.evaluated_tier ?? '');
console.log(`   >>> tier: ${tier}\n`);

// `mapQuarantine` renders an absent antibody hash as the sentinel string 'NONE', which
// is truthy — so a plain `if (hash)` reads the literal antibody "NONE" and the node
// rejects it. Compare against the sentinel, not against emptiness.
try {
  const quarantine = await step('read quarantine for target', () => fe.inspectAgent(TARGET));
  if (quarantine.antibody_hash && quarantine.antibody_hash !== 'NONE') {
    const sig = await step('read the minted antibody', () =>
      client.readContract({
        address: PHAGE_CONTRACT_ADDRESS,
        functionName: 'get_antibody',
        args: [quarantine.antibody_hash],
      }),
    );
    console.log(`   ${JSON.stringify(sig, J)}\n`);
  }
} catch {
  console.log('   (inspection failed — the writes above already settled; see the summary)\n');
}
const after = await step('read state after', () => fe.loadProtocolState());

// A quarantine verdict does not pay the reporter: the bond and bounty are escrowed for
// the length of the appeal window. Read it back so the settlement path is visible here
// rather than inferred from the tier.
const escrow = await fe.getEscrow(REPORT_ID);
if (escrow.exists) {
  console.log(`── escrow for ${REPORT_ID}`);
  console.log(`   status           ${escrow.status}`);
  console.log(`   held             ${escrow.bond_gen} GEN bond + ${escrow.payout_gen} GEN bounty`);
  console.log(`   locked until     ${escrow.locked_until_iso} (releasable now: ${escrow.is_releasable})`);
  console.log(`   release with     release_escrow("${REPORT_ID}") once the window closes\n`);
} else {
  console.log(`── no escrow opened for ${REPORT_ID} (the verdict carried no quarantine)\n`);
}

// Report the delta rather than asserting it: the tier is the LLM's verdict, so the
// balance movement is an outcome to observe, not a value to hardcode.
const num = (s) => Number(s ?? 0);
console.log('── summary');
console.log(`   tier             ${pending?.evaluated_tier || '(none while pending)'} -> ${tier}`);
console.log(`   reports          ${before.stats.total_reports_evaluated} -> ${after.stats.total_reports_evaluated}`);
console.log(`   quarantined      ${before.stats.total_quarantines_active} -> ${after.stats.total_quarantines_active}`);
console.log(`   antibodies       ${before.stats.total_antibodies_minted} -> ${after.stats.total_antibodies_minted}`);
console.log(`   bounty pool      ${before.stats.bounty_pool_gen} -> ${after.stats.bounty_pool_gen} GEN`);
console.log(`   reserves         ${before.stats.protocol_reserves_gen} -> ${after.stats.protocol_reserves_gen} GEN`);
console.log(`   disputed escrow  ${before.stats.locked_escrow_gen} -> ${after.stats.locked_escrow_gen} GEN`);
console.log(`   deposited        ${(num(after.stats.total_deposited_gen) - num(before.stats.total_deposited_gen)).toFixed(4)} GEN net in`);
const claimable = await fe.getClaimableBalanceGen(account.address);
console.log(`   claimable (you)  ${claimable} GEN`);
console.log(`\n   bond refunded intact, slashed to reserves, escrowed pending appeal, or paid`);
console.log(`   out as a bounty — whichever the tier above implies. Nothing is asserted here.`);
