// End-to-end contract<->frontend test against the live studio-dev deployment.
// Phase A: every view method in the ABI.
// Phase B: every write method, dry-run through the SAME client the frontend builds.
// Phase C: every read function the frontend actually exports.
import { createClient, isSuccessful } from 'genlayer-js';
import { PHAGE_CONTRACT_ADDRESS, STUDIO_DEV_CHAIN, STUDIONET_RPC } from '../src/lib/contract.ts';
import * as fe from '../src/lib/genlayer.ts';
import { describeError } from '../src/lib/errors.ts';
import { installRateLimit } from './pace.mjs';

installRateLimit();

const A = PHAGE_CONTRACT_ADDRESS;
const ZERO = '0x0000000000000000000000000000000000000000';
const probe = '0x0000000000000000000000000000000000000001';
const calldata = STUDIO_DEV_CHAIN;
console.log(`chain=${calldata.name} id=${calldata.id} rpc=${STUDIONET_RPC} contract=${A}\n`);
const client = createClient({ chain: STUDIO_DEV_CHAIN, endpoint: STUDIONET_RPC });
const J = (_k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v);
const brief = (v) => { const s = JSON.stringify(v, J); return s === undefined ? String(v) : s.length > 110 ? s.slice(0, 110) + '…' : s; };

let pass = 0, revert = 0, fail = 0;

console.log('=== PHASE A: view methods (15) ===');
const VIEWS = [
  ['get_registry_overview', []],
  ['is_quarantined', [probe]],
  ['get_quarantine_info', [probe]],
  ['get_defended_appeals_count', [probe]],
  ['get_required_reporter_bond', [probe]],
  ['get_claimable_balance', [ZERO]],
  ['get_antibody', ['nope']],
  ['get_report', ['nope']],
  ['get_appeal', ['nope']],
  ['get_escrow', ['nope']],
  ['list_quarantined_agents_paginated', [0, 50]],
  ['list_antibodies_paginated', [0, 50]],
  ['list_reports_paginated', [0, 50]],
  ['list_quarantined_agents', []],
  ['list_antibodies', []],
];
for (const [fn, args] of VIEWS) {
  try {
    const out = await client.readContract({ address: A, functionName: fn, args });
    console.log(`  OK    ${fn.padEnd(36)} ${brief(out)}`); pass++;
  } catch (e) {
    const msg = describeError(e);
    const own = /EXPECTED|does not exist|not found|unknown/i.test(msg);
    console.log(`  ${own ? 'REVERT' : 'FAIL  '} ${fn.padEnd(36)} ${msg.slice(0, 100)}`);
    own ? revert++ : fail++;
  }
}

console.log('\n=== PHASE B: write methods, dry-run (all 13) ===');
// Values mirror what the UI sends. The point is not that the call succeeds —
// most must revert on a fresh contract — but that the node ACCEPTS the calldata
// and reaches the contract, which is what a v1 client could not do.
const TX = '0x' + 'a'.repeat(64);
const WRITES = [
  ['fund_bounty_pool', [], 10_000_000_000_000_000n],
  ['report_pathogen', ['fe-test-tx', probe, 'EVM_TX', TX], 10_000_000_000_000_000n],
  ['evaluate_pathogen', ['fe-test-1'], 0n],
  ['file_appeal', ['fe-test-1', TX, 'EVM_TX'], 200_000_000_000_000_000n],
  ['resolve_appeal', ['appeal-fe-test-1-1'], 0n],
  ['expire_appeal', ['appeal-fe-test-1-1'], 0n],
  ['claim_payout', ['fe-test-1'], 0n],
  ['release_escrow', ['fe-test-1'], 0n],
  ['recover_agent', [probe], 0n],
  ['reclaim_expired_report_bond', ['fe-test-1'], 0n],
  ['withdraw', [], 0n],
  ['withdraw_claimable', [], 0n],
];
for (const [fn, args, value] of WRITES) {
  try {
    const out = await client.simulateWriteContract({ address: A, functionName: fn, args, value });
    console.log(`  OK    ${fn.padEnd(36)} ${brief(out)}`); pass++;
  } catch (e) {
    const msg = describeError(e);
    const encoded = /malformed_entry|Missing or invalid parameters|cannot decode/i.test(msg);
    console.log(`  ${encoded ? 'FAIL  ' : 'REVERT'} ${fn.padEnd(36)} ${msg.slice(0, 100)}`);
    encoded ? fail++ : revert++;
  }
}

console.log('\n=== PHASE C: frontend exported read functions ===');
const FNS = [
  ['loadProtocolState()', () => fe.loadProtocolState()],
  ['inspectAgent(probe)', () => fe.inspectAgent(probe)],
  ['getRequiredReporterBondGen(probe)', () => fe.getRequiredReporterBondGen(probe)],
  ['getRequiredReporterBondAtto(probe)', () => fe.getRequiredReporterBondAtto(probe)],
  ['getClaimableBalanceGen(zero)', () => fe.getClaimableBalanceGen(ZERO)],
  ['getReport("nope")', () => fe.getReport('nope')],
  ['getAppeal("nope")', () => fe.getAppeal('nope')],
  ['getEscrow("nope")', () => fe.getEscrow('nope')],
  ['getTotalAppeals()', () => fe.getTotalAppeals()],
];
for (const [label, run] of FNS) {
  try {
    const out = await run();
    console.log(`  OK    ${label.padEnd(36)} ${brief(out)}`); pass++;
  } catch (e) {
    const msg = describeError(e);
    const own = /EXPECTED|does not exist|not found|unknown/i.test(msg);
    console.log(`  ${own ? 'REVERT' : 'FAIL  '} ${label.padEnd(36)} ${msg.slice(0, 100)}`);
    own ? revert++ : fail++;
  }
}

console.log(`\n=== ${pass} ok, ${revert} contract reverts (expected), ${fail} failures ===`);
process.exit(fail ? 1 : 0);
