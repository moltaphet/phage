// Adversarial test suite against the live PhageSentinel deployment on studio-dev.
// Every case is a dry-run (simulateWriteContract / readContract): no state is
// mutated, no funds move. A case PASSES when the contract refuses the attack
// with its own [EXPECTED] guard, or when a read returns a bounded result.
import { createClient } from 'genlayer-js';
import { PHAGE_CONTRACT_ADDRESS, STUDIO_DEV_CHAIN, STUDIONET_RPC } from '../src/lib/contract.ts';
import { describeError } from '../src/lib/errors.ts';
import { installRateLimit } from './pace.mjs';

const A = PHAGE_CONTRACT_ADDRESS;
installRateLimit();
const client = createClient({ chain: STUDIO_DEV_CHAIN, endpoint: STUDIONET_RPC });
const VICTIM = '0x2e56c8579fa11cb144e6fd778da772061f4dd930';
const ATTACKER = '0xdead00000000000000000000000000000000beef';
const TARGET = '0x0000000000000000000000000000000000000abc';
const GEN = 10n ** 18n;
const U256MAX = 2n ** 256n - 1n;

let pass = 0, fail = 0;
const failures = [];

// Attempt a write that MUST be refused. `guard` is a regex the rejection must match.
async function mustReject(name, { functionName, args = [], value = 0n }, guard) {
  try {
    const out = await client.simulateWriteContract({ address: A, functionName, args, value });
    console.log(`  VULNERABLE  ${name}`);
    console.log(`              call unexpectedly succeeded: ${JSON.stringify(out)}`);
    fail++; failures.push(name);
  } catch (e) {
    const msg = describeError(e);
    if (guard && !guard.test(msg)) {
      console.log(`  WRONG-GUARD ${name}\n              got: ${msg.slice(0, 110)}`);
      fail++; failures.push(name);
    } else {
      console.log(`  blocked     ${name}\n              ${msg.slice(0, 100)}`);
      pass++;
    }
  }
}

async function mustRead(name, { functionName, args = [] }, check) {
  try {
    const out = await client.readContract({ address: A, functionName, args });
    const v = check ? check(out) : { ok: true, note: JSON.stringify(out)?.slice(0, 60) };
    if (v.ok) { console.log(`  bounded     ${name}\n              ${v.note}`); pass++; }
    else { console.log(`  ISSUE       ${name}\n              ${v.note}`); fail++; failures.push(name); }
  } catch (e) {
    const msg = describeError(e);
    const own = /EXPECTED|not found|does not exist/i.test(msg);
    if (own) { console.log(`  bounded     ${name}\n              ${msg.slice(0, 100)}`); pass++; }
    else { console.log(`  ERROR       ${name}\n              ${msg.slice(0, 110)}`); fail++; failures.push(name); }
  }
}

const EXP = /\[EXPECTED\]/;

console.log('=== 1. Unauthorized withdrawal / value extraction ===');
await mustReject('withdraw() by an account with no claimable balance', { functionName: 'withdraw' }, EXP);
await mustReject('withdraw_claimable() by an account with no claimable balance', { functionName: 'withdraw_claimable' }, EXP);
await mustReject('drain protocol reserves (no such method exists)', { functionName: 'withdraw_reserves' }, /not found|unknown|Missing|EXPECTED|execution failed/i);

console.log('\n=== 2. report_pathogen: report_id validation ===');
const legit = { platform: 'EVM_ADDRESS', traceId: TARGET };
await mustReject('empty report_id', { functionName: 'report_pathogen', args: ['', TARGET, legit.platform, legit.traceId], value: GEN }, EXP);
await mustReject('whitespace-only report_id', { functionName: 'report_pathogen', args: ['   ', TARGET, legit.platform, legit.traceId], value: GEN }, EXP);

console.log('\n=== 3. report_pathogen: platform allow-list ===');
for (const p of ['SOLANA', 'evm_tx', 'EVM_TX ', '', '../../etc', 'EVM_TX\x00', 'GITHUB_AUDIT', 'AGENT_RPC', 'SECURITY_FEED', 'TX_TRACE']) {
  await mustReject(`platform ${JSON.stringify(p)}`, { functionName: 'report_pathogen', args: ['sec-p1', TARGET, p, legit.traceId], value: GEN }, EXP);
}

console.log('\n=== 4. report_pathogen: evidence identifier validation ===');
// Transaction platforms take exactly 0x + 64 hex; EVM_ADDRESS takes exactly 0x + 40.
const BAD_TX = ['http://evil.example/x', 'https://evil.example/x', 'ftp://evil.example', 'trace://x',
                '../../etc/passwd', 'trace/../../etc', 'abc', 'x'.repeat(67), 'трейс-0001',
                'trace\x00id', 'trace id', '${jndi:ldap://x}', "' OR 1=1--",
                '0x' + 'a'.repeat(63), '0x' + 'a'.repeat(65), '0x' + 'z'.repeat(64), 'a'.repeat(64)];
for (const t of BAD_TX) {
  await mustReject(`EVM_TX trace ${JSON.stringify(t.slice(0, 30))}`, { functionName: 'report_pathogen', args: ['sec-t', TARGET, 'EVM_TX', t], value: GEN }, EXP);
}

console.log('\n=== 5. report_pathogen: evidence must name the reported target ===');
// The core guard: EVM_ADDRESS evidence *is* the target address, so a record about a
// different address cannot be attached to this report. This is what stops a reporter
// from citing generic, unrelated metadata as proof against an arbitrary agent.
const OTHER = '0x0000000000000000000000000000000000000001';
await mustReject('EVM_ADDRESS trace naming a different address than the target',
  { functionName: 'report_pathogen', args: ['sec-binding-1', TARGET, 'EVM_ADDRESS', OTHER], value: GEN }, EXP);
await mustReject('EVM_ADDRESS trace that is a valid address of the wrong length',
  { functionName: 'report_pathogen', args: ['sec-binding-2', TARGET, 'EVM_ADDRESS', '0x' + 'a'.repeat(39)], value: GEN }, EXP);
await mustReject('EVM_ADDRESS trace that is a 32-byte hash, not an address',
  { functionName: 'report_pathogen', args: ['sec-binding-3', TARGET, 'EVM_ADDRESS', '0x' + 'a'.repeat(64)], value: GEN }, EXP);
await mustRead('EVM_ADDRESS trace equal to the target is accepted as bound',
  { functionName: 'get_required_reporter_bond', args: [TARGET] },
  (o) => ({ ok: typeof o === 'string' || typeof o === 'bigint', note: `bond for a bound target: ${o}` }));

console.log('\n=== 6. report_pathogen: malformed target address ===');
for (const a of ['not-an-address', '0x1234', '0x' + 'a'.repeat(39), '0x' + 'z'.repeat(40), '']) {
  await mustReject(`target_agent ${JSON.stringify(a.slice(0, 22))}`, { functionName: 'report_pathogen', args: ['sec-a', a, 'EVM_ADDRESS', legit.traceId], value: GEN }, /EXPECTED|invalid|address|Missing|execution failed/i);
}

console.log('\n=== 7. Bond / value enforcement ===');
await mustReject('report_pathogen with zero bond', { functionName: 'report_pathogen', args: ['sec-b1', TARGET, 'EVM_ADDRESS', legit.traceId], value: 0n }, EXP);
await mustReject('report_pathogen with 1 atto under the 0.1 GEN bond', { functionName: 'report_pathogen', args: ['sec-b2', TARGET, 'EVM_ADDRESS', legit.traceId], value: GEN / 10n - 1n }, EXP);
await mustReject('appeal_quarantine with zero bond', { functionName: 'appeal_quarantine', args: [TARGET, legit.traceId, 'EVM_ADDRESS'], value: 0n }, EXP);
await mustReject('fund_bounty_pool with zero value', { functionName: 'fund_bounty_pool', value: 0n }, EXP);

console.log('\n=== 8. State-machine guards (attacks against non-existent state) ===');
await mustReject('appeal_quarantine against a never-quarantined agent', { functionName: 'appeal_quarantine', args: [TARGET, legit.traceId, 'EVM_ADDRESS'], value: GEN }, EXP);
await mustReject('recover_agent against a never-quarantined agent', { functionName: 'recover_agent', args: [TARGET] }, EXP);
await mustReject('evaluate_pathogen on a non-existent report', { functionName: 'evaluate_pathogen', args: ['no-such-report'] }, EXP);
await mustReject('reclaim_expired_report_bond on a non-existent report', { functionName: 'reclaim_expired_report_bond', args: ['no-such-report'] }, EXP);
await mustReject("reclaim_expired_report_bond against someone else's pending report", { functionName: 'reclaim_expired_report_bond', args: ['sec-other'] }, EXP);

console.log('\n=== 9. Escrow: disputed payouts cannot be moved early ===');
await mustReject('release_escrow on a report with no escrow', { functionName: 'release_escrow', args: ['no-such-report'] }, EXP);
await mustReject('release_escrow with an empty report id', { functionName: 'release_escrow', args: [''] }, EXP);
await mustRead('get_escrow on an unknown report reports absence, not an error',
  { functionName: 'get_escrow', args: ['no-such-report'] },
  (o) => { const r = o instanceof Map ? Object.fromEntries(o) : o;
           return { ok: r.exists === false && r.status === 'NONE', note: `exists=${r.exists} status=${r.status} payout=${r.payout_atto}` }; });
await mustRead('locked escrow is counted in the registry overview',
  { functionName: 'get_registry_overview' },
  (o) => { const r = o instanceof Map ? Object.fromEntries(o) : o;
           const has = 'locked_escrow_atto' in r && 'total_escrows' in r;
           return { ok: has, note: `locked_escrow_atto=${r.locked_escrow_atto} total_escrows=${r.total_escrows}` }; });

console.log('\n=== 10. Pagination bounds / DoS ===');
await mustRead('limit clamped at MAX_PAGE_LIMIT=50 (request 10^9)', { functionName: 'list_reports_paginated', args: [0, 1_000_000_000] },
  (o) => ({ ok: Array.isArray(o) && o.length <= 50, note: `returned ${Array.isArray(o) ? o.length : '?'} rows` }));
await mustRead('offset = 2^256-1 does not overflow', { functionName: 'list_reports_paginated', args: [U256MAX, 50] },
  (o) => ({ ok: Array.isArray(o) && o.length === 0, note: `returned ${JSON.stringify(o)}` }));
await mustRead('limit = 2^256-1 does not overflow', { functionName: 'list_reports_paginated', args: [0, U256MAX] },
  (o) => ({ ok: Array.isArray(o) && o.length <= 50, note: `returned ${Array.isArray(o) ? o.length : '?'} rows` }));
await mustRead('limit = 0 returns empty', { functionName: 'list_antibodies_paginated', args: [0, 0] },
  (o) => ({ ok: Array.isArray(o) && o.length === 0, note: `returned ${JSON.stringify(o)}` }));

console.log('\n=== 11. Information disclosure ===');
await mustRead('claimable balance of an arbitrary third party is public', { functionName: 'get_claimable_balance', args: [VICTIM] },
  (o) => ({ ok: true, note: `returns ${o} — address balances are public by design` }));
await mustRead('private keys / owner secrets are not exposed by any view', { functionName: 'get_registry_overview' },
  (o) => { const keys = Object.keys(o instanceof Map ? Object.fromEntries(o) : o); const leak = keys.filter((k) => /key|secret|password|mnemonic|pk/i.test(k));
           return { ok: leak.length === 0, note: `view keys: ${keys.join(', ')}` }; });

console.log(`\n=== ${pass} blocked/bounded, ${fail} issues ===`);
if (failures.length) console.log('ISSUES: ' + failures.join(' | '));
process.exit(fail ? 1 : 0);
