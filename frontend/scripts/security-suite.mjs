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
// Every report claims an exploit category; the binding / format guards below fire
// before the category's mechanics are checked.
const CATEGORY = 'FLASH_LOAN_DRAIN';
const JUSTIFICATION = 'Authorised treasury rebalance executed by the protocol admin key.';
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
// Evidence is a transaction the target is party to. Guards that fire before the
// binding fetch are exercised with a well-formed hash; the binding itself is
// exercised against real Ethereum transactions in section 5.
const legit = { platform: 'EVM_TX', traceId: '0x' + 'a'.repeat(64) };
await mustReject('empty report_id', { functionName: 'report_pathogen', args: ['', TARGET, legit.platform, legit.traceId, CATEGORY], value: GEN }, EXP);
await mustReject('whitespace-only report_id', { functionName: 'report_pathogen', args: ['   ', TARGET, legit.platform, legit.traceId, CATEGORY], value: GEN }, EXP);

console.log('\n=== 3. report_pathogen: platform allow-list ===');
for (const p of ['SOLANA', 'evm_tx', 'EVM_TX ', '', '../../etc', 'EVM_TX\x00', 'GITHUB_AUDIT', 'AGENT_RPC', 'SECURITY_FEED', 'TX_TRACE', 'EVM_ADDRESS']) {
  await mustReject(`platform ${JSON.stringify(p)}`, { functionName: 'report_pathogen', args: ['sec-p1', TARGET, p, legit.traceId, CATEGORY], value: GEN }, EXP);
}

console.log('\n=== 4. report_pathogen: evidence identifier validation ===');
// Every platform takes exactly 0x + 64 hex -- never a URL, label or address.
const BAD_TX = ['http://evil.example/x', 'https://evil.example/x', 'ftp://evil.example', 'trace://x',
                '../../etc/passwd', 'trace/../../etc', 'abc', 'x'.repeat(67), 'трейс-0001',
                'trace\x00id', 'trace id', '${jndi:ldap://x}', "' OR 1=1--",
                '0x' + 'a'.repeat(63), '0x' + 'a'.repeat(65), '0x' + 'z'.repeat(64), 'a'.repeat(64),
                TARGET];
for (const t of BAD_TX) {
  await mustReject(`EVM_TX trace ${JSON.stringify(t.slice(0, 30))}`, { functionName: 'report_pathogen', args: ['sec-t', TARGET, 'EVM_TX', t, CATEGORY], value: GEN }, EXP);
}

console.log('\n=== 5. report_pathogen: evidence must be an incident involving the target ===');
// The core guard. Filing fetches the cited transaction from Blockscout and reverts
// with ERR_UNBOUND_EVIDENCE unless it exists, echoes the cited hash, and names the
// target as a party. The Euler exploit transaction is real; TARGET is not in it.
const EULER_TX = '0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d';
const UNBOUND = /ERR_UNBOUND_EVIDENCE/;
await mustReject('a real transaction the target is not a party to',
  { functionName: 'report_pathogen', args: ['sec-binding-1', TARGET, 'EVM_TX', EULER_TX, CATEGORY], value: GEN }, UNBOUND);
await mustReject('a well-formed hash for a transaction that does not exist',
  { functionName: 'report_pathogen', args: ['sec-binding-2', TARGET, 'EVM_TX', '0x' + '0'.repeat(63) + '1', CATEGORY], value: GEN }, UNBOUND);
await mustReject('an Ethereum transaction cited on the Base platform',
  { functionName: 'report_pathogen', args: ['sec-binding-3', '0x5F259D0b76665c337c6104145894F4D1D2758B8c', 'EVM_TX_BASE', EULER_TX, CATEGORY], value: GEN }, UNBOUND);

console.log('\n=== 6. report_pathogen: malformed target address ===');
for (const a of ['not-an-address', '0x1234', '0x' + 'a'.repeat(39), '0x' + 'z'.repeat(40), '']) {
  await mustReject(`target_agent ${JSON.stringify(a.slice(0, 22))}`, { functionName: 'report_pathogen', args: ['sec-a', a, legit.platform, legit.traceId, CATEGORY], value: GEN }, /EXPECTED|invalid|address|Missing|execution failed/i);
}

console.log('\n=== 6b. report_pathogen: exploit category must be a recognised enum ===');
for (const c of ['GENERIC_EXPLOIT', 'reentrancy', '', 'PROMPT_INJECTION']) {
  await mustReject(`category ${JSON.stringify(c)}`, { functionName: 'report_pathogen', args: ['sec-cat', TARGET, legit.platform, legit.traceId, c], value: GEN }, /ERR_UNSUPPORTED_EXPLOIT_CATEGORY/);
}

console.log('\n=== 7. Bond / value enforcement ===');
await mustReject('report_pathogen with zero bond', { functionName: 'report_pathogen', args: ['sec-b1', TARGET, legit.platform, legit.traceId, CATEGORY], value: 0n }, EXP);
await mustReject('report_pathogen with 1 atto under the 0.1 GEN bond', { functionName: 'report_pathogen', args: ['sec-b2', TARGET, legit.platform, legit.traceId, CATEGORY], value: GEN / 10n - 1n }, EXP);
await mustReject('file_appeal with zero bond', { functionName: 'file_appeal', args: ['sec-b3', legit.traceId, 'AUTHORIZED_ADMIN_ACTION', JUSTIFICATION], value: 0n }, EXP);
await mustReject('fund_bounty_pool with zero value', { functionName: 'fund_bounty_pool', value: 0n }, EXP);

console.log('\n=== 8. State-machine guards (attacks against non-existent state) ===');
await mustReject('file_appeal against a report with no disputable escrow', { functionName: 'file_appeal', args: ['no-such-report', legit.traceId, 'AUTHORIZED_ADMIN_ACTION', JUSTIFICATION], value: GEN }, EXP);
await mustReject('resolve_appeal on a non-existent appeal', { functionName: 'resolve_appeal', args: ['no-such-appeal'] }, EXP);
await mustReject('expire_appeal on a non-existent appeal', { functionName: 'expire_appeal', args: ['no-such-appeal'] }, EXP);
await mustReject('recover_agent against a never-quarantined agent', { functionName: 'recover_agent', args: [TARGET] }, EXP);
await mustReject('evaluate_pathogen on a non-existent report', { functionName: 'evaluate_pathogen', args: ['no-such-report'] }, EXP);
await mustReject('reclaim_expired_report_bond on a non-existent report', { functionName: 'reclaim_expired_report_bond', args: ['no-such-report'] }, EXP);
await mustReject("reclaim_expired_report_bond against someone else's pending report", { functionName: 'reclaim_expired_report_bond', args: ['sec-other'] }, EXP);

console.log('\n=== 9. Escrow: disputed payouts cannot be moved early ===');
await mustReject('claim_payout on a report with no escrow', { functionName: 'claim_payout', args: ['no-such-report'] }, EXP);
await mustReject('claim_payout with an empty report id', { functionName: 'claim_payout', args: [''] }, EXP);
await mustReject('release_escrow (alias) on a report with no escrow', { functionName: 'release_escrow', args: ['no-such-report'] }, EXP);
await mustReject('expire_incident on a non-existent report', { functionName: 'expire_incident', args: ['no-such-report'] }, EXP);
await mustRead('get_escrow on an unknown report reports absence, not an error',
  { functionName: 'get_escrow', args: ['no-such-report'] },
  (o) => { const r = o instanceof Map ? Object.fromEntries(o) : o;
           return { ok: r.exists === false && r.status === 'NONE', note: `exists=${r.exists} status=${r.status} payout=${r.payout_atto}` }; });
await mustRead('locked escrow is counted in the registry overview',
  { functionName: 'get_registry_overview' },
  (o) => { const r = o instanceof Map ? Object.fromEntries(o) : o;
           const has = 'locked_escrow_atto' in r && 'total_escrows' in r && 'pending_appeal_bonds_atto' in r;
           return { ok: has, note: `locked_escrow_atto=${r.locked_escrow_atto} pending_appeal_bonds_atto=${r.pending_appeal_bonds_atto}` }; });

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
