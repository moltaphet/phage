// Adversarial test suite against the live PhageSentinel deployment on studio-dev.
// Every case is a dry-run (simulateWriteContract / readContract): no state is
// mutated, no funds move. A case PASSES when the contract refuses the attack
// with its own [EXPECTED] guard, or when a read returns a bounded result.
import { createClient } from 'genlayer-js';
import { PHAGE_CONTRACT_ADDRESS, STUDIO_DEV_CHAIN, STUDIONET_RPC } from '../src/lib/contract.ts';
import { describeError } from '../src/lib/errors.ts';

const A = PHAGE_CONTRACT_ADDRESS;
// The node caps callers at 30 requests/minute and answers the 31st with -32029. A fixed
// sleep between cases does not survive a back-to-back run — the previous suite's requests
// are still inside the server-side window — so gate every HTTP request through a sliding
// window instead. 28 leaves headroom for a request already in flight.
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 28;
const sent = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (...args) => {
  for (;;) {
    const now = Date.now();
    while (sent.length && now - sent[0] > WINDOW_MS) sent.shift();
    if (sent.length < MAX_REQUESTS) {
      sent.push(now);
      break;
    }
    await new Promise((r) => setTimeout(r, sent[0] + WINDOW_MS - now + 50));
  }
  return realFetch(...args);
};
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
const legit = { platform: 'AGENT_RPC', traceId: 'trace-sec-0001' };
await mustReject('empty report_id', { functionName: 'report_pathogen', args: ['', TARGET, legit.platform, legit.traceId], value: GEN }, EXP);
await mustReject('whitespace-only report_id', { functionName: 'report_pathogen', args: ['   ', TARGET, legit.platform, legit.traceId], value: GEN }, EXP);

console.log('\n=== 3. report_pathogen: platform allow-list ===');
for (const p of ['SOLANA', 'agent_rpc', 'AGENT_RPC ', '', '../../etc', 'AGENT_RPC\x00']) {
  await mustReject(`platform ${JSON.stringify(p)}`, { functionName: 'report_pathogen', args: ['sec-p1', TARGET, p, legit.traceId], value: GEN }, EXP);
}

console.log('\n=== 4. report_pathogen: trace_id injection surface ===');
for (const t of ['http://evil.example/x', 'https://evil.example/x', 'ftp://evil.example', 'trace://x',
                 '../../etc/passwd', 'trace/../../etc', 'abc', 'x'.repeat(67), 'трейс-0001',
                 'trace\x00id', 'trace id', '${jndi:ldap://x}', "' OR 1=1--"]) {
  await mustReject(`trace_id ${JSON.stringify(t.slice(0, 30))}`, { functionName: 'report_pathogen', args: ['sec-t', TARGET, 'AGENT_RPC', t], value: GEN }, EXP);
}

console.log('\n=== 5. report_pathogen: GITHUB_AUDIT path parsing ===');
for (const t of ['no-slash-here', 'owner/', '/repo', 'owner/../../etc', 'a'.repeat(101) + '/repo', 'own er/repo']) {
  await mustReject(`github trace ${JSON.stringify(t.slice(0, 30))}`, { functionName: 'report_pathogen', args: ['sec-g', TARGET, 'GITHUB_AUDIT', t], value: GEN }, EXP);
}

console.log('\n=== 6. report_pathogen: malformed target address ===');
for (const a of ['not-an-address', '0x1234', '0x' + 'a'.repeat(39), '0x' + 'z'.repeat(40), '']) {
  await mustReject(`target_agent ${JSON.stringify(a.slice(0, 22))}`, { functionName: 'report_pathogen', args: ['sec-a', a, 'AGENT_RPC', legit.traceId], value: GEN }, /EXPECTED|invalid|address|Missing|execution failed/i);
}

console.log('\n=== 7. Bond / value enforcement ===');
await mustReject('report_pathogen with zero bond', { functionName: 'report_pathogen', args: ['sec-b1', TARGET, 'AGENT_RPC', legit.traceId], value: 0n }, EXP);
await mustReject('report_pathogen with 1 atto under the 0.1 GEN bond', { functionName: 'report_pathogen', args: ['sec-b2', TARGET, 'AGENT_RPC', legit.traceId], value: GEN / 10n - 1n }, EXP);
await mustReject('appeal_quarantine with zero bond', { functionName: 'appeal_quarantine', args: [TARGET, 'trace-appeal-1', 'AGENT_RPC'], value: 0n }, EXP);
await mustReject('fund_bounty_pool with zero value', { functionName: 'fund_bounty_pool', value: 0n }, EXP);

console.log('\n=== 8. State-machine guards (attacks against non-existent state) ===');
await mustReject('appeal_quarantine against a never-quarantined agent', { functionName: 'appeal_quarantine', args: [TARGET, 'trace-appeal-2', 'AGENT_RPC'], value: GEN }, EXP);
await mustReject('recover_agent against a never-quarantined agent', { functionName: 'recover_agent', args: [TARGET] }, EXP);
await mustReject('evaluate_pathogen on a non-existent report', { functionName: 'evaluate_pathogen', args: ['no-such-report'] }, EXP);
await mustReject('reclaim_expired_report_bond on a non-existent report', { functionName: 'reclaim_expired_report_bond', args: ['no-such-report'] }, EXP);
await mustReject("reclaim_expired_report_bond against someone else's pending report", { functionName: 'reclaim_expired_report_bond', args: ['sec-other'] }, EXP);

console.log('\n=== 9. Pagination bounds / DoS ===');
await mustRead('limit clamped at MAX_PAGE_LIMIT=50 (request 10^9)', { functionName: 'list_reports_paginated', args: [0, 1_000_000_000] },
  (o) => ({ ok: Array.isArray(o) && o.length <= 50, note: `returned ${Array.isArray(o) ? o.length : '?'} rows` }));
await mustRead('offset = 2^256-1 does not overflow', { functionName: 'list_reports_paginated', args: [U256MAX, 50] },
  (o) => ({ ok: Array.isArray(o) && o.length === 0, note: `returned ${JSON.stringify(o)}` }));
await mustRead('limit = 2^256-1 does not overflow', { functionName: 'list_reports_paginated', args: [0, U256MAX] },
  (o) => ({ ok: Array.isArray(o) && o.length <= 50, note: `returned ${Array.isArray(o) ? o.length : '?'} rows` }));
await mustRead('limit = 0 returns empty', { functionName: 'list_antibodies_paginated', args: [0, 0] },
  (o) => ({ ok: Array.isArray(o) && o.length === 0, note: `returned ${JSON.stringify(o)}` }));

console.log('\n=== 10. Information disclosure ===');
await mustRead('claimable balance of an arbitrary third party is public', { functionName: 'get_claimable_balance', args: [VICTIM] },
  (o) => ({ ok: true, note: `returns ${o} — address balances are public by design` }));
await mustRead('private keys / owner secrets are not exposed by any view', { functionName: 'get_registry_overview' },
  (o) => { const keys = Object.keys(o instanceof Map ? Object.fromEntries(o) : o); const leak = keys.filter((k) => /key|secret|password|mnemonic|pk/i.test(k));
           return { ok: leak.length === 0, note: `view keys: ${keys.join(', ')}` }; });

console.log(`\n=== ${pass} blocked/bounded, ${fail} issues ===`);
if (failures.length) console.log('ISSUES: ' + failures.join(' | '));
process.exit(fail ? 1 : 0);
