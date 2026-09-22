# Live contract test scripts

Scripts that exercise the deployed PhageSentinel contract on GenLayer Studio-dev
through the frontend's own client code.

```bash
cd frontend
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/security-suite.mjs
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/contract-frontend-test.mjs
```

| Script | Spends? | What it does |
| :--- | :--- | :--- |
| `security-suite.mjs` | no | 60 adversarial cases via `simulateWriteContract` / `readContract` |
| `contract-frontend-test.mjs` | no | every view method, every write dry-run, every exported read helper |
| `live-cycle.mjs` | **yes — 0.1 GEN bond** | one real `report_pathogen` → `evaluate_pathogen` cycle |

`ts-resolve*.mjs` is a small Node loader hook that lets these `.mjs` scripts
import the frontend's TypeScript modules directly, so the tests exercise the
real `src/lib/genlayer.ts` code rather than a reimplementation of it. It also
needs `--experimental-strip-types`, since those modules are TypeScript.

## The live cycle

The two suites are dry runs. `simulateWriteContract` executes the call on a single
node — including the leader side of `run_nondet`, so the binding checks in
`security-suite.mjs` section 5 see a real Blockscout fetch — but it commits nothing
and involves no validators, so it cannot prove consensus is reached.
`live-cycle.mjs` is the script that does, by filing a real bonded report and
letting the resulting tier decide whether it is refunded, slashed, or escrowed.

It needs a signing key, which the suites do not. Pass it through the environment
so it never lands in shell history or this file:

```bash
GL_PK=$(security find-generic-password -s genlayer-cli -a account:<name> -w) \
  node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs \
  ./scripts/live-cycle.mjs --dry     # drop --dry to spend
```

Defaults cite a real incident: the Euler Finance exploit transaction
(`0xc310a0af…b111d`, Ethereum, 2023-03-13), reported against its sender
`0x5F259D0b…8B8c`, which Blockscout tags as *Euler Finance Exploiter 3* /
`ATTACKER`. `report_pathogen` fetches that transaction from `eth.blockscout.com`
and takes the bond only if the target is one of its parties (sender, recipient or
created contract); otherwise the filing reverts with `ERR_UNBOUND_EVIDENCE`. Pass
`--target`, `--platform EVM_TX|EVM_TX_BASE` and `--trace 0x<64 hex>` to cite a
different incident. Both platforms resolve to Blockscout's keyless public API.

If the verdict carries a quarantine, the run also prints the escrow it opened:
the bond and bounty are held until the appeal window closes with no appeal
pending (`claim_payout`), or are slashed by an upheld appeal
(`file_appeal` → `resolve_appeal`).

## Rate limiting

The node caps callers at **30 requests per minute** and answers the 31st with
`-32029` plus a `retry_after_seconds` hint. `pace.mjs` gates `fetch` through a
shared sliding window rather than sleeping between cases, because the frontend
helpers issue several RPCs per call and per-case sleeping would still overrun.

The window lives in a file under the temp directory, not in process memory. That
matters: an in-memory counter only paces one script, so a second suite started
while the first one's requests were still inside the *server's* 60s window would
open with `-32029` and misreport those cases as failures — the guards expect a
contract `[EXPECTED]` message and do not match "rate limit exceeded". Sharing
the ledger makes back-to-back runs work, which is why there is no longer a
"wait a minute between runs" rule. Delete the file to reset the window:

```bash
rm -f "${TMPDIR:-/tmp}/phage-studio-dev-rpc-window"
```
