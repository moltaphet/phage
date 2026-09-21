# Phage Sentinel

### Autonomous On-Chain Immune System & Threat Quarantine Protocol for the Agentic Economy

```
Protocol:        Phage Sentinel
Runtime:         GenLayer GenVM (Intelligent Contracts, Python)
Network:         GenLayer Studio-dev
Chain ID:        61997
RPC:             https://studio-dev.genlayer.com/api
Explorer:        https://explorer-studio-dev.genlayer.com
Contract:        0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80
Owner:           0x1f9813eeB2de53134af5C824cA156CE82C4EB0fa
Live Demo:       https://phage-sentinel.vercel.app
Pinned Runner:   py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng
Verification:    Deployed & verified on-chain (Studio-dev); 66/66 local direct tests pass on the pinned RC toolchain
License:         MIT
```

---

## Table of Contents

1. [Overview & Vision](#1-overview--vision)
2. [The Problem](#2-the-problem)
3. [Architecture & Economics](#3-architecture--economics)
4. [Threat Lifecycle](#4-threat-lifecycle)
5. [Smart Contract Methods](#5-smart-contract-methods)
6. [The Non-Deterministic Consensus Engine](#6-the-non-deterministic-consensus-engine)
7. [Security & Audit Verification](#7-security--audit-verification)
8. [Setup, Testing & Deployment](#8-setup-testing--deployment)
9. [Frontend dApp](#9-frontend-dapp)
10. [Repository Layout](#10-repository-layout)
11. [Disclaimer & License](#11-disclaimer--license)

---

## 1. Overview & Vision

**Phage Sentinel** is an autonomous, on-chain **immune system** for the agentic economy, built natively on **GenLayer's GenVM**. As AI agents take direct custody of treasuries, trade on decentralized exchanges, and exchange unstructured messages with one another, the dominant attack surface shifts from deterministic bytecode bugs (reentrancy, overflow) to **semantic exploits**: indirect prompt injection, tool hijacking, jailbreaks, and adversarial telemetry. Deterministic EVM contracts cannot reason about unstructured forensic evidence; human multisig response times guarantee a drained treasury long before a manual reaction.

Phage closes that gap by turning threat response into a permissionless, economically-bonded protocol. Inspired by the bacteriophage — a virus that hunts and neutralizes specific bacterial hosts — the protocol implements four cooperating primitives:

- **Bonded pathogen reports.** Anyone can report a suspicious agent, but only by escrowing a bond. This makes spam and griefing expensive.
- **A decentralized, non-deterministic multi-LLM consensus tribunal.** Validators independently fetch authoritative telemetry and classify the incident. The verdict is an indivisible categorical **tier**, never a fuzzy score.
- **Tiered quarantine & bounty payouts.** Confirmed threats are quarantined for a tier-bound duration; genuine critical findings earn a scaled bounty and mint a reusable **antibody** signature.
- **An anti-griefing appeal lifecycle.** A wrongly-quarantined agent can appeal; an upheld appeal lifts the quarantine, revokes the antibody, slashes the malicious reporter, and permanently escalates the bond required to report that target again.

The result is a **fail-closed, self-funding, adversarially-hardened** defense layer that other contracts can consult on-chain via `is_quarantined(agent)`.

---

## 2. The Problem

| Attack Dimension | Classical EVM Exploit | Agentic Semantic Exploit |
| :--- | :--- | :--- |
| **Attack surface** | Bytecode logic, opcode order, arithmetic | Unstructured text, tool prompts, context windows |
| **Payload delivery** | Calldata parameters | Natural-language RPC, feeds, GitHub PRs, webhooks |
| **Execution vector** | EVM interpreter state transition | LLM parsing and autonomous tool invocation |
| **Detection method** | Static analysis, symbolic execution | Multi-LLM semantic reasoning over forensic evidence |
| **Impact** | Reentrancy drain, overflow | Rogue liquidation, key exfiltration, unauthorized trades |

Phage exists because **detection of the second column requires reasoning that only a decentralized network of LLMs can perform deterministically enough for consensus** — which is exactly what GenLayer's GenVM provides.

---

## 3. Architecture & Economics

### 3.1 System Components

| Component | Storage | Responsibility |
| :--- | :--- | :--- |
| **Reports registry** | `reports`, `report_ids` | Every bonded pathogen report and its resolution |
| **Quarantine registry** | `quarantines`, `quarantined_agents` | Active/expired quarantine state per agent |
| **Antibody registry** | `antibodies`, `antibody_hashes` | Reusable signatures of confirmed critical pathogens |
| **Appeals registry** | `appeals`, `appeal_ids` | Appeal records and their arbitration outcome |
| **Replay guards** | `evaluated_digests`, `pending_digests` | Deterministic per-incident replay protection |
| **Anti-griefing** | `defended_appeals` | Escalating reporter bond after each upheld appeal |
| **Anti-farming** | `last_bounty_claimed_at` | Per-target bounty cooldown |
| **Settlement** | `claimable_balances` | Pull-based, per-account claimable ledger |
| **Disputed escrow** | `escrows`, `escrow_ids` | Bond + bounty held for the appeal window after a quarantine verdict |

### 3.2 The Balance Ledger

Every atto (1 GEN = 10¹⁸ atto) that enters the contract lives in exactly one accounting bucket at rest:

| Bucket | Field | Meaning |
| :--- | :--- | :--- |
| **Bounty pool** | `bounty_pool_atto` | Sponsor-funded rewards for confirmed critical findings |
| **Protocol reserves** | `protocol_reserves_atto` | Slashed bonds (fabricated reports, rejected appeals) |
| **Claimable balances** | `claimable_balances[addr]` | Funds owed to users, awaiting pull withdrawal |
| **Total claimed** | `total_claimed_atto` | Cumulative value already withdrawn |
| **Disputed escrow** | `escrows[report_id]` (`locked_escrow_atto`) | Bond + bounty won on a *quarantine* verdict, held for the appeal window |

Three categories of funds are held **in escrow** while a decision is pending and are not yet assigned to a resting bucket:

- **Pending report bonds** — a reporter's bond between `report_pathogen` and its `evaluate_pathogen` / `reclaim_expired_report_bond`.
- **Disputed payouts** — a `TIER_PATHOGEN_CRITICAL` / `TIER_SUSPICIOUS_ANOMALY` verdict credits the reporter **nothing** at evaluation time. It opens an `EscrowRecord` holding the bond and bounty, locked for the length of the quarantine, which is exactly the appeal window (`appeal_quarantine` requires an active quarantine). The verification of the verdict and the payment for it are deliberately separated: the reporter is paid only once nothing can reverse the finding.
- **In-flight appeal bonds** — settled atomically within `appeal_quarantine`, so they never persist across calls.

`total_deposited_atto` tracks **all** native GEN ever received (funding + report bonds + appeal bonds).

### 3.3 The Solvency Invariant

At every point where no report is mid-evaluation, the ledger balances exactly:

```
total_deposited = bounty_pool + protocol_reserves + Σ(claimable_balances) + total_claimed
                + Σ(pending_report_bonds) + Σ(locked_escrows)
```

Informally, **`Balance = Pool + Reserves + Claimable + Claimed + Bonds + Escrow`**. Every state transition is designed to preserve this equality: a bond either moves from *pending* → *reserves* (slash), *pending* → *claimable* (refund), or *pending* → *escrow* (quarantine verdict); and an escrow resolves to *claimable* (released) or splits back into *pool* + *reserves* (slashed). Each of those is a movement between buckets, never a creation or destruction of value. This invariant is asserted directly by the test suite across multi-cycle scenarios, in **`test_escrow_accounting_keeps_solvency_across_both_outcomes`** (one escrow slashed by an upheld appeal, one released after its window closes) and `test_solvency_invariant_multi_cycle`.

### 3.4 Checks-Effects-Interactions & Pull Withdrawals

The contract never pushes value inside a state-mutating branch. Instead:

1. **Checks** — validate inputs, bonds, replay guards, and state preconditions.
2. **Effects** — mutate storage (zero the claimable balance, mark digests, update registries).
3. **Interactions** — the *only* native-token movement is a user-initiated `withdraw()`, which zeroes the caller's claimable balance **before** emitting the transfer, and emits it with `on="finalized"` so an evaluation that is later appealed and slashed cannot leak value out of the contract.

```python
def withdraw(self) -> None:
    amount = _get_claimable(self.claimable_balances, caller_hex)
    if amount == 0:
        raise gl.vm.UserError(f"{ERROR_EXPECTED} zero claimable balance")
    # Effects before Interactions
    self.claimable_balances[caller_hex] = u256(0)
    self.total_claimed_atto = u256(int(self.total_claimed_atto) + amount)
    # Interaction: native GEN pull, deferred to the finalized consensus decision
    gl.get_contract_at(gl.message.sender_address).emit_transfer(
        value=u256(amount), on="finalized"
    )
```

### 3.5 Threat Tiers

Classification is **indivisible and categorical** — there are no continuous floats in consensus-bound state.

| Tier | Quarantine | Bounty (bps) | Reporter Bond | Antibody |
| :--- | :--- | :--- | :--- | :--- |
| `TIER_PATHOGEN_CRITICAL` | 7 days | 10000 (100%) | refunded | minted |
| `TIER_SUSPICIOUS_ANOMALY` | 24 hours | 0 | refunded | — |
| `TIER_BENIGN_NOISE` | none | 0 | refunded | — |
| `TIER_FABRICATED_ATTACK` | none | 0 | **slashed 100%** | — |

### 3.6 Economic Constants

| Constant | Value | Purpose |
| :--- | :--- | :--- |
| `MIN_REPORTER_BOND` | 0.1 GEN | Base anti-spam bond to file a report |
| `APPEAL_BOND` | 0.2 GEN | Mandatory bond to appeal a quarantine |
| `BASE_BOUNTY_REWARD` | 1 GEN | Standard allocation for a critical finding |
| `TARGET_BOUNTY_COOLDOWN_SEC` | 7 days | Per-target cooldown that caps repeat bounties to 0 |
| `REPORT_EXPIRY_SEC` | 7 days | Liveness timeout after which a stale bond is reclaimable |
| `MAX_PAGE_LIMIT` | 50 | Hard cap on paginated view queries (storage-DoS guard) |

Bounty payouts are additionally scaled to `min(BASE_BOUNTY_REWARD, bounty_pool // 10)` so a single finding can never drain more than ~10% of the pool, and are `min`-clamped to the available pool to prevent underflow.

---

## 4. Threat Lifecycle

```
  fund_bounty_pool()                 (sponsor tops up the bounty pool)
         │
         ▼
  report_pathogen(bond) ──────────► PENDING report + pending replay digest
         │                                   │
         │                                   │ (7-day liveness timeout, un-evaluated)
         │                                   ▼
         │                          reclaim_expired_report_bond() → bond back to reporter
         ▼
  evaluate_pathogen()  ── multi-LLM consensus ──► indivisible TIER
         │
         ├── FABRICATED  → bond slashed to reserves
         ├── BENIGN      → bond refunded, no quarantine
         ├── SUSPICIOUS  → bond refunded, 24h quarantine
         └── CRITICAL    → bond refunded + scaled bounty, 7d quarantine, antibody minted
                                   │
                                   ▼
                          appeal_quarantine(appeal_bond)
                                   │
                     ┌─────────────┴─────────────┐
              UPHELD (BENIGN)              REJECTED (threat real / proof fake)
              lift quarantine,             appeal bond slashed 100%
              revoke antibody,             to reserves
              slash original reporter,
              escalate future bond
                                   │
                                   ▼
                          recover_agent()  (after quarantine expiry)
                                   │
                                   ▼
                          withdraw()  (pull settlement of claimable balance)
```

---

## 5. Smart Contract Methods

`contracts/phage_sentinel.py` exposes **22 entrypoints** (8 state-changing, 14 views).

### 5.1 State-Changing Entrypoints

| Method | Payable | Description |
| :--- | :--- | :--- |
| `fund_bounty_pool()` | ✅ | Deposit native GEN into the bounty pool. Rejects zero deposits. |
| `report_pathogen(report_id, target_agent, platform, trace_id)` | ✅ | File a bonded report. Validates uniqueness, platform, trace format, replay guard, and escalated bond. |
| `evaluate_pathogen(report_id)` | — | Run multi-LLM consensus, bind the tier, settle bond/bounty, enforce quarantine, mint antibody. |
| `appeal_quarantine(target_agent, appeal_proof_trace_id, platform)` | ✅ | Appeal an active quarantine with a bond. Upheld → lift + revoke + slash reporter; rejected → slash appeal bond. |
| `recover_agent(target_agent)` | — | Clear an expired quarantine flag once the cooldown has elapsed. |
| `reclaim_expired_report_bond(report_id)` | — | Reporter-only reclaim of a bond for a report left un-evaluated past the 7-day liveness timeout. |
| `release_escrow(report_id)` | — | Release a matured disputed payout to its recorded reporter. Permissionless. |
| `withdraw()` | — | Pull the caller's entire claimable balance (CEI, `on="finalized"`). |
| `withdraw_claimable()` | — | Idempotent alias of `withdraw()`. |

> **Naming note:** the appeal entrypoint is `appeal_quarantine` (it operates on the target agent's active quarantine, not a single report id).

### 5.2 View Entrypoints (read-only)

| Method | Returns |
| :--- | :--- |
| `is_quarantined(target_agent)` | `bool` — the core cross-contract interop guard |
| `get_quarantine_info(target_agent)` | Full quarantine record |
| `get_antibody(signature_hash)` | Antibody signature record |
| `get_report(report_id)` | Report record |
| `get_appeal(appeal_id)` | Appeal record |
| `get_claimable_balance(account)` | Claimable atto (string) |
| `get_defended_appeals_count(target_agent)` | Successful-defense counter |
| `get_required_reporter_bond(target_agent)` | Current (possibly escalated) bond |
| `get_registry_overview()` | Global counters + the ledger buckets, incl. `locked_escrow_atto` |
| `get_escrow(report_id)` | Status, amounts, and release eligibility of a disputed payout |
| `list_reports_paginated(offset, limit)` | Bounded page of reports |
| `list_quarantined_agents_paginated(offset, limit)` | Bounded page of quarantines |
| `list_antibodies_paginated(offset, limit)` | Bounded page of antibodies |
| `list_quarantined_agents()` / `list_antibodies()` | Back-compat views capped at `MAX_PAGE_LIMIT` |

### 5.3 Supported Telemetry Platforms

Three platforms, each resolving to a live keyless public indexer and each carrying an identifier the contract checks against the accused agent **before any model reads the payload**:

| Platform | Provider | Binding check |
| :--- | :--- | :--- |
| `EVM_TX` | `eth.blockscout.com` | Target must appear in the transaction's participant set |
| `EVM_TX_BASE` | `base.blockscout.com` | Same, on Base |
| `EVM_ADDRESS` | `eth.blockscout.com` | Evidence identifier must *equal* the target address |

Callers submit only a **trace identifier**, never a full URL — the contract deterministically builds the authoritative provider URL from a whitelisted template, eliminating SSRF/URL-injection vectors. A payload that does not implicate the accused resolves `TIER_FABRICATED_ATTACK` and slashes the reporter's bond; the same gate applies to appeal proofs. The check is deterministic and runs on the validator's own copy of the response, so it is a guarantee rather than a prompt instruction.

---

## 6. The Non-Deterministic Consensus Engine

Evaluation and appeal arbitration both run through GenLayer's leader/validator model via **`gl.vm.run_nondet`** — the *safe*, sandboxed variant that runs the validator in isolation and compares results with explicit error-equivalence handling (as opposed to the unsafe variant, which surfaces any validator error as a bare disagreement).

1. **Leader function** fetches authoritative telemetry (`gl.nondet.web.get`), pre-quantizes it into a coarse threat indicator + anomaly score (to prevent boundary divergence between validators), and asks an LLM to return **strict JSON** with one of the four tiers.
2. **Validator function** independently re-runs the leader logic and agrees only if it reaches the **same tier**, guaranteeing consensus on the categorical verdict rather than on any noisy underlying score.

**Fail-closed telemetry policy:**

- Transient faults (`429/500/502/503/504`, empty body, fetch exception) → clean revert (`[TRANSIENT]`); the report stays `PENDING` and no quarantine is applied.
- Non-retryable failures (e.g. `404` unverifiable trace) → resolve as `TIER_FABRICATED_ATTACK`, slashing the reporter.

**Prompt-injection safeguards:** every attacker-controlled field is wrapped in `<untrusted_input>…</untrusted_input>` tags, the system prompt instructs the model to ignore any instructions inside those tags, and telemetry strings are sanitized to printable ASCII before ever reaching the model.

---

## 7. Security & Audit Verification

### 7.1 Test Suite — 66 direct-mode tests

The direct-mode suite exercises every key path and adversarial edge case in-memory (no Docker, ~90s):

```bash
.venv/bin/pytest tests/direct/ -v
# ...
# 66 passed
```

> **Toolchain note:** the live contract targets the v0.3.0 runner (`py-genlayer:5jyc…`) on Studio-dev and is verified on-chain. The versions in `requirements.txt` are load-bearing — see §8.2 for why the RC line is the one that works.

Coverage highlights: bounty funding, all-platform reporting & validation, fail-closed telemetry (`429/500`/empty), URL/injection rejection, tier→payout binding, adversarial slashing (fabricated + `404`), multi-cycle solvency, pull settlement, multi-wallet & cross-platform replay, appeal upheld/rejected, escalating bonds, bounty-farming cooldown & pool scaling, paginated views, quarantine expiry/recovery, antibody revocation, boolean anti-spoofing, bounded-liveness reclaim, plus malformed-address rejection across every external-input entrypoint. Two audit regressions pin the remediated economics: **evidence binding** (a transaction the target is not party to, and an address record naming a different address, both resolve `TIER_FABRICATED_ATTACK` and slash the reporter rather than reaching a verdict) and **escrow** (a reporter cannot withdraw a disputed payout before the appeal that reverses it, an unbound appeal proof forfeits the appellant's bond, and escrow accounting keeps the solvency invariant across both appeal outcomes).

### 7.2 Protection Matrix

| Threat | Mechanism |
| :--- | :--- |
| **Reentrancy / value leakage** | Strict CEI + pull withdrawal, `on="finalized"` settlement |
| **Cross-wallet / cross-platform replay** | `sha256(platform ‖ target ‖ trace)` digest across `pending` + `evaluated` sets |
| **SSRF / URL injection** | Trace-id-only inputs; deterministic whitelisted URL templates; identifier must be a bare 0x address or tx hash |
| **Unbound / generic evidence** | Evidence-to-target binding checked in-contract before the model runs: tx participant set must include the target, address records must equal it; failure resolves `TIER_FABRICATED_ATTACK` and slashes the reporter |
| **Appeal with unrelated proof** | Same binding gate on appeal telemetry; failure forfeits the appellant's 0.2 GEN bond |
| **Front-running an appeal payout** | Disputed bond + bounty escrowed for the quarantine duration; never withdrawable while an appeal is possible |
| **Prompt injection** | `<untrusted_input>` fencing + ASCII sanitization + guardrail system prompt |
| **Consensus divergence** | Coarse telemetry pre-quantization; agreement on categorical tier only |
| **Validator error opacity** | Safe, sandboxed `gl.vm.run_nondet` |
| **Griefing (false reports)** | Bonded reports; escalating bond per upheld appeal (`1 + defended`) |
| **Bounty farming** | 7-day per-target cooldown; payout capped to `pool // 10` and clamped to pool |
| **Liveness lock-up** | `reclaim_expired_report_bond` after the 7-day timeout |
| **Storage DoS** | All list views bounded by `MAX_PAGE_LIMIT = 50` |
| **Integer overflow / underflow / ÷0** | `u256` wrapping, `min`-guarded subtractions, constant divisors |

### 7.3 Solvency Guarantee

The invariant `Balance = Pool + Reserves + Claimable + Claimed + Bonds + Escrow` is preserved by construction and asserted by tests. Slashes route to reserves, refunds and matured escrows route to claimable, and the bounty pool is restored on upheld appeals from the escrow the bounty never left.

### 7.4 Escrowed Disputed Payouts

**Mechanism.** A verdict that quarantines a target does not pay the reporter. `evaluate_pathogen` opens an `EscrowRecord` holding the reporter's bond and the bounty, with `locked_until_utc = now + quarantine_duration`; the reporter's `claimable_balances` entry is not touched. The quarantine duration *is* the appeal window, because `appeal_quarantine` requires an active quarantine — so the lock cannot expire while an appeal is still possible.

**Why the value is never in the reporter's hands.** The previous model credited the bounty to `claimable_balances` at evaluation time and clawed it back on a successful appeal, bounded by `min(current_claimable, bond + payout)`. A reporter who withdrew immediately after finalization left nothing to reclaim. Escrowing removes the window entirely rather than narrowing it: there is no moment at which the disputed value is both withdrawable and still appealable, so the front-running race does not exist to be lost. The penalty on an upheld appeal therefore lands in full — the escrow still holds both amounts by construction.

**Resolution paths.**

| Outcome | Escrow | Also |
| :--- | :--- | :--- |
| Appeal upheld (quarantine overturned) | `SLASHED` — bounty → `bounty_pool_atto`, reporter bond → `protocol_reserves_atto` | appellant refunded; quarantine and antibody revoked; defended-appeal counter incremented |
| Appeal rejected | `RELEASED` to the reporter immediately | appellant bond → reserves; quarantine stays active |
| No appeal; window elapses | `release_escrow(report_id)` → `RELEASED` | permissionless: pays only the recorded reporter |

Two regressions pin this: `test_reporter_cannot_escape_appeal_penalty_by_withdrawing_first` (the withdrawal route is closed, and the upheld appeal recovers the full bond and bounty), and `test_escrow_accounting_keeps_solvency_across_both_outcomes`.

---

## 8. Setup, Testing & Deployment

### 8.1 Prerequisites

- Python 3.12 (contract runtime & tests)
- Node.js 20+ and npm (frontend)
- The `genlayer` CLI (`npm i -g genlayer`) for deployment

Install the pinned Python toolchain. The matching toolchain for studio-dev is still on the
release-candidate line, so `--prerelease=allow` is required:

```bash
uv venv .venv
uv pip install --python .venv/bin/python --prerelease=allow -r requirements.txt
```

### 8.2 Run the Contract Test Suite

```bash
# from the repository root, using the project virtualenv
.venv/bin/pytest tests/direct/ -v      # expect: 66 passed
```

The direct runner loads the contract against its pinned runner
(`py-genlayer:5jyc…`), mocks web/LLM calls, and executes entirely in-memory.

The versions in `requirements.txt` are load-bearing, not cosmetic. On the older stable
toolchain (`genlayer-test 0.29.2` / `genlayer-py 0.16.3`) the direct runner extracts a
`v0.2.16` SDK that reads its calldata from stdin at import time and dies under pytest with
`DecodingError: unexpected end of memory` — all 66 tests fail before reaching the contract.
`genlayer-py >= 0.19.0rc2` also ships the `studio_devnet` chain (id 61997) that
`gltest.config.yaml` targets; on the older SDK it does not exist at all.

### 8.3 Deploy to GenLayer Studio-dev

The constructor takes **no arguments**, so deployment needs only the contract path — but
studio-dev is *not* gasless, and the CLI cannot derive fees for it.

```bash
# 1. Select the built-in network. Do NOT pass --rpc: for a built-in network that
#    bypasses the chain's own config (chain id, consensus addresses, calldata
#    encoding) and the deploy will not settle correctly.
genlayer network set studio-dev

# 2. Deploy with fees attached explicitly. Studio-dev sets no FeeManager, so the CLI
#    has nothing to fall back on and reverts with FeeValueMustBeNonZero(1) without
#    these. The node's own sim_getFeeConfig `defaultFees` is not usable verbatim —
#    its executionBudgetPerRound sits on the floor and __init__ dies with
#    `out_of receipt nondet_output`. Raise the timeunit allocations into the
#    100–200s range and lift the execution budget, then attach the deposit:
genlayer deploy --contract contracts/phage_sentinel.py \
  --fees '{"distribution":{"leaderTimeunitsAllocation":"100","validatorTimeunitsAllocation":"200","appealRounds":"0","executionBudgetPerRound":"300000000000000","executionConsumed":"0","totalMessageFees":"0","rotations":["0"],"maxPriceGenPerTimeUnit":"2","storageFeeMaxGasPrice":"300000000","receiptFeeMaxGasPrice":"300000000"}}' \
  --fee-value 500000000000000

# 3. Smoke-test the live contract (same rule: no --rpc).
genlayer call 0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80 get_registry_overview
```

Writes need the same treatment, derived per call rather than hardcoded. `genlayer write`
cannot send value at all (`value: 0n` is hardcoded in the CLI), so payable methods —
`fund_bounty_pool`, `report_pathogen`, `appeal_quarantine` — are unreachable from the CLI.
The frontend derives each fee through `estimateTransactionFeesForWrite`; see
[`frontend/src/lib/genlayer.ts`](frontend/src/lib/genlayer.ts).

Network parameters live in `.env` / `.env.example` (`GENLAYER_RPC_URL`,
`GENLAYER_CHAIN_ID=61997`, `GENLAYER_EXPLORER_URL`) and in `gltest.config.yaml`, which
carries the matching `studio_devnet` entry. That entry needs the RC toolchain pinned in
`requirements.txt` (`genlayer-py >= 0.19.0rc2`, installed with `--prerelease=allow`) — on the
older stable SDK no studio-dev chain exists, so the network is unreachable from gltest.

---

## 9. Frontend dApp

A React 19 + Vite + TypeScript single-page app lives in `frontend/`. It provides the Sentinel dashboard, agent inspector, reporting portal, antibody registry, appeal chamber, and a real **wallet connection** flow.

### 9.1 Wallet Integration

Wallet handling is implemented in `frontend/src/lib/useWallet.ts` as a self-contained EIP-1193 hook (no heavyweight web3 dependency):

- **Connect** — requests accounts via `eth_requestAccounts`, then prompts the wallet to switch to **Studio-dev (chain `0xf22d` / 61997)**, auto-adding the network (`wallet_addEthereumChain`) if unknown. Fetches the live GEN balance.
- **Graceful failure** — user rejection (`4001`), already-pending requests (`-32002`), missing provider, and network-switch rejection all surface as non-fatal toasts.
- **Disconnect** — an explicit **Disconnect** button wipes address/balance/chain state, clears the `phage.wallet.*` localStorage keys, and immediately reflects the disconnected state in the UI.
- **Live sync** — listens to `accountsChanged`, `chainChanged`, and `disconnect` provider events to auto-reset or re-sync the session. A silent reconnect on reload only occurs if the user did not explicitly disconnect.

### 9.2 Local Development

```bash
cd frontend
npm install
npm run dev        # Vite dev server (hot reload)
npm run build      # type-check (tsc -b) + production bundle → dist/  (zero errors)
npm run preview    # serve the production build locally
npm run lint       # oxlint
```

To interact with the live contract, install MetaMask, click **Connect**, and approve the Studio-dev network prompt.

The contract address is read from `VITE_PHAGE_CONTRACT_ADDRESS`, falling back to the verified
studio-dev deployment hardcoded in [`frontend/src/lib/contract.ts`](frontend/src/lib/contract.ts).
Every variable in `frontend/.env.example` is optional, so an empty environment is a working
configuration; set the override (e.g. as a Vercel env var) to point a preview or production
build at a different deployment without a code change.

### 9.3 Live Verification Against Studio-dev

Two suites exercise the deployed contract through the frontend's *own* client code — the same
`genlayer-js` v2 path the dApp uses — rather than through gltest:

```bash
cd frontend
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/contract-frontend-test.mjs
node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/security-suite.mjs
```

The first walks all 15 view methods and dry-runs all 9 writes; the second runs 60 adversarial
cases (unauthorized withdrawal, `report_id` validation, platform allow-list, evidence-identifier
injection, evidence-to-target binding, escrow release guards, malformed addresses, bond
enforcement, state-machine guards, pagination bounds).
Both pace themselves under the node's limit of **30 requests per minute** — exceeding it fails
with error `-32029` and a `retry_after_seconds` hint. See
[`frontend/scripts/README.md`](frontend/scripts/README.md).

Both of those are **dry runs**: `simulateWriteContract` never reaches `run_nondet`, so neither
proves the consensus engine runs — only that its guards hold. A third script does prove it, by
escrowing a real bond and letting the tier decide the outcome:

```bash
GL_PK=$(security find-generic-password -s genlayer-cli -a account:<name> -w) \
  node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/live-cycle.mjs
```

It has been run against this deployment. Report `live-cycle-1` (target `0x…dEaD`, trace naming
that same address under the then-current `GITHUB_AUDIT` platform) resolved **`TIER_BENIGN_NOISE`**
on-chain: the LLM classified an unremarkable address as nominal traffic, the contract bound that
tier to zero quarantine seconds and zero payout, and the 0.1 GEN bond was refunded intact to
`claimable_balances`. No antibody was minted, which is correct — only `TIER_PATHOGEN_CRITICAL`
mints one. The ledger balanced: `total_deposited_atto` 0.1 GEN against 0.1 GEN claimable.

The platform set has since been replaced (§5.3): all three providers now resolve, and every one
of them binds its evidence to the reported target. The cycle defaults to `EVM_ADDRESS`, whose
evidence identifier *is* the target, so it binds by construction; pass
`--platform EVM_TX --trace 0x<64 hex>` to drive it from a transaction where the target is a
party. Because the remaining providers are live, a `CRITICAL` verdict is now reachable, and the
script prints the escrow it opens — the bond and bounty held for the appeal window rather than
paid to the reporter.

### 9.4 Live Demo

The dApp is deployed at **[phage-sentinel.vercel.app](https://phage-sentinel.vercel.app)** and
talks to the studio-dev deployment above directly from the browser — reads need no wallet.
Rebuild and redeploy with:

```bash
cd frontend
vercel deploy --prod --yes     # project: moltaphets-projects/phage-sentinel
```

The contract address is baked into the bundle at build time from the fallback in
`src/lib/contract.ts`, so a redeploy of the *contract* means rebuilding the frontend. Set
`VITE_PHAGE_CONTRACT_ADDRESS` as a Vercel env var instead to make that a config change — the
variable is optional and the fallback is the verified address, so an empty environment is
still a working configuration.

---

## 10. Repository Layout

```
Phage/
├── contracts/
│   └── phage_sentinel.py            # The Intelligent Contract (GenVM Python)
├── tests/
│   └── direct/
│       ├── conftest.py              # Fixtures + web/LLM mock helpers
│       └── test_phage_sentinel.py   # 66-test direct-mode suite
├── frontend/                        # React 19 + Vite + TS dApp
│   ├── scripts/                     # Live studio-dev suites (views, writes, security, live cycle)
│   ├── .env.example                 # Optional VITE_PHAGE_CONTRACT_ADDRESS override
│   └── src/
│       ├── lib/
│       │   ├── contract.ts          # Network config + typed contract models
│       │   ├── genlayer.ts          # Client, reads/writes, per-call fee derivation
│       │   ├── errors.ts            # GenVM failure decoding for the UI
│       │   ├── useWallet.ts         # EIP-1193 connect/disconnect hook
│       │   └── format.ts
│       ├── components/              # Dashboard, inspector, portal, appeal chamber…
│       ├── types/ethereum.d.ts      # Minimal EIP-1193 provider typings
│       └── App.tsx
├── gltest.config.yaml               # Direct-runner network config (incl. studio_devnet)
├── requirements.txt                 # Pinned Python toolchain (RC line — see 8.1)
├── pytest.ini                       # Test discovery
├── .env / .env.example              # RPC, chain id, explorer, contract + owner address
└── README.md
```

---

## 11. Disclaimer & License

Phage Sentinel is research-grade software provided **as-is** for the GenLayer ecosystem. It has not undergone a third-party security audit; the 66-test suite and the invariants documented above are the current verification baseline. Deploy to mainnet-equivalent environments at your own risk and after independent review.

Released under the **MIT License**.
