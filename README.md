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
Verification:    Deployed & verified on-chain (Studio-dev); 57/57 local direct tests pass on the pinned RC toolchain
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

### 3.2 The Four-Bucket Balance Ledger

Every atto (1 GEN = 10¹⁸ atto) that enters the contract lives in exactly one accounting bucket at rest:

| Bucket | Field | Meaning |
| :--- | :--- | :--- |
| **Bounty pool** | `bounty_pool_atto` | Sponsor-funded rewards for confirmed critical findings |
| **Protocol reserves** | `protocol_reserves_atto` | Slashed bonds (fabricated reports, rejected appeals) |
| **Claimable balances** | `claimable_balances[addr]` | Funds owed to users, awaiting pull withdrawal |
| **Total claimed** | `total_claimed_atto` | Cumulative value already withdrawn |

Two categories of funds are held **in escrow** while a decision is pending and are not yet assigned to a resting bucket:

- **Pending report bonds** — a reporter's bond between `report_pathogen` and its `evaluate_pathogen` / `reclaim_expired_report_bond`.
- **In-flight appeal bonds** — settled atomically within `appeal_quarantine`, so they never persist across calls.

`total_deposited_atto` tracks **all** native GEN ever received (funding + report bonds + appeal bonds).

### 3.3 The Solvency Invariant

At every point where no report is mid-evaluation, the ledger balances exactly:

```
total_deposited = bounty_pool + protocol_reserves + Σ(claimable_balances) + total_claimed + Σ(pending_report_bonds)
```

Informally, **`Balance = Pool + Reserves + Claimable + Bonds`**. Every state transition is designed to preserve this equality: a bond either moves from *pending* → *reserves* (slash), *pending* → *claimable* (refund), or a bounty moves *pool* → *claimable* (net-zero across buckets). This invariant is asserted directly by the test suite across multi-cycle scenarios — including the subtle case where a malicious reporter withdraws a leaked bounty *before* a successful appeal (the un-reclaimable value stays accounted for inside `total_claimed`).

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
| `get_registry_overview()` | Global counters + the four ledger buckets |
| `list_reports_paginated(offset, limit)` | Bounded page of reports |
| `list_quarantined_agents_paginated(offset, limit)` | Bounded page of quarantines |
| `list_antibodies_paginated(offset, limit)` | Bounded page of antibodies |
| `list_quarantined_agents()` / `list_antibodies()` | Back-compat views capped at `MAX_PAGE_LIMIT` |

### 5.3 Supported Telemetry Platforms

`AGENT_RPC`, `TX_TRACE`, `SECURITY_FEED`, `GITHUB_AUDIT`. Callers submit only a **trace identifier**, never a full URL — the contract deterministically builds the authoritative provider URL from a whitelisted template, eliminating SSRF/URL-injection vectors.

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

### 7.1 Test Suite — 57 direct-mode tests

The direct-mode suite exercises every key path and adversarial edge case in-memory (no Docker, ~90s):

```bash
.venv/bin/pytest tests/direct/ -v
# ...
# 57 passed
```

> **Toolchain note:** the live contract targets the v0.3.0 runner (`py-genlayer:5jyc…`) on Studio-dev and is verified on-chain. The versions in `requirements.txt` are load-bearing — see §8.2 for why the RC line is the one that works.

Coverage highlights: bounty funding, all-platform reporting & validation, fail-closed telemetry (`429/500`/empty), URL/injection rejection, tier→payout binding, adversarial slashing (fabricated + `404`), multi-cycle solvency, pull settlement, multi-wallet & cross-platform replay, appeal upheld/rejected, escalating bonds, bounty-farming cooldown & pool scaling, paginated views, quarantine expiry/recovery, antibody revocation, boolean anti-spoofing, bounded-liveness reclaim, and two audit regressions (solvency after a pre-appeal withdrawal, and a critical report against an empty pool), plus malformed-address rejection across every external-input entrypoint.

### 7.2 Protection Matrix

| Threat | Mechanism |
| :--- | :--- |
| **Reentrancy / value leakage** | Strict CEI + pull withdrawal, `on="finalized"` settlement |
| **Cross-wallet / cross-platform replay** | `sha256(platform ‖ target ‖ trace)` digest across `pending` + `evaluated` sets |
| **SSRF / URL injection** | Trace-id-only inputs; deterministic whitelisted URL templates; `://` rejected |
| **Prompt injection** | `<untrusted_input>` fencing + ASCII sanitization + guardrail system prompt |
| **Consensus divergence** | Coarse telemetry pre-quantization; agreement on categorical tier only |
| **Validator error opacity** | Safe, sandboxed `gl.vm.run_nondet` |
| **Griefing (false reports)** | Bonded reports; escalating bond per upheld appeal (`1 + defended`) |
| **Bounty farming** | 7-day per-target cooldown; payout capped to `pool // 10` and clamped to pool |
| **Liveness lock-up** | `reclaim_expired_report_bond` after the 7-day timeout |
| **Storage DoS** | All list views bounded by `MAX_PAGE_LIMIT = 50` |
| **Integer overflow / underflow / ÷0** | `u256` wrapping, `min`-guarded subtractions, constant divisors |

### 7.3 Solvency Guarantee

The invariant `Balance = Pool + Reserves + Claimable + Bonds` is preserved by construction and asserted by tests. Slashes route to reserves, refunds and bounties route to claimable, and the bounty pool is restored on upheld appeals whenever the leaked value is still reclaimable — otherwise it remains fully accounted for in `total_claimed`.

### 7.4 Optimistic Payout Dynamics & Post-Finalization Appeal Trade-off

**Mechanism.** `withdraw()` settles the caller's `claimable_balances` entry under GenVM `on="finalized"` semantics: value only leaves the contract once the underlying evaluation is finalized by consensus, so an evaluation that is appealed and slashed *within the same finalization window* cannot leak value.

**Residual trade-off.** The appeal claw-back is bounded by what is still on-hand — `slash_amount = min(current_claimable, orig_bond + orig_payout)`. If a reporter withdraws their claimable bounty *immediately after finalization* and the defendant then wins an appeal *afterward*, `current_claimable` is already `0`, so the slash reclaims nothing and the paid bounty is **not** restored to `bounty_pool_atto` — the bounty escrow is economically depleted. This does **not** break the solvency invariant: the withdrawn value stays fully accounted for in `total_claimed_atto` (`Balance = Pool + Reserves + Claimable + Bonds` still holds). The loss is economic (a depleted bounty pool after a successful grief-then-withdraw), not an insolvency. This exact case is pinned by `test_solvency_preserved_when_reporter_withdrew_before_appeal`.

**Roadmap (Phage v2 — Timelock Challenge Window).** A configurable **24–48h Challenge Window** will hold verified bounties in a new `queued_payouts` state before they graduate to `claimable_balances`. A payout becomes withdrawable only after the window elapses with no upheld appeal, fully eliminating the front-running withdrawal edge case while preserving the current `on="finalized"` settlement guarantees.

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
.venv/bin/pytest tests/direct/ -v      # expect: 57 passed
```

The direct runner loads the contract against its pinned runner
(`py-genlayer:5jyc…`), mocks web/LLM calls, and executes entirely in-memory.

The versions in `requirements.txt` are load-bearing, not cosmetic. On the older stable
toolchain (`genlayer-test 0.29.2` / `genlayer-py 0.16.3`) the direct runner extracts a
`v0.2.16` SDK that reads its calldata from stdin at import time and dies under pytest with
`DecodingError: unexpected end of memory` — all 57 tests fail before reaching the contract.
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

The first walks all 14 view methods and dry-runs all 8 writes; the second runs 50 adversarial
cases (unauthorized withdrawal, `report_id` validation, platform allow-list, `trace_id`
injection, malformed addresses, bond enforcement, state-machine guards, pagination bounds).
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

It has been run against this deployment. Report `live-cycle-1` (target `0x…dEaD`,
`GITHUB_AUDIT`, trace `genlayerlabs/genlayer-js`) resolved **`TIER_BENIGN_NOISE`** on-chain: the
LLM classified a real public repository as nominal traffic, the contract bound that tier to zero
quarantine seconds and zero payout, and the 0.1 GEN bond was refunded intact to
`claimable_balances`. No antibody was minted, which is correct — only `TIER_PATHOGEN_CRITICAL`
mints one. The ledger balances: `total_deposited_atto` 0.1 GEN against 0.1 GEN claimable.

Only `GITHUB_AUDIT` can complete a cycle. The other three telemetry hosts in
`_PLATFORM_URL_TEMPLATES` do not resolve, so their `leader_fn` raises `[TRANSIENT]` and the
evaluation reverts — see §7.2. The live cycle therefore proves the engine, the tier→payout
binding, the replay guard and the settlement path; it does not exercise the quarantine or
antibody branches, which need a `CRITICAL` verdict from a provider that exists.

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
│       └── test_phage_sentinel.py   # 57-test direct-mode suite
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

Phage Sentinel is research-grade software provided **as-is** for the GenLayer ecosystem. It has not undergone a third-party security audit; the 57-test suite and the invariants documented above are the current verification baseline. Deploy to mainnet-equivalent environments at your own risk and after independent review.

Released under the **MIT License**.
