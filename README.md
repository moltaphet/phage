# Phage Sentinel

### Autonomous On-Chain Immune System & Threat Quarantine Protocol for the Agentic Economy

```
Protocol:        Phage Sentinel
Runtime:         GenLayer GenVM (Intelligent Contracts, Python)
Network:         GenLayer Studio-dev
Chain ID:        61997
RPC:             https://studio-dev.genlayer.com/api
Explorer:        https://explorer-studio-dev.genlayer.com
Contract:        0x038d5Fd5082Cb05586C4C7CBcdDE827AC7f6BBa1   (v0.4.0, deployed 2026-09-22)
Deploy Tx:       0x58e04a07337f3fb03076c5b42040bbe1d6a94e0b1c4908e90920c5f4540d632d
Owner:           0x2E56C8579fA11CB144E6FD778dA772061f4dd930
Live Demo:       https://phage-sentinel.vercel.app
Pinned Runner:   py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng
Evidence:        Incident-level: a transaction on Ethereum/Base (Blockscout) the target is a party to
Verification:    Deployed on Studio-dev with a live consensus cycle (§9.3); 80/80 direct tests pass
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

- **Bonded, target-bound pathogen reports.** Anyone can report a suspicious agent, but only by posting a bond and citing a specific on-chain incident — a transaction the agent is a party to. Validators fetch that transaction when the report is filed and agree the agent is in it before any bond is taken.
- **A decentralized, non-deterministic multi-LLM consensus tribunal.** Validators independently fetch the incident from the block explorer and classify it. The verdict is an indivisible categorical **tier**, never a fuzzy score.
- **Tiered quarantine & bounty payouts.** Confirmed threats are quarantined for a tier-bound duration; genuine critical findings earn a scaled bounty and mint a reusable **antibody** signature.
- **An anti-griefing appeal lifecycle.** A wrongly-quarantined agent can appeal the report behind it. The reporter's bond and bounty are held in escrow and frozen the moment an appeal is filed, so an upheld appeal can always slash them in full; it also lifts the quarantine, revokes the antibody, and permanently escalates the bond required to report that target again.

The result is a **fail-closed, self-funding, adversarially-hardened** defense layer that other contracts can consult on-chain via `is_quarantined(agent)`.

---

## 2. The Problem

| Attack Dimension | Classical EVM Exploit | Agentic Semantic Exploit |
| :--- | :--- | :--- |
| **Attack surface** | Bytecode logic, opcode order, arithmetic | Unstructured text, tool prompts, context windows |
| **Payload delivery** | Calldata parameters | Natural-language RPC, feeds, pull requests, webhooks |
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
| **Appeals registry** | `appeals`, `appeal_ids` | Per-report appeal records: filed, then resolved or expired |
| **Replay guards** | `evaluated_digests`, `pending_digests` | Deterministic per-incident replay protection |
| **Anti-griefing** | `defended_appeals` | Escalating reporter bond after each upheld appeal |
| **Anti-farming** | `last_bounty_claimed_at` | Per-target bounty cooldown |
| **Settlement** | `claimable_balances` | Pull-based, per-account claimable ledger |
| **Disputed escrow** | `escrows`, `escrow_ids` | Bond + bounty held after a quarantine verdict until no appeal can reach it |

### 3.2 The Balance Ledger

Every atto (1 GEN = 10¹⁸ atto) that enters the contract lives in exactly one accounting bucket at rest:

| Bucket | Field | Meaning |
| :--- | :--- | :--- |
| **Bounty pool** | `bounty_pool_atto` | Sponsor-funded rewards for confirmed critical findings |
| **Protocol reserves** | `protocol_reserves_atto` | Slashed bonds (fabricated reports, rejected appeals) |
| **Claimable balances** | `claimable_balances[addr]` | Funds owed to users, awaiting pull withdrawal |
| **Total claimed** | `total_claimed_atto` | Cumulative value already withdrawn |
| **Disputed escrow** | `escrows[report_id]` (`locked_escrow_atto`) | Bond + bounty won on a *quarantine* verdict, `LOCKED` or `UNDER_APPEAL` |
| **Pending appeal bonds** | `pending_appeal_bonds_atto` | Appeal bonds filed and not yet resolved or expired |

Funds held while a decision is pending:

- **Pending report bonds** — a reporter's bond between `report_pathogen` and its `evaluate_pathogen` / `reclaim_expired_report_bond`.
- **Disputed payouts** — a `TIER_PATHOGEN_CRITICAL` / `TIER_SUSPICIOUS_ANOMALY` verdict credits the reporter **nothing** at evaluation time. It opens an `EscrowRecord` holding the bond and bounty. The reporter is paid only once no appeal can reach it (§7.4).
- **Pending appeal bonds** — posted by `file_appeal`, held until `resolve_appeal` or `expire_appeal` settles them.

`total_deposited_atto` tracks **all** native GEN ever received (funding + report bonds + appeal bonds).

### 3.3 The Solvency Invariant

At every point where no report is mid-evaluation, the ledger balances exactly:

```
total_deposited = bounty_pool + protocol_reserves + Σ(claimable_balances) + total_claimed
                + Σ(pending_report_bonds) + Σ(locked_escrows) + pending_appeal_bonds
```

Informally, **`Balance = Pool + Reserves + Claimable + Claimed + Bonds + Escrow + Appeal bonds`**. Every state transition is designed to preserve this equality: a bond either moves from *pending* → *reserves* (slash), *pending* → *claimable* (refund), or *pending* → *escrow* (quarantine verdict); an escrow resolves to *claimable* (released) or splits back into *pool* + *reserves* (slashed); and an appeal bond moves from *pending appeal bonds* to *claimable* (upheld / expired) or *reserves* (rejected). Each of those is a movement between buckets, never a creation or destruction of value. The test suite asserts the full equality, including escrow and in-flight appeal bonds, after every step of every appeal path (`_assert_solvent` in `test_payout_preserved_during_appeal`, `test_appeal_slashes_false_reporter_and_refunds_escrow`, `test_appeal_upholds_valid_incident_and_releases_escrow`, `test_junk_appeal_cannot_foreclose_the_targets_appeal`, `test_expired_appeal_refunds_appellant_and_restores_claim`, `test_escrow_accounting_keeps_solvency_across_both_outcomes`) and `test_solvency_invariant_multi_cycle`.

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
| `TIER_PATHOGEN_CRITICAL` | 7 days | 10000 (100%) | escrowed with the bounty (§7.4) | minted |
| `TIER_SUSPICIOUS_ANOMALY` | 24 hours | 0 | escrowed (§7.4) | — |
| `TIER_BENIGN_NOISE` | none | 0 | refunded | — |
| `TIER_FABRICATED_ATTACK` | none | 0 | **slashed 100%** | — |

### 3.6 Economic Constants

| Constant | Value | Purpose |
| :--- | :--- | :--- |
| `MIN_REPORTER_BOND` | 0.1 GEN | Base anti-spam bond to file a report |
| `APPEAL_BOND` | 0.2 GEN | Bond to appeal a report; × (1 + rejected appeals on that report) |
| `APPEAL_GRACE_SEC` | 24 hours | Minimum time a report stays appealable after an appeal against it is rejected |
| `APPEAL_RESOLUTION_TIMEOUT_SEC` | 7 days | After this, an unresolved appeal can be expired (bond refunded, verdict stands) |
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
  report_pathogen(bond, tx hash) ─ validators fetch the tx and agree the target is a party
         │                           └─ not a party / no such tx → ERR_UNBOUND_EVIDENCE, revert
         ▼
  PENDING report (binding role recorded) ──(7 days un-evaluated)──► reclaim_expired_report_bond()
         │
         ▼
  evaluate_pathogen()  ── multi-LLM consensus ──► indivisible TIER
         │
         ├── FABRICATED  → bond slashed to reserves
         ├── BENIGN      → bond refunded, no quarantine
         ├── SUSPICIOUS  → 24h quarantine;  bond → escrow LOCKED
         └── CRITICAL    → 7d quarantine, antibody; bond + scaled bounty → escrow LOCKED
                                   │
            ┌──────────────────────┴───────────────────────┐
     no appeal before                                file_appeal(report_id, proof tx, bond)
     locked_until_utc                                      │  escrow → UNDER_APPEAL
            │                                              │  claim_payout → ERR_PAYOUT_LOCKED
            │                                              ▼
            │                                   resolve_appeal(appeal_id)  (permissionless)
            │                     ┌────────────────────────┼───────────────────────────┐
            │              UPHELD (verdict false)   REJECTED (incident stands)   7d unresolved:
            │              escrow SLASHED:          appellant bond → reserves;   expire_appeal()
            │              bounty → pool,           escrow → LOCKED, window      bond refunded,
            │              reporter bond → reserves; open ≥ 24h more,            escrow → LOCKED
            │              appellant refunded;      next appeal bond ×2
            │              quarantine + antibody
            │              lifted; report OVERTURNED
            ▼
  claim_payout(report_id) → escrow RELEASED to the reporter (permissionless)
         │
         ▼
  recover_agent() (after quarantine expiry)      withdraw() (pull settlement of claimable)
```

---

## 5. Smart Contract Methods

`contracts/phage_sentinel.py` exposes **22 entrypoints** (8 state-changing, 14 views).

### 5.1 State-Changing Entrypoints

| Method | Payable | Description |
| :--- | :--- | :--- |
| `fund_bounty_pool()` | ✅ | Deposit native GEN into the bounty pool. Rejects zero deposits. |
| `report_pathogen(report_id, target_agent, platform, trace_id)` | ✅ | File a bonded report citing a transaction. Validates uniqueness, platform, hash format, replay guard and bond, then fetches the transaction under consensus and reverts with `ERR_UNBOUND_EVIDENCE` unless the target is a party to it. |
| `evaluate_pathogen(report_id)` | — | Run multi-LLM consensus on the bound incident, bind the tier, enforce quarantine, mint antibody, and settle or escrow the bond and bounty. |
| `file_appeal(report_id, appeal_proof_trace_id, platform)` | ✅ | Dispute one report's quarantine verdict while its escrow is appealable. Deterministic: posts the bond and moves the escrow to `UNDER_APPEAL`. |
| `resolve_appeal(appeal_id)` | — | Run appeal consensus and enforce the outcome (§7.4). Permissionless. |
| `expire_appeal(appeal_id)` | — | Close an appeal still unresolved after 7 days: refund its bond, return the escrow to `LOCKED`. Permissionless. |
| `claim_payout(report_id)` | — | Release a disputed escrow to its recorded reporter once its window has closed and no appeal is pending. Permissionless. `release_escrow` is a kept alias. |
| `recover_agent(target_agent)` | — | Clear an expired quarantine flag once the cooldown has elapsed. |
| `reclaim_expired_report_bond(report_id)` | — | Reporter-only reclaim of a bond for a report left un-evaluated past the 7-day liveness timeout. |
| `withdraw()` | — | Pull the caller's entire claimable balance (CEI, `on="finalized"`). |
| `withdraw_claimable()` | — | Idempotent alias of `withdraw()`. |

Named refusals that callers can match on: `ERR_UNBOUND_EVIDENCE: incident telemetry does not prove relationship to target` and `ERR_PAYOUT_LOCKED: funds preserved until appeal resolution`, both under the contract's `[EXPECTED]` prefix.

### 5.2 View Entrypoints (read-only)

| Method | Returns |
| :--- | :--- |
| `is_quarantined(target_agent)` | `bool` — the core cross-contract interop guard |
| `get_quarantine_info(target_agent)` | Full quarantine record |
| `get_antibody(signature_hash)` | Antibody signature record |
| `get_report(report_id)` | Report record, incl. `evidence_binding` (the target's role in the cited transaction) |
| `get_appeal(appeal_id)` | Appeal record, incl. the `report_id` it disputes |
| `get_claimable_balance(account)` | Claimable atto (string) |
| `get_defended_appeals_count(target_agent)` | Successful-defense counter |
| `get_required_reporter_bond(target_agent)` | Current (possibly escalated) bond |
| `get_registry_overview()` | Global counters + the ledger buckets, incl. `locked_escrow_atto` and `pending_appeal_bonds_atto` |
| `get_escrow(report_id)` | Status, amounts, `is_appealable` / `is_releasable`, `active_appeal_id`, `required_appeal_bond_atto` |
| `list_reports_paginated(offset, limit)` | Bounded page of reports |
| `list_quarantined_agents_paginated(offset, limit)` | Bounded page of quarantines |
| `list_antibodies_paginated(offset, limit)` | Bounded page of antibodies |
| `list_quarantined_agents()` / `list_antibodies()` | Back-compat views capped at `MAX_PAGE_LIMIT` |

### 5.3 Incident Telemetry & Evidence Binding

Evidence is **one on-chain incident**: a transaction, identified by its 32-byte hash, in which the accused agent is a party. Two platforms, both Blockscout's keyless public v2 API:

| Platform | Provider (fetched URL) |
| :--- | :--- |
| `EVM_TX` | `https://eth.blockscout.com/api/v2/transactions/{hash}` |
| `EVM_TX_BASE` | `https://base.blockscout.com/api/v2/transactions/{hash}` |

**Binding is proven when the report is filed**, not asked of the model later. `report_pathogen` fetches the transaction inside `gl.vm.run_nondet`; each validator re-fetches it and must derive the identical result. The evidence is bound only if all of these hold on the fetched bytes:

1. the provider answers `200` (a `404` means the incident does not exist);
2. the body is a transaction object whose `hash` equals the cited hash — so it is the incident the reporter committed to, and not a repository page, an address profile, or any other generic document;
3. the target address appears as its `from`, `to`, or `created_contract`.

Otherwise the filing reverts with `ERR_UNBOUND_EVIDENCE` before any state is written — no report, no replay digest, no bond taken. A bound filing records the target's role (`evidence_binding`) on the report. Provider faults (`429`/`5xx`/unreachable) revert `[TRANSIENT]` instead and can be retried. `evaluate_pathogen` re-checks the same binding on the exact bytes it classifies (defence in depth: unbound → `TIER_FABRICATED_ATTACK`), and appeal proofs must pass it too (unbound → appeal rejected).

Callers submit only the hash, never a URL — the contract builds the provider URL from a whitelisted template, eliminating SSRF/URL-injection vectors.

**Retired providers.** Earlier versions accepted `AGENT_RPC`, `TX_TRACE`, `SECURITY_FEED` (hosts that do not resolve), `GITHUB_AUDIT` (generic repository metadata naming no address), and `EVM_ADDRESS` (an address's explorer profile: bound to the target, but account metadata rather than an incident). All are rejected as `invalid platform`.

---

## 6. The Non-Deterministic Consensus Engine

Evaluation and appeal arbitration both run through GenLayer's leader/validator model via **`gl.vm.run_nondet`** — the *safe*, sandboxed variant that runs the validator in isolation and compares results with explicit error-equivalence handling (as opposed to the unsafe variant, which surfaces any validator error as a bare disagreement).

1. **Leader function** fetches the incident (`gl.nondet.web.get`), re-checks the evidence binding, derives a coarse threat indicator from the explorer's own flags on the parties (exploit / attacker / phishing / scam tags, `is_scam`, reverts), builds a canonical incident summary, and asks an LLM to return **strict JSON** with one of the four tiers. The summary keeps only fields that are fixed once a transaction is final — parties and their tags, status, method, value, the first token transfers — in a fixed order, so every validator prompts on identical text (the raw body carries per-block fields such as `confirmations`).
2. **Validator function** independently re-runs the leader logic and agrees only if it reaches the **same tier**, guaranteeing consensus on the categorical verdict rather than on any noisy underlying score.

**Fail-closed telemetry policy:**

- Transient faults (`429/500/502/503/504`, empty body, fetch exception) → clean revert (`[TRANSIENT]`); the report stays `PENDING` and no quarantine is applied.
- A `404` or unbound payload at filing → `ERR_UNBOUND_EVIDENCE` revert, no bond taken. The same at evaluation (evidence changed after filing) → `TIER_FABRICATED_ATTACK`, slashing the reporter.

**Prompt-injection safeguards:** every attacker-controlled field is wrapped in `<untrusted_input>…</untrusted_input>` tags, the system prompt instructs the model to ignore any instructions inside those tags, and telemetry strings are sanitized to printable ASCII before ever reaching the model.

---

## 7. Security & Audit Verification

### 7.1 Test Suite — 80 direct-mode tests

The direct-mode suite exercises every key path and adversarial edge case in-memory (no Docker, ~90s):

```bash
.venv/bin/pytest tests/direct/ -v
# ...
# 80 passed
```

> **Toolchain note:** the live contract targets the pinned runner (`py-genlayer:5jyc…`) on Studio-dev and is verified on-chain. The versions in `requirements.txt` are load-bearing — see §8.2 for why the RC line is the one that works.

Coverage highlights: bounty funding, reporting & validation, fail-closed telemetry (`429/500/503`/empty), URL/injection rejection, tier→payout binding, adversarial slashing, multi-cycle solvency, pull settlement, multi-wallet & cross-platform replay, escalating bonds, bounty-farming cooldown & pool scaling, paginated views, quarantine expiry/recovery, antibody revocation, boolean anti-spoofing, bounded-liveness reclaim, and malformed-address rejection. The steward remediation is pinned by: **evidence binding** — `test_reject_generic_unbound_github_metadata` (a GitHub repository document, even one mentioning the target, and every retired platform are refused with nothing filed), `test_unbound_evidence_reverts_at_filing` (target not a party, hash mismatch, nonexistent tx, non-JSON), `test_accept_bound_incident_telemetry` (each participant role), `test_binding_check_validators_agree_only_on_identical_binding`, and `test_triage_prompt_sees_parties_and_explorer_flags_not_volatile_fields`; **appeal escrow** — `test_payout_preserved_during_appeal`, `test_appeal_slashes_false_reporter_and_refunds_escrow`, `test_appeal_upholds_valid_incident_and_releases_escrow`, `test_junk_appeal_cannot_foreclose_the_targets_appeal`, `test_expired_appeal_refunds_appellant_and_restores_claim`, and `test_superseded_report_keeps_its_own_appealable_escrow`.

### 7.2 Protection Matrix

| Threat | Mechanism |
| :--- | :--- |
| **Reentrancy / value leakage** | Strict CEI + pull withdrawal, `on="finalized"` settlement |
| **Cross-wallet / cross-platform replay** | `sha256(platform ‖ target ‖ trace)` digest across `pending` + `evaluated` sets |
| **SSRF / URL injection** | Hash-only inputs; deterministic whitelisted URL templates; identifier must be a bare 0x tx hash |
| **Unbound / generic evidence** | Binding proven under consensus at filing: the fetched body must be the cited transaction and name the target as a party, or `ERR_UNBOUND_EVIDENCE` reverts with no bond taken; re-checked at evaluation |
| **Appeal with unrelated proof** | Same binding gate on appeal telemetry; failure rejects the appeal and forfeits its bond |
| **Front-running an appeal payout** | Disputed bond + bounty escrowed; nothing payable while an appeal is pending (`ERR_PAYOUT_LOCKED`), even past the original window |
| **Appeal lost to an outage** | Filing is deterministic and freezes the escrow at once; resolution can be retried by anyone |
| **Reporter pre-empting the target's appeal** | A rejected appeal does not pay out or close the dispute: window kept open ≥ 24h, next appeal bond escalates |
| **Prompt injection** | `<untrusted_input>` fencing + ASCII sanitization + guardrail system prompt |
| **Consensus divergence** | Coarse telemetry pre-quantization; agreement on categorical tier only |
| **Validator error opacity** | Safe, sandboxed `gl.vm.run_nondet` |
| **Griefing (false reports)** | Bonded reports; escalating bond per upheld appeal (`1 + defended`) |
| **Bounty farming** | 7-day per-target cooldown; payout capped to `pool // 10` and clamped to pool |
| **Liveness lock-up** | `reclaim_expired_report_bond` after the 7-day timeout; `expire_appeal` for an appeal consensus cannot resolve |
| **Storage DoS** | All list views bounded by `MAX_PAGE_LIMIT = 50` |
| **Integer overflow / underflow / ÷0** | `u256` wrapping, `min`-guarded subtractions, constant divisors |

### 7.3 Solvency Guarantee

The invariant `Balance = Pool + Reserves + Claimable + Claimed + Bonds + Escrow` is preserved by construction and asserted by tests. Slashes route to reserves, refunds and matured escrows route to claimable, and the bounty pool is restored on upheld appeals from the escrow the bounty never left.

### 7.4 Appeal Escrow Preservation

**Mechanism.** A verdict that quarantines a target does not pay the reporter. `evaluate_pathogen` opens an `EscrowRecord` holding the reporter's bond and the bounty, appealable until `locked_until_utc` (verdict time + quarantine duration). Appeals are **per report**, so a later report taking over the quarantine record never strands an earlier report's escrow outside any appeal.

```
LOCKED ──file_appeal──► UNDER_APPEAL ──resolve_appeal──► SLASHED          (upheld; final)
  ▲                          │                  └──────► LOCKED           (rejected; window ≥ now+24h)
  │                          └──expire_appeal (7d)─────► LOCKED           (no verdict; bond refunded)
  └──claim_payout (window closed, no appeal pending)───► RELEASED
```

**Why the penalty is always enforceable.** The value is never in the reporter's hands while anything can still reverse the verdict. Filing an appeal is deterministic — it only posts the bond and flips the escrow to `UNDER_APPEAL` — so the dispute is preserved the instant it is raised. From then until the appeal is resolved, `claim_payout` reverts with `ERR_PAYOUT_LOCKED: funds preserved until appeal resolution`, **including after the original window has elapsed**. An explorer outage or consensus retry can delay the verdict but cannot let the window run out underneath a pending appeal. When an appeal is upheld, the escrow still holds the full bond and bounty by construction.

**Outcomes.**

| Outcome | Escrow | Also |
| :--- | :--- | :--- |
| Appeal upheld (report false) | `SLASHED` — bounty → `bounty_pool_atto`, reporter bond → `protocol_reserves_atto` | appellant refunded; report `OVERTURNED`; antibody revoked; quarantine lifted if this report defines it; defended-appeal counter +1 |
| Appeal rejected (incident stands) | back to `LOCKED`; window extended to at least now + 24h; `failed_appeals` +1 | appellant's contestation bond → reserves; report `RESOLVED`; quarantine stays |
| Appeal unresolved for 7 days | back to `LOCKED`, window not extended | appellant refunded; appeal `EXPIRED`; verdict stands |
| Window closes, no appeal pending | `claim_payout` → `RELEASED` to the reporter | permissionless; pays only the recorded reporter |

**Why a rejected appeal does not pay the reporter immediately.** Anyone may appeal, so if a rejection settled the dispute, a reporter could file a deliberately losing appeal against their own false report just before the window closed — forfeiting 0.2 GEN to collect up to 1.1 GEN and lock the real target out. Instead a rejection keeps the report appealable for at least 24 hours, and each rejected appeal on a report raises the next appeal bond (0.2 → 0.4 → 0.6 GEN), so repeated appeals cannot hold a payout hostage cheaply. `test_junk_appeal_cannot_foreclose_the_targets_appeal` pins this.

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
.venv/bin/pytest tests/direct/ -v      # expect: 80 passed
```

The direct runner loads the contract against its pinned runner
(`py-genlayer:5jyc…`), mocks web/LLM calls, and executes entirely in-memory.

The versions in `requirements.txt` are load-bearing, not cosmetic. On the older stable
toolchain (`genlayer-test 0.29.2` / `genlayer-py 0.16.3`) the direct runner extracts a
`v0.2.16` SDK that reads its calldata from stdin at import time and dies under pytest with
`DecodingError: unexpected end of memory` — every test fails before reaching the contract.
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
genlayer call 0x038d5Fd5082Cb05586C4C7CBcdDE827AC7f6BBa1 get_registry_overview
```

Writes need the same treatment, derived per call rather than hardcoded. `genlayer write`
cannot send value at all (`value: 0n` is hardcoded in the CLI), so payable methods —
`fund_bounty_pool`, `report_pathogen`, `file_appeal` — are unreachable from the CLI.
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

The first walks all 15 view methods and dry-runs all 13 writes; the second runs 64 adversarial
cases (unauthorized withdrawal, `report_id` validation, platform allow-list incl. every retired
provider, evidence-identifier injection, evidence-to-target binding against real Ethereum
transactions, appeal/escrow guards, malformed addresses, bond enforcement, state-machine guards,
pagination bounds). Against the v0.4.0 deployment: 20 ok / 16 expected reverts / 0 failures,
and 64 blocked-or-bounded / 0 issues.
Both pace themselves under the node's limit of **30 requests per minute** — exceeding it fails
with error `-32029` and a `retry_after_seconds` hint. See
[`frontend/scripts/README.md`](frontend/scripts/README.md).

Both of those are **dry runs**. A simulation executes the call on a single node — including the
leader side of `run_nondet`, which is why section 5 of the security suite sees the real
`ERR_UNBOUND_EVIDENCE` computed from a live Blockscout fetch — but commits nothing and involves no
validators, so it cannot show consensus being reached. A third script does, by filing a real
bonded report and letting the tier decide the outcome:

```bash
GL_PK=$(security find-generic-password -s genlayer-cli -a account:<name> -w) \
  node --experimental-strip-types --import ./scripts/ts-resolve-register.mjs ./scripts/live-cycle.mjs
```

**Live run against v0.4.0 (2026-09-22).** Report `euler-exploit-1` cited the Euler Finance
exploit transaction `0xc310a0af…b111d` (Ethereum, 2023-03-13) against its sender
`0x5F259D0b…8B8c`, which Blockscout tags *Euler Finance Exploiter 3* / `ATTACKER`:

| Step | Transaction | Outcome |
| :--- | :--- | :--- |
| `report_pathogen` | `0xe118c1556e47ea97e7ab1bb61facf1baa37faa6968d4e41fddff54241357f618` | Validators fetched the tx and agreed the target is its `from`; `evidence_binding = "from"`, 0.1 GEN bond taken |
| `evaluate_pathogen` | `0x374e3c111a253d6671012805490edf776450a649a52431b7e1bc2cb24b29d58e` | **`TIER_PATHOGEN_CRITICAL`**; 7-day quarantine; antibody `0ab5c839…547c04` minted |

The bond was not refunded to `claimable_balances`: it sits in escrow `LOCKED` until
2026-09-29T17:55:29Z (`locked_escrow_atto` = 0.1 GEN, claimable 0), appealable via
`file_appeal`. The same deployment refuses the same transaction cited against an address that is
not a party to it (`ERR_UNBOUND_EVIDENCE`, parties listed in the message). The deployment record
is in [`deployments/studio-dev.json`](deployments/studio-dev.json).

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
│       └── test_phage_sentinel.py   # 80-test direct-mode suite
├── deployments/
│   └── studio-dev.json              # Live address, deploy tx, live-cycle txs
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

Phage Sentinel is research-grade software provided **as-is** for the GenLayer ecosystem. It has not undergone a third-party security audit; the 80-test suite and the invariants documented above are the current verification baseline. Deploy to mainnet-equivalent environments at your own risk and after independent review.

Released under the **MIT License**.
