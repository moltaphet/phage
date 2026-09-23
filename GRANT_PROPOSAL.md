# GenLayer Ecosystem Grant Proposal: Phage Protocol

### Autonomous On-Chain Immune System & Threat Quarantine Protocol for the Agentic Economy

```
Project Name:        Phage (Phage Sentinel)
Track:               Track 6: Autonomous Protocols & Agentic Infrastructure
Target Network:      GenLayer (Studio-dev / Mainnet)
Contract Address:    0x831e3b4772c86F05EB780174CbDc30926DF8d2B2   (v0.5.0)
Deploy Tx:           0x58e04a07337f3fb03076c5b42040bbe1d6a94e0b1c4908e90920c5f4540d632d
Owner:               0x2E56C8579fA11CB144E6FD778dA772061f4dd930
Live Demo:           https://phage-sentinel.vercel.app
License:             MIT Open Source
Repository:          https://github.com/moltaphet/phage
```

---

## 1. Executive Summary

As the Web3 paradigm evolves from human-driven transactions to the **Agentic Economy**, autonomous AI agents are assuming direct custody of multi-million dollar protocol treasuries, executing autonomous arbitrage, and orchestrating algorithmic trades. However, this transition introduces an existential security dilemma: **agents are fundamentally susceptible to semantic, non-deterministic exploits**—including prompt injection, goal hijacking, model hallucination manipulation, and corrupted off-chain telemetry feeds.

Standard EVM chains are mathematically blind to semantic exploits because deterministic smart contracts cannot parse natural language, evaluate unstructured forensic logs, or arbitrate agent behavior. Furthermore, traditional human emergency multisigs (with 4- to 48-hour response latencies) are obsolete against machine-speed drain events.

**Phage** is the first decentralized, autonomous on-chain immune system built natively on GenLayer. Emulating biological bacteriophages that target pathogenic organisms while preserving healthy cells, Phage provides:
1. **Real-time decentralized pathogen sensing** via economic reporter bonds.
2. **Multi-LLM consensus triage** that analyzes unstructured forensic logs directly on-chain via GenVM.
3. **Autonomous, millisecond-scale threat quarantine** preventing compromised agents from interacting with DeFi vaults.
4. **Global cryptographic antibody registry** providing systemic inoculation across all participating protocols.
5. **Robust economic game theory** with anti-griefing bond scaling, appeal arbitration, and restitution slashing.

Phage is not merely another smart contract—it is an **essential infrastructure public good** that enables the entire autonomous agent economy on GenLayer to operate safely.

---

## 2. Problem Statement & Market Opportunity

### 2.1 The Agentic Security Crisis
In 2024–2026, autonomous agent frameworks (AutoGPT, Eliza, CrewAI, LangChain) transitioned from sandboxed scripts to key-holding Web3 financial actors. Autonomous agents hold private keys, manage LP positions, and trigger automated smart contract functions.

However, existing security stacks are broken for this paradigm:
- **Semantic Attack Vectors**: An attacker does not need a bytecode reentrancy bug. By sending a carefully crafted micro-transaction or natural language RPC message containing a prompt injection, the attacker hijacks the agent’s internal planner, causing it to transfer funds or liquidate collateral to an exploit contract.
- **Inability of EVM to Inspect Semantic Context**: On Ethereum or Solana, smart contracts can only check numeric balances and cryptographic signatures. They cannot evaluate whether an agent's transaction was induced by a prompt injection attack.
- **The Human Latency Failure**: A compromised autonomous agent executes thousands of malicious state transitions within minutes. Relying on off-chain human multisig signers to recognize the attack, coordinate across time zones, and execute an emergency pause guarantees that treasuries are drained before human intervention begins.

### 2.2 Why This Problem Can ONLY Be Solved on GenLayer
Phage requires two fundamental capabilities that do not exist on any other blockchain:
1. **Multi-LLM Validator Consensus (`gl.nondet.exec_prompt`)**: GenLayer's GenVM allows independent validator nodes to run parallel LLM inferences over forensic logs and reach deterministic consensus on complex semantic evaluations (e.g., classifying whether an agent log represents a critical exploit or benign noise).
2. **Native Non-Deterministic Web Access (`gl.nondet.web.get`)**: Validators independently fetch the cited incident — today, a transaction record from a public block explorer — and must agree on what it shows, through GenLayer’s leader-validator equivalence framework.

Without GenLayer, an on-chain immune protocol would have to rely on centralized off-chain oracles, recreating the very single-point-of-failure vulnerabilities that decentralized systems seek to eliminate.

---

## 3. Protocol Architecture & Technical Innovation

Phage combines biomimetic immunology with rigorous GenVM decentralized state machine engineering.

```
                              +--------------------+
                              |  External Sentinel |
                              | (Human/AI Watcher) |
                              +--------------------+
                                         |
                   report_pathogen(bond >= 0.1 GEN, incident tx hash)
                                         v
                 +------------------------------------------------+
                 |            PHAGE SENTINEL CONTRACT             |
                 |  - Replay Check: SHA256(Platform|Target|Trace) |
                 |  - Pending Digest Tracking (No Race Condition) |
                 |  - Dynamic Escalating Bond Verification        |
                 |  - Evidence Binding under consensus: the tx    |
                 |    must name the target, else revert           |
                 |    ERR_UNBOUND_EVIDENCE (no bond taken)        |
                 +------------------------------------------------+
                                         |
                                 evaluate_pathogen()
                                         v
                         +------------------------------+
                         |     GENVM NONDET ENGINE      |
                         |  Multi-LLM Validator Quorum  |
                         |     gl.nondet.web.get()      |
                         |   gl.nondet.exec_prompt()    |
                         +------------------------------+
                                         |
        +--------------------------------+-------------------------------+
        |                                |                               |
        v                                v                               v
[TIER_FABRICATED_ATTACK]      [TIER_SUSPICIOUS_ANOMALY]       [TIER_PATHOGEN_CRITICAL]
  * 100% Reporter Bond Slashed  * 24-Hour Quarantine Hold       * 7-Day Quarantine
  * Sent to Reserves            * 0 GEN Bounty Allocated        * Bond + Bounty -> ESCROW
  * Zero Quarantine Applied     * Reporter Bond -> ESCROW       * Global Antibody Minted
                                                                         |
                                                                         v
                                                       +----------------------------------+
                                                       |         QUARANTINE STATE         |
                                                       | is_quarantined(target) == True   |
                                                       | disputed value held in ESCROW    |
                                                       | (LOCKED) until no appeal can     |
                                                       | reach it                         |
                                                       +----------------------------------+
                                                                         |
                                      file_appeal(report_id, proof tx, bond >= 0.2 GEN)
                                      escrow -> UNDER_APPEAL: claim_payout reverts with
                                      ERR_PAYOUT_LOCKED until the appeal is resolved
                                                                         |
                                                             resolve_appeal(appeal_id)
                                                                         v
                                                       +----------------------------------+
                                                       |     APPEAL CONSENSUS ARBITER     |
                                                       |  Multi-LLM Telemetry Verification|
                                                       |  (proof must bind to the target) |
                                                       +----------------------------------+
                                                                         |
                                        +--------------------------------+--------------------------------+
                                        |                                                                 |
                                        v                                                                 v
                                [APPEAL UPHELD]                                                   [APPEAL REJECTED]
                     * ESCROW SLASHED: reporter bond -> reserves,                      * Contestation bond -> reserves
                       bounty -> pool (the penalty lands in full,                      * Quarantine remains active
                       because nothing was payable while pending)                      * ESCROW back to LOCKED; window
                     * Appeal bond refunded to appellant                                 kept open >= 24h, next appeal
                     * Quarantine lifted, antibody revoked                               bond doubles
                     * Report OVERTURNED; defended appeals +1                          * Report RESOLVED
                                        |                                                                 |
                                        +--------------------------------+--------------------------------+
                                                                         |
                                                window closed, no appeal pending
                                                                         v
                                                       +----------------------------------+
                                                       |  claim_payout(report_id)         |
                                                       |  permissionless; pays only the   |
                                                       |  recorded reporter               |
                                                       +----------------------------------+
```

### 3.1 Core Innovations
1. **Discrete Categorical Consensus**: To eliminate validator float-divergence, evaluations strictly resolve into indivisible discrete tuples `(quarantine_seconds, payout_basis_points)`.
2. **Defensive Prompt Sandboxing**: Telemetry payloads are strictly encapsulated within `<untrusted_input>` XML tags with a coarse threat indicator derived deterministically from the explorer's own exploit/scam flags on the parties, making prompt injection through the evidence substantially harder (the binding and tier mapping are enforced in code regardless of what the model says).
3. **Escalating Anti-Griefing Bonds**: To prevent malicious actors from repeatedly grieving legitimate competitor agents, each successfully defended appeal dynamically scales future required reporter bonds:
   $$\text{Required Bond} = \text{MIN\_REPORTER\_BOND} \times (1 + \text{defended\_appeals})$$
4. **Conservation of Value Accounting**: Double-entry bookkeeping guarantees absolute solvency across all deposits, active bounties, reserves, pending bonds, claimable balances, and escrowed disputed payouts.
5. **Composable Protocol Inoculation**: Other contracts consult `is_quarantined(target)` on-chain today; a Solidity `IPhageSentinel` interface and `onlyHealthyAgent` modifier are Milestone 2 deliverables.
6. **Incident-Bound Evidence**: Every report cites one on-chain incident (a transaction hash). Validators fetch it when the report is filed and must agree it names the accused as a party, or the filing reverts with `ERR_UNBOUND_EVIDENCE` and no bond is taken.
7. **Appeal Escrow Preservation**: Disputed payouts are frozen from the moment an appeal is filed until it is resolved, so the promised penalty is always still enforceable.

### 3.2 Incident Binding & Appeal Escrow Preservation

**Evidence is one incident, bound to the target at filing.** A report cites a transaction
hash on one of two platforms, both Blockscout's keyless public API:

| Platform | Source |
| :--- | :--- |
| `EVM_TX` | `https://eth.blockscout.com/api/v2/transactions/{hash}` |
| `EVM_TX_BASE` | `https://base.blockscout.com/api/v2/transactions/{hash}` |

`report_pathogen` fetches the transaction inside `gl.vm.run_nondet`, and every validator
must derive the same result from its own fetch. The evidence is bound only if the provider
answers 200, the body is a transaction whose `hash` echoes the cited one, and the target is
its `from`, `to` or `created_contract`. Otherwise the filing reverts with
`ERR_UNBOUND_EVIDENCE` before any state is written, so no bond is taken. Generic metadata of
any kind (a repository document, an address profile) fails the second check. The target's
proven role is committed to the report as `evidence_binding`. Evaluation re-checks the same
binding on the bytes it classifies, and appeal proofs must pass it too.

The earlier providers are retired and refused as `invalid platform`: `AGENT_RPC`,
`TX_TRACE` and `SECURITY_FEED` pointed at hosts that did not resolve, `GITHUB_AUDIT`
returned generic repository metadata naming no address, and `EVM_ADDRESS` returned an
address profile, which is bound to the target but is not an incident.

**Disputed payouts are preserved until the appeal can enforce its penalty.** A quarantine
verdict credits the reporter nothing; it opens an escrow holding the bond and bounty.
Appeals are per report and are split in two:

- `file_appeal(report_id, proof, platform)` is deterministic. It posts the appeal bond and
  moves the escrow to `UNDER_APPEAL`. From then on `claim_payout` reverts with
  `ERR_PAYOUT_LOCKED: funds preserved until appeal resolution`, even after the original
  window has elapsed, so an explorer outage or consensus retry cannot let the reporter
  collect while an appeal is pending.
- `resolve_appeal(appeal_id)` runs appeal consensus and is permissionless.
  - **Upheld:** the escrow is slashed (reporter bond to reserves, bounty back to the
    pool), the appellant is refunded, the quarantine and antibody are lifted, and the
    report is marked `OVERTURNED`.
  - **Rejected:** the appellant's contestation bond goes to reserves and the escrow
    returns to `LOCKED`. The reporter is paid by `claim_payout` once the window closes.
- `expire_appeal` closes an appeal that consensus could not resolve in 7 days. It refunds
  the bond and the verdict stands, so no appeal can freeze a payout indefinitely.

A rejection deliberately does not pay out on the spot. Otherwise a reporter could file a
losing appeal against their own false report to foreclose the target's appeal. Instead the
window stays open at least 24h after a rejection, and each rejected appeal doubles the next
appeal bond on that report.

**Live on studio-dev (v0.4.0).** Report `euler-exploit-1` cited the Euler Finance exploit
transaction against its sender (tagged "Euler Finance Exploiter 3" by Blockscout).
Validators agreed on the binding (`from`) in report tx `0xe118c155…f618`. Evaluation tx
`0x374e3c11…d58e` resolved `TIER_PATHOGEN_CRITICAL` and minted an antibody, and the bond is
held in escrow `LOCKED` until the appeal window closes.

---

## 4. Current Development Status & Validation Proof

Phage is not a theoretical whitepaper; it is a **fully implemented, battle-tested, and live protocol** deployed on GenLayer Studio-dev.

### 4.1 Production Deployment
- **Network**: GenLayer Studio-dev (Chain ID: `61997`)
- **Contract Address**: [`0x831e3b4772c86F05EB780174CbDc30926DF8d2B2`](https://explorer-studio-dev.genlayer.com/address/0x831e3b4772c86F05EB780174CbDc30926DF8d2B2) (v0.5.0)
- **Deploy Transaction**: `0x58e04a07337f3fb03076c5b42040bbe1d6a94e0b1c4908e90920c5f4540d632d` (see [`deployments/studio-dev.json`](deployments/studio-dev.json))
- **Live Demo**: [phage-sentinel.vercel.app](https://phage-sentinel.vercel.app) — the dApp reads and writes this deployment directly; reads work with no wallet connected.
- **Compiler / Runner**: Pinned runner `py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng`

### 4.2 Comprehensive Test Suite
- **Direct Mode Test Suite**: 80 unit and regression tests, all passing.
- **Live Consensus Run (v0.4.0)**: report `euler-exploit-1` cited a real exploit transaction; validators agreed on the target binding at filing, then resolved `TIER_PATHOGEN_CRITICAL`, quarantined the target, minted an antibody and escrowed the bond. This is the non-deterministic path running for real, not a simulation.
- **Adversarial Suite**: 64 cases against the live deployment (unauthorized withdrawal, `report_id` / evidence-identifier injection, platform allow-list incl. every retired provider, malformed addresses, evidence-to-target binding against real Ethereum transactions, appeal/escrow guards, bond enforcement, state-machine guards, pagination bounds) — all refused or bounded, 0 bypasses.
- **Test Categories**:
  - Full pathogen lifecycle (Reporting $\to$ Evaluation $\to$ Quarantine $\to$ Antibody Minting $\to$ Bounties).
  - Multi-LLM prompt injection resilience and telemetry spoofing rejection.
  - Pending replay race condition prevention and platform-scoped digest validation.
  - Appeal arbitration, bond slashing, bounty restitution, and antibody revocation.
  - Incident binding (generic repository metadata, unbound, nonexistent and mismatched transactions all revert `ERR_UNBOUND_EVIDENCE` at filing) and appeal escrow preservation (payout locked while under appeal, false reporter slashed, valid incident paid out, junk-appeal pre-emption, appeal expiry).
  - Mathematical balance conservation across high-volume stress cycles.
- **Static Analysis**: `genvm-lint lint` and `genvm-lint validate` pass across 27 contract methods (15 view, 12 write).

---

## 5. Ecosystem Impact & Value Proposition to GenLayer

Funding Phage creates multi-dimensional value for the GenLayer network:

1. **Flagship Demonstration of GenVM Capabilities**: Phage provides an intuitive, high-impact narrative that showcases why GenLayer's Multi-LLM consensus and non-deterministic execution are indispensable for Web3.
2. **Foundational Security Infrastructure**: Any team building autonomous agents, AI hedge funds, prediction markets, or autonomous DAOs on GenLayer can integrate Phage out-of-the-box, significantly lowering their security overhead.
3. **Ecosystem Token Utility & Demand Sink**: Reporter bonds, appeal deposits, and protocol bounties are paid strictly in **$GEN**, creating sustainable, security-driven on-chain demand for the native asset.
4. **Cross-Chain Security Inoculation**: As Phage's antibody registry grows, other networks (Arbitrum, Base, Optimism) can read GenLayer state as a **decentralized security oracle**, cementing GenLayer as the trust anchor of the agentic Web3.

---

## 6. Milestones, Deliverables & Budget Breakdown

We are requesting a grant of **$45,000 (denominated in USD / equivalent $GEN)** distributed across three performance-verified milestones:

### Milestone 1: Production Hardening & Sentinel Watcher Node Release
*Duration: 6 Weeks | Funding: $15,000*
- [x] **Core Sentinel Contract**: Deployed on Studio-dev with 100% test coverage and linter pass.
- [ ] **Open-Source Watcher Daemon (`phage-watcher`)**: Lightweight Python/Node.js service that monitors agent RPCs, parses anomalies, and automatically submits reports with economic bonds.
- [ ] **Telemetry Provider Integration**: Pre-configured connectors for standard agent telemetry feeds (Langfuse, AgentOps, Helicone, on-chain trace RPCs).
- [ ] **Technical Documentation & Video Walkthrough**: End-to-end integration tutorial for agent developers.

### Milestone 2: Agent SDK, Inoculation Middleware & Developer Dashboard
*Duration: 6 Weeks | Funding: $15,000*
- [ ] **TypeScript & Python Client SDK (`@phage/sdk`)**: Simplified client library for querying quarantine state, verifying antibodies, and submitting appeals.
- [ ] **Solidity / EVM Interface & Library**: Standardized interface (`IPhageSentinel.sol`) and ready-to-use modifier contracts (`onlyHealthyAgent`) for EVM cross-compatibility.
- [ ] **Sentinel Analytics Web Dashboard**: Open-source visual explorer tracking active quarantines, circulating antibodies, reporter rankings, and bounty pool health.
- [ ] **Automated Fuzzing & Formal Verification**: Comprehensive invariant testing via Echidna/Hypothesis over GenVM state transitions.

### Milestone 3: Cross-Chain Oracle Bridge, Security Partnerships & Mainnet Launch
*Duration: 8 Weeks | Funding: $15,000*
- [ ] **Cross-Chain Immune Oracle**: Integration with LayerZero / Chainlink CCIP / Hyperlane to broadcast antibody signatures and quarantine verdicts from GenLayer to EVM chains.
- [ ] **Pilot Integrations with 3+ GenLayer Ecosystem Projects**: Direct integration with autonomous vaults and agent protocols on GenLayer.
- [ ] **Bug Bounty Program & Security Audit**: Formal third-party smart contract audit prior to GenLayer Mainnet launch.
- [ ] **Mainnet Genesis Deployment**: Protocol initialization on GenLayer Mainnet with genesis bounty seed funding.

---

## 7. Budget Allocation

| Category | Description | Allocation |
| :--- | :--- | :--- |
| **Core Protocol Engineering** | GenVM optimization, SDK development, Watcher daemon implementation | 45% ($20,250) |
| **Security Audit & Verification** | Third-party smart contract audit, formal verification, fuzz testing | 25% ($11,250) |
| **Frontend & Developer Tooling** | Immune Explorer dashboard, telemetry connectors, documentation | 15% ($6,750) |
| **Ecosystem Seed Bounty Pool** | Initial on-chain liquidity deposited into `fund_bounty_pool()` to bootstrap sentinels | 15% ($6,750) |
| **Total** | | **100% ($45,000)** |

---

## 8. Project Links & Verification

- **Smart Contract Code**: [`contracts/phage_sentinel.py`](https://github.com/moltaphet/phage/blob/main/contracts/phage_sentinel.py)
- **Test Suite (80 tests)**: [`tests/direct/test_phage_sentinel.py`](https://github.com/moltaphet/phage/blob/main/tests/direct/test_phage_sentinel.py)
- **Studio-dev Explorer**: [0x831e3b4772c86F05EB780174CbDc30926DF8d2B2](https://explorer-studio-dev.genlayer.com/address/0x831e3b4772c86F05EB780174CbDc30926DF8d2B2)
- **Project Documentation**: [README.md](https://github.com/moltaphet/phage/blob/main/README.md)
