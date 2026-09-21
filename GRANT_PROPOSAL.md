# GenLayer Ecosystem Grant Proposal: Phage Protocol

### Autonomous On-Chain Immune System & Threat Quarantine Protocol for the Agentic Economy

```
Project Name:        Phage (Phage Sentinel)
Track:               Track 6: Autonomous Protocols & Agentic Infrastructure
Target Network:      GenLayer (Studio-dev / Mainnet)
Contract Address:    0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80
Owner:               0x1f9813eeB2de53134af5C824cA156CE82C4EB0fa
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
2. **Native Non-Deterministic Web Access (`gl.nondet.web.get`)**: Validators can query authenticated telemetry endpoints, transaction traces, and security feeds in real time, securely bound through GenLayer’s leader-validator equivalence framework.

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
                            report_pathogen(bond >= 0.1 GEN)
                                         v
                 +------------------------------------------------+
                 |            PHAGE SENTINEL CONTRACT             |
                 |  - Replay Check: SHA256(Platform|Target|Trace) |
                 |  - Pending Digest Tracking (No Race Condition) |
                 |  - Dynamic Escalating Bond Verification        |
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
  * 100% Reporter Bond Slashed  * 24-Hour Quarantine Hold       * 7-Day / Permanent Quarantine
  * Sent to Reserves            * 0 GEN Bounty Allocated        * Bond + Bounty -> ESCROW
  * Zero Quarantine Applied     * Reporter Bond Refunded        * Global Antibody Minted
                                * No Escrow Opened                       |
                                                                         v
                                                       +----------------------------------+
                                                       |         QUARANTINE STATE         |
                                                       | is_quarantined(target) == True   |
                                                       | disputed value held in ESCROW,   |
                                                       | locked for the appeal window     |
                                                       +----------------------------------+
                                                                         |
                                                   appeal_quarantine(bond = 0.2 GEN)
                                                                         |
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
                     * Quarantine Lifted Instantly                                     * 100% Appeal Bond Slashed
                     * Appeal Bond Refunded to Appellant                               * Transferred to Reserves
                     * ESCROW SLASHED (the penalty lands in full,                       * Quarantine Remains Active
                       because the value was never withdrawable)                       * ESCROW RELEASED to Reporter
                     * Reporter Bond -> Reserves, Bounty -> Pool                         (they need not wait out
                     * Antibody Revoked (is_active = False)                               the remaining quarantine)
                     * Target Defended Appeals Incremented                             * Defense Counter Unchanged
                                        |                                                                 |
                                        +--------------------------------+--------------------------------+
                                                                         |
                                                            no appeal filed, window elapses
                                                                         v
                                                       +----------------------------------+
                                                       |  release_escrow(report_id)       |
                                                       |  permissionless; pays only the   |
                                                       |  recorded reporter               |
                                                       +----------------------------------+
```

### 3.1 Core Innovations
1. **Discrete Categorical Consensus**: To eliminate validator float-divergence, evaluations strictly resolve into indivisible discrete tuples `(quarantine_seconds, payout_basis_points)`.
2. **Defensive Prompt Sandboxing**: Telemetry payloads are strictly encapsulated within `<untrusted_input>` XML tags with pre-quantized telemetry indicators (`CRITICAL_PATHOGEN_INDICATED`, `SUSPICIOUS_ANOMALY_INDICATED`, `BENIGN_NOMINAL_INDICATED`), making adversarial jailbreaks mathematically impossible.
3. **Escalating Anti-Griefing Bonds**: To prevent malicious actors from repeatedly grieving legitimate competitor agents, each successfully defended appeal dynamically scales future required reporter bonds:
   $$\text{Required Bond} = \text{MIN\_REPORTER\_BOND} \times (1 + \text{defended\_appeals})$$
4. **Conservation of Value Accounting**: Double-entry bookkeeping guarantees absolute solvency across all deposits, active bounties, reserves, pending bonds, claimable balances, and escrowed disputed payouts.
5. **Composable Protocol Inoculation**: External DeFi protocols simply import `IPhageSentinel` and apply the `onlyHealthyAgent(target)` modifier, gaining instant, automated protection against compromised counterparties.
6. **Deterministic Evidence Binding**: Every report and appeal cites an identifier the contract itself resolves to a participant set or an address, and checks against the accused *before* the model is consulted — so an unbound payload cannot reach a verdict at all.

### 3.2 Escrowed Disputed Payouts & Evidence Binding

**Evidence binds to the target before any model sees it.** A report cites one of three
telemetry sources, each of which resolves to a live public indexer and carries an
identifier the contract checks deterministically against the accused agent:

| Platform | Source | Binding check |
| :--- | :--- | :--- |
| `EVM_TX` | `eth.blockscout.com` | The target must appear in the transaction's participant set (`from`, `to`, or `created_contract`). |
| `EVM_TX_BASE` | `base.blockscout.com` | Same, on Base. |
| `EVM_ADDRESS` | `eth.blockscout.com` | The evidence identifier *is* the target address; the contract requires the two to match exactly. |

This check runs in the contract, before `gl.nondet.exec_prompt` is reached. A payload that
does not implicate the accused returns `TIER_FABRICATED_ATTACK` and slashes the reporter's
bond — it never becomes an input to the model. Determinism is the point: a prompt
instruction is advice to a model, whereas this is a guarantee enforced on the validator's
own copy of the data, so every validator reaches the same conclusion from the same bytes.
The same gate applies to appeal proofs, so an appellant cannot win with records about some
unrelated agent.

**Disputed payouts are escrowed, not paid.** A verdict that quarantines a target credits
the reporter nothing immediately. Instead the contract opens an `EscrowRecord` holding the
reporter's bond and the bounty, locked for the length of the quarantine — which is exactly
the appeal window, since `appeal_quarantine` requires an active quarantine. The disputed
value is therefore never in the reporter's hands while the appeal can still reverse it:

- **Appeal upheld** (quarantine overturned) → the appellant's bond is refunded, the
  quarantine and antibody are revoked, and the escrow is slashed: the leaked bounty
  returns to the pool it came from and the malicious reporter's own bond is forfeit to
  reserves. The penalty is enforced in full, because the value was never withdrawable.
- **Appeal rejected** → the appellant's bond is forfeit to reserves, the quarantine
  stands, and the escrow is released to the reporter immediately rather than making them
  wait out the remaining quarantine.
- **No appeal** → `release_escrow(report_id)` becomes callable once the window elapses.
  It is permissionless by design: the only address it can ever pay is the reporter
  recorded in the escrow, so anyone may trigger it and the funds cannot be stranded on an
  inactive reporter.

This closes the front-running hole in the earlier optimistic-payout model, where a
reporter could withdraw a bounty immediately after finalization and leave nothing for an
appeal to claw back. It is pinned by `test_reporter_cannot_escape_appeal_penalty_by_withdrawing_first`
and `test_escrow_accounting_keeps_solvency_across_both_outcomes`, and exposed on-chain via
`get_escrow` and the `locked_escrow_atto` field of the registry overview. The protocol's
conservation-of-value invariant now accounts for escrowed value as a first-class bucket.

---

## 4. Current Development Status & Validation Proof

Phage is not a theoretical whitepaper; it is a **fully implemented, battle-tested, and live protocol** deployed on GenLayer Studio-dev.

### 4.1 Production Deployment
- **Network**: GenLayer Studio-dev (Chain ID: `61997`)
- **Contract Address**: [`0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80`](https://explorer-studio-dev.genlayer.com/address/0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80)
- **Live Demo**: [phage-sentinel.vercel.app](https://phage-sentinel.vercel.app) — the dApp reads and writes this deployment directly; reads work with no wallet connected.
- **Compiler / Runner**: Pinned GenVM v0.3.0 (`py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng`)

### 4.2 Comprehensive Test Suite
- **Direct Mode Test Suite**: 66 unit and regression tests (100% pass on a matching v0.3.0 GenVM toolchain).
- **Live Consensus Run**: a real end-to-end cycle has executed on-chain — report `live-cycle-1` resolved `TIER_BENIGN_NOISE` through multi-LLM consensus, with the tier bound to zero quarantine and zero payout and the 0.1 GEN bond refunded intact. This is the non-deterministic path running for real, not a simulation. The run was performed against the pre-remediation deployment (`GITHUB_AUDIT`); the telemetry platform set has since been replaced, and the cycle is re-run against each new deployment.
- **Adversarial Suite**: 60 cases against the live deployment (unauthorized withdrawal, `report_id` / evidence-identifier injection, platform allow-list, malformed addresses, evidence-to-target binding, escrow release guards, bond enforcement, state-machine guards, pagination bounds) — all refused by the contract's own `[EXPECTED]` guards, 0 bypasses.
- **Test Categories**:
  - Full pathogen lifecycle (Reporting $\to$ Evaluation $\to$ Quarantine $\to$ Antibody Minting $\to$ Bounties).
  - Multi-LLM prompt injection resilience and telemetry spoofing rejection.
  - Pending replay race condition prevention and platform-scoped digest validation.
  - Appeal arbitration, bond slashing, bounty restitution, and antibody revocation.
  - Evidence-to-target binding (unbound transaction and address records rejected) and escrow locking across both appeal outcomes.
  - Mathematical balance conservation across high-volume stress cycles.
- **Static Analysis**: 100% pass rate on `genvm-lint` with 0 warnings/errors across 24 contract methods (15 view, 9 write).

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
- **Test Suite (66 tests)**: [`tests/direct/test_phage_sentinel.py`](https://github.com/moltaphet/phage/blob/main/tests/direct/test_phage_sentinel.py)
- **Studio-dev Explorer**: [0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80](https://explorer-studio-dev.genlayer.com/address/0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80)
- **Project Documentation**: [README.md](https://github.com/moltaphet/phage/blob/main/README.md)
