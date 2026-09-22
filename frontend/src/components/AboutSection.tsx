import { ExternalLink } from 'lucide-react';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_EXPLORER } from '../lib/contract';
import { shortHex } from '../lib/format';

export function AboutSection() {
  return (
    <div className="stack" style={{ gap: 24 }}>
      <section className="plate">
        <p className="kicker" style={{ marginBottom: 12 }}>Biomimetic defense</p>
        <h2 className="section-title">Autonomous containment for the agentic economy</h2>
        <p className="section-copy" style={{ marginTop: 14 }}>
          Autonomous agents now hold keys, manage LP positions, and sign state changes. A prompt injection or hijacked tool call can drain a treasury before a human multisig wakes up. Phage is the on-chain immune system for that world: reporters stake bonds, GenLayer validators classify forensic logs with multi-LLM consensus, and quarantined agents are refused by any contract that checks <code className="mono">onlyHealthyAgent</code>.
        </p>
      </section>

      <div className="cards cards-3">
        <article className="pillar">
          <div className="label">01</div>
          <h3 className="h3" style={{ marginTop: 10 }}>Semantic attack surface</h3>
          <p className="help" style={{ marginTop: 8, lineHeight: 1.65 }}>
            Eliza, LangChain, and CrewAI agents parse unstructured RPC, RSS, and webhooks. The exploit is language, not bytecode. Deterministic EVM contracts cannot see it.
          </p>
        </article>
        <article className="pillar">
          <div className="label">02</div>
          <h3 className="h3" style={{ marginTop: 10 }}>Multi-LLM quorum</h3>
          <p className="help" style={{ marginTop: 8, lineHeight: 1.65 }}>
            Independent GenLayer validators run <code className="mono">gl.nondet.exec_prompt</code> over telemetry, then converge on a discrete tier — fabricated, anomaly, or critical pathogen.
          </p>
        </article>
        <article className="pillar">
          <div className="label">03</div>
          <h3 className="h3" style={{ marginTop: 10 }}>Cryptographic inoculation</h3>
          <p className="help" style={{ marginTop: 8, lineHeight: 1.65 }}>
            A confirmed threat mints an SHA-256 antibody. Every integrated vault inherits the block without a manual upgrade.
          </p>
        </article>
      </div>

      <section className="plate">
        <h3 className="h3">Biology mapped onto protocol</h3>
        <p className="help" style={{ margin: '8px 0 16px' }}>
          Bacteriophages hunt a specific pathogen and leave the host intact. Phage does the same for agents.
        </p>
        <div className="ledger-wrap">
          <table className="ledger">
            <thead>
              <tr>
                <th>Immune system</th>
                <th>Phage on GenLayer</th>
                <th>Effect</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Pathogen</td>
                <td className="mono">Rogue agent / exploit payload</td>
                <td>Prompt injection, drain, oracle poison</td>
              </tr>
              <tr>
                <td>T-cell recognition</td>
                <td className="mono">Multi-LLM consensus</td>
                <td>Independent nodes classify the trace</td>
              </tr>
              <tr>
                <td>Cellular quarantine</td>
                <td className="mono">evaluate_pathogen</td>
                <td>Isolation for 24h or 7 days</td>
              </tr>
              <tr>
                <td>Antibody memory</td>
                <td className="mono">evaluate_pathogen (critical)</td>
                <td>Network-wide payload rejection</td>
              </tr>
              <tr>
                <td>Autoimmune check</td>
                <td className="mono">file_appeal / resolve_appeal</td>
                <td>Bound counter-proof lifts a false positive and slashes the reporter</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <div className="contract-bar">
        <div>
          <div style={{ fontWeight: 700 }}>Live on GenLayer Studio-dev</div>
          <div className="hash" style={{ marginTop: 4, color: 'var(--filament-mute)' }}>
            {shortHex(PHAGE_CONTRACT_ADDRESS, 12, 8)} · chain 61997
          </div>
        </div>
        <a
          className="btn btn-ghost"
          href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          Open explorer
          <ExternalLink size={14} aria-hidden="true" />
        </a>
      </div>
    </div>
  );
}
