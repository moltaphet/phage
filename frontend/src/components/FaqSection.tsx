import { useState } from 'react';
import { ChevronDown, ExternalLink } from 'lucide-react';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_EXPLORER } from '../lib/contract';

interface FaqItem {
  id: string;
  question: string;
  answer: string;
  badge: string;
}

const ITEMS: FaqItem[] = [
  {
    id: 'faq-1',
    badge: 'Protocol',
    question: 'What does Phage protect?',
    answer:
      'Phage is an autonomous on-chain immune system for GenLayer. As agents execute DeFi, they face prompt injection, hijacked tools, and recursive drains. Phage verifies threat telemetry with multi-LLM consensus, quarantines the rogue agent, and mints antibodies that immunize every integrated protocol.',
  },
  {
    id: 'faq-2',
    badge: 'Quarantine',
    question: 'What happens when an agent is quarantined?',
    answer:
      'Consensus assigns a discrete tier — TIER_PATHOGEN_CRITICAL (7 days) or TIER_SUSPICIOUS_ANOMALY (24 hours). Any contract using the onlyHealthyAgent guard reverts calls from that address until isolation expires or an appeal is upheld.',
  },
  {
    id: 'faq-3',
    badge: 'Bonds',
    question: 'How does the escalating reporter bond stop griefing?',
    answer:
      'A report requires 0.10 GEN × (1 + defended_appeals). Innocent agents that win appeals become more expensive to accuse. A verified pathogen refunds the bond and pays a 0.15 GEN bounty. A fabricated report is slashed into reserves.',
  },
  {
    id: 'faq-4',
    badge: 'Antibodies',
    question: 'What is a cryptographic antibody?',
    answer:
      'An immutable SHA-256 digest of the neutralized vector — a prompt signature, function selector, or telemetry trace. Protocols call is_antibody_active(hash) to refuse known exploit patterns across the swarm.',
  },
  {
    id: 'faq-5',
    badge: 'Appeals',
    question: 'How do I contest a false positive?',
    answer:
      'Stake 0.20 GEN in the appeal chamber and provide a patch commit or clean trace. Validators re-evaluate. If upheld, quarantine lifts, the antibody is revoked, and the bond is refunded plus 0.05 GEN restitution.',
  },
  {
    id: 'faq-6',
    badge: 'Consensus',
    question: 'How is this different from a price oracle?',
    answer:
      'Oracles deliver numbers. GenLayer validators run independent frontier models over unstructured logs and converge via the equivalence principle on a categorical verdict — not a float that can diverge.',
  },
  {
    id: 'faq-7',
    badge: 'Integrate',
    question: 'How do I add Phage to a vault or agent?',
    answer:
      'In Solidity, import IPhageSentinel and apply onlyHealthyAgent to execution functions. In Python or TypeScript, call is_agent_quarantined(target) before dispatching funds. The SDK modal has drop-in snippets.',
  },
  {
    id: 'faq-8',
    badge: 'Studio-dev',
    question: 'Where is it deployed?',
    answer: `Phage Sentinel is deployed on GenLayer Studio-dev (chain 61997) at ${PHAGE_CONTRACT_ADDRESS}, RPC https://studio-dev.genlayer.com/api. Inspect live state on the Studio-dev explorer.`,
  },
];

export function FaqSection() {
  const [openIds, setOpenIds] = useState<string[]>(['faq-1']);

  const toggle = (id: string) => {
    setOpenIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div>
        <h2 className="section-title">Questions</h2>
        <p className="section-copy">Quarantine, bonds, antibodies, appeals, and Studio-dev deployment.</p>
      </div>

      {ITEMS.map((item) => {
        const open = openIds.includes(item.id);
        return (
          <div key={item.id} className="faq-item">
            <button
              type="button"
              className="faq-q"
              onClick={() => toggle(item.id)}
              aria-expanded={open}
            >
              <span className="cluster" style={{ gap: 10 }}>
                <span className="chip">{item.badge}</span>
                <span>{item.question}</span>
              </span>
              <ChevronDown
                size={18}
                aria-hidden="true"
                style={{ transform: open ? 'rotate(180deg)' : undefined, color: 'var(--filament-mute)' }}
              />
            </button>
            {open && <div className="faq-a">{item.answer}</div>}
          </div>
        );
      })}

      <div className="contract-bar">
        <span className="help">Inspect the open-source contract on Studio-dev.</span>
        <a
          className="btn btn-ghost"
          href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          Contract
          <ExternalLink size={13} aria-hidden="true" />
        </a>
      </div>
    </div>
  );
}
