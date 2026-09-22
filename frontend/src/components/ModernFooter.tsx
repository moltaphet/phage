import { useState } from 'react';
import { Check, Copy, ExternalLink } from 'lucide-react';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_CHAIN_ID, STUDIONET_EXPLORER, STUDIO_WEB } from '../lib/contract';
import { PhageMark } from './PhageMark';

interface ModernFooterProps {
  onSelectTab: (tab: string) => void;
  onOpenDevModal: () => void;
}

export function ModernFooter({ onSelectTab, onOpenDevModal }: ModernFooterProps) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(PHAGE_CONTRACT_ADDRESS);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const go = (tab: string) => {
    onSelectTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer className="foot">
      <div className="wrap">
        <div className="foot-grid">
          <div>
            <div className="cluster" style={{ gap: 10, marginBottom: 14 }}>
              <PhageMark size={32} />
              <div>
                <div className="brand-name">PHAGE SENTINEL</div>
                <div className="brand-sub">{'GenVM v0.3.0'}</div>
              </div>
            </div>
            <p className="help" style={{ maxWidth: '36ch', lineHeight: 1.65 }}>
              Autonomous threat quarantine and antibody synthesis for the agentic economy, powered by GenLayer multi-LLM consensus.
            </p>
            <div className="chip chip-live" style={{ marginTop: 16 }}>
              <span className="pulse" />
              Studio-dev live · {STUDIONET_CHAIN_ID}
            </div>
          </div>

          <div>
            <div className="foot-title">Protocol</div>
            <ul className="foot-list">
              <li><button type="button" className="linkish" onClick={() => go('sentinel')}>Sentinel</button></li>
              <li><button type="button" className="linkish" onClick={() => go('inspector')}>Inspector</button></li>
              <li><button type="button" className="linkish" onClick={() => go('report')}>Report pathogen</button></li>
              <li><button type="button" className="linkish" onClick={() => go('antibodies')}>Antibody registry</button></li>
              <li><button type="button" className="linkish" onClick={() => go('appeal')}>Appeal chamber</button></li>
            </ul>
          </div>

          <div>
            <div className="foot-title">Knowledge</div>
            <ul className="foot-list">
              <li><button type="button" className="linkish" onClick={() => go('about')}>About</button></li>
              <li><button type="button" className="linkish" onClick={() => go('faq')}>FAQ</button></li>
              <li><button type="button" className="linkish" onClick={onOpenDevModal}>Integration SDK</button></li>
              <li>
                <a href="https://github.com/moltaphet/phage" target="_blank" rel="noopener noreferrer">
                  GitHub
                </a>
              </li>
            </ul>
          </div>

          <div>
            <div className="foot-title">Network</div>
            <ul className="foot-list">
              <li>
                <a href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`} target="_blank" rel="noopener noreferrer">
                  Studio-dev explorer <ExternalLink size={11} aria-hidden="true" />
                </a>
              </li>
              <li>
                <a href={STUDIO_WEB} target="_blank" rel="noopener noreferrer">
                  GenLayer Studio
                </a>
              </li>
              <li>
                <a href="https://docs.genlayer.com" target="_blank" rel="noopener noreferrer">
                  Documentation
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="contract-bar">
          <div>
            <span style={{ fontWeight: 650, marginRight: 8 }}>Contract</span>
            <span className="hash">{PHAGE_CONTRACT_ADDRESS}</span>
          </div>
          <div className="cluster" style={{ gap: 8 }}>
            <button type="button" className="btn btn-ghost" style={{ minHeight: 36, fontSize: 12 }} onClick={copy}>
              {copied ? <Check size={13} /> : <Copy size={13} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <a
              className="btn btn-ghost"
              style={{ minHeight: 36, fontSize: 12 }}
              href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Explorer
            </a>
          </div>
        </div>

        <div className="legal">
          <span>© 2026 Phage Sentinel. MIT. Built on GenLayer.</span>
          <span>Optimistic democracy · Equivalence principle</span>
        </div>
      </div>
    </footer>
  );
}
