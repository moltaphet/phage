import { ExternalLink, Wallet } from 'lucide-react';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_CHAIN_ID, STUDIONET_EXPLORER } from '../lib/contract';
import { shortHex } from '../lib/format';
import { PhageMark } from './PhageMark';

interface NavbarProps {
  walletAddress: string | null;
  isConnected: boolean;
  isConnecting: boolean;
  isCorrectNetwork: boolean;
  balanceGen: string | null;
  hasProvider: boolean;
  onConnectWallet: () => void;
  onDisconnectWallet: () => void;
  onSwitchNetwork: () => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenDevModal?: () => void;
}

const NAV = [
  { id: 'sentinel', label: 'Sentinel' },
  { id: 'inspector', label: 'Inspector' },
  { id: 'report', label: 'Report' },
  { id: 'antibodies', label: 'Antibodies' },
  { id: 'appeal', label: 'Appeals' },
  { id: 'about', label: 'About' },
  { id: 'faq', label: 'FAQ' },
];

export function Navbar({
  walletAddress,
  isConnected,
  isConnecting,
  isCorrectNetwork,
  balanceGen,
  hasProvider,
  onConnectWallet,
  onDisconnectWallet,
  onSwitchNetwork,
  activeTab,
  setActiveTab,
}: NavbarProps) {
  return (
    <header className="mast">
      <div className="wrap mast-inner">
        <div className="brand" onClick={() => setActiveTab('sentinel')} role="button" tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setActiveTab('sentinel'); }}>
          <PhageMark size={34} />
          <div className="brand-copy">
            <span className="brand-name">PHAGE</span>
            <span className="brand-sub">Sentinel · Studio-dev</span>
          </div>
        </div>

        <nav className="mast-nav" aria-label="Primary">
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`nav-item${activeTab === item.id ? ' is-active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              aria-current={activeTab === item.id ? 'page' : undefined}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="mast-actions">
          <a
            className="chip chip-live chip-net"
            href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            <span className="pulse" />
            Chain {STUDIONET_CHAIN_ID}
            <ExternalLink size={11} aria-hidden="true" />
          </a>
          {isConnected && walletAddress ? (
            <>
              {!isCorrectNetwork && (
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={onSwitchNetwork}
                  title="Switch your wallet to GenLayer Studio-dev"
                >
                  Wrong network
                </button>
              )}
              <span className="chip chip-ok" title={walletAddress}>
                <Wallet size={14} aria-hidden="true" />
                {shortHex(walletAddress, 6, 4)}
                {balanceGen ? ` · ${balanceGen} GEN` : ''}
              </span>
              <button type="button" className="btn btn-ghost" onClick={onDisconnectWallet}>
                Disconnect
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-stain"
              onClick={onConnectWallet}
              disabled={isConnecting}
            >
              <Wallet size={15} aria-hidden="true" />
              {isConnecting ? 'Connecting…' : hasProvider ? 'Connect' : 'Install Wallet'}
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
