import { useEffect, useState } from 'react';
import { Activity, BookOpen, Dna, HelpCircle, Scale, Search, ShieldAlert, Terminal } from 'lucide-react';
import type { Antibody, ProtocolStats, QuarantineInfo } from './lib/contract';
import { INITIAL_ANTIBODIES, INITIAL_QUARANTINED_AGENTS, INITIAL_STATS, STUDIONET_CHAIN_ID } from './lib/contract';
import { useWallet } from './lib/useWallet';
import { shortHex } from './lib/format';
import { Navbar } from './components/Navbar';
import { ImmuneStatsBanner } from './components/ImmuneStatsBanner';
import { ThreeImmuneCanvas } from './components/ThreeImmuneCanvas';
import { AgentHealthInspector } from './components/AgentHealthInspector';
import { PathogenReportingPortal } from './components/PathogenReportingPortal';
import { AntibodyRegistryGrid } from './components/AntibodyRegistryGrid';
import { AppealChamber } from './components/AppealChamber';
import { AboutSection } from './components/AboutSection';
import { FaqSection } from './components/FaqSection';
import { ModernFooter } from './components/ModernFooter';
import { ConsensusTriageModal } from './components/ConsensusTriageModal';
import { DeveloperIntegrationModal } from './components/DeveloperIntegrationModal';

const TABS = [
  { id: 'sentinel', label: 'Sentinel', icon: Activity },
  { id: 'inspector', label: 'Inspector', icon: Search },
  { id: 'report', label: 'Report', icon: ShieldAlert },
  { id: 'antibodies', label: 'Antibodies', icon: Dna },
  { id: 'appeal', label: 'Appeals', icon: Scale },
  { id: 'about', label: 'About', icon: BookOpen },
  { id: 'faq', label: 'FAQ', icon: HelpCircle },
];

export function App() {
  const [activeTab, setActiveTab] = useState('sentinel');
  const [isDevModalOpen, setIsDevModalOpen] = useState(false);
  const [isConsensusModalOpen, setIsConsensusModalOpen] = useState(false);
  const [stats, setStats] = useState<ProtocolStats>(INITIAL_STATS);
  const [quarantinedAgents, setQuarantinedAgents] = useState<QuarantineInfo[]>(INITIAL_QUARANTINED_AGENTS);
  const [antibodies, setAntibodies] = useState<Antibody[]>(INITIAL_ANTIBODIES);
  const wallet = useWallet();
  const [pendingReportData, setPendingReportData] = useState<{
    targetAgent: string;
    platform: string;
    traceId: string;
    category: string;
    description: string;
    bondGen: string;
  } | null>(null);
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'info' } | null>(null);

  const showToast = (text: string, type: 'success' | 'info' = 'success') => {
    setToastMessage({ text, type });
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Surface wallet errors (rejections, pending requests, network issues) as toasts.
  useEffect(() => {
    if (wallet.error) showToast(wallet.error, 'info');
  }, [wallet.error]);

  const handleConnectWallet = async () => {
    const address = await wallet.connect();
    if (address) {
      showToast(`Connected ${shortHex(address, 6, 4)} on GenLayer Studio-dev (chain ${STUDIONET_CHAIN_ID})`);
    }
  };

  const handleDisconnectWallet = () => {
    wallet.disconnect();
    showToast('Wallet disconnected', 'info');
  };

  const handleFundPool = () => {
    showToast('Simulated deposit: +1.00 GEN to the bounty pool');
    setStats((prev) => ({
      ...prev,
      bounty_pool_gen: (parseFloat(prev.bounty_pool_gen) + 1).toFixed(2),
      total_deposited_gen: (parseFloat(prev.total_deposited_gen) + 1).toFixed(2),
    }));
  };

  const handleSelectTab = (tab: string) => {
    setActiveTab(tab);
    window.scrollTo({ top: 0 });
  };

  const handleCompleteConsensus = (result: {
    targetAgent: string;
    quarantineSeconds: number;
    reasonTier: string;
    antibodyHash: string;
    bountyPayoutGen: string;
    traceId: string;
    platform: string;
  }) => {
    const newQuarantine: QuarantineInfo = {
      target_agent: result.targetAgent,
      is_active: true,
      quarantine_until_utc: Math.floor(Date.now() / 1000) + result.quarantineSeconds,
      quarantine_until_iso: new Date(Date.now() + result.quarantineSeconds * 1000).toISOString(),
      reason_tier: result.reasonTier,
      last_report_id: `REP-${Math.floor(Math.random() * 9000 + 1000)}`,
      total_quarantines: 1,
      antibody_hash: result.antibodyHash,
      defended_appeals: 0,
      current_required_bond_gen: '0.10',
    };

    setQuarantinedAgents((prev) => {
      const filtered = prev.filter((q) => q.target_agent.toLowerCase() !== result.targetAgent.toLowerCase());
      return [newQuarantine, ...filtered];
    });

    const newAntibody: Antibody = {
      antibody_hash: result.antibodyHash,
      target_agent: result.targetAgent,
      platform: result.platform,
      trace_id: result.traceId,
      pathogen_digest: `sha256:${result.antibodyHash.substring(2, 8)}…`,
      mint_timestamp_utc: Math.floor(Date.now() / 1000),
      mint_timestamp_iso: new Date().toISOString(),
      is_active: true,
    };

    setAntibodies((prev) => [newAntibody, ...prev]);
    setStats((prev) => ({
      ...prev,
      total_quarantines_active: prev.total_quarantines_active + 1,
      total_antibodies_minted: prev.total_antibodies_minted + 1,
      total_reports_evaluated: prev.total_reports_evaluated + 1,
      total_claimed_gen: (parseFloat(prev.total_claimed_gen) + parseFloat(result.bountyPayoutGen)).toFixed(2),
    }));
    showToast(`Pathogen quarantined. Antibody ${result.antibodyHash.substring(0, 10)}… minted.`);
  };

  const handleSubmitAppeal = (data: {
    targetAgent: string;
    proofTraceId: string;
    platform: string;
    reason: string;
    appealBondGen: string;
  }) => {
    showToast(`Appeal submitted for ${data.targetAgent.substring(0, 10)}…`);
    setQuarantinedAgents((prev) =>
      prev.map((q) =>
        q.target_agent.toLowerCase() === data.targetAgent.toLowerCase()
          ? {
              ...q,
              is_active: false,
              defended_appeals: q.defended_appeals + 1,
              current_required_bond_gen: (0.1 * (1 + q.defended_appeals + 1)).toFixed(2),
            }
          : q
      )
    );
    setAntibodies((prev) =>
      prev.map((ab) =>
        ab.target_agent.toLowerCase() === data.targetAgent.toLowerCase() ? { ...ab, is_active: false } : ab
      )
    );
    setStats((prev) => ({
      ...prev,
      total_appeals_processed: prev.total_appeals_processed + 1,
      total_quarantines_active: Math.max(0, prev.total_quarantines_active - 1),
    }));
  };

  const activeAntibodies = antibodies.filter((a) => a.is_active).length;

  return (
    <div className="shell">
      <a className="skip" href="#workbench">Skip to workbench</a>

      {toastMessage && (
        <div className="toast" role="status">
          <span className={`pulse ${toastMessage.type === 'info' ? '' : ''}`} />
          <span>{toastMessage.text}</span>
        </div>
      )}

      <Navbar
        activeTab={activeTab}
        setActiveTab={handleSelectTab}
        walletAddress={wallet.address}
        isConnected={wallet.isConnected}
        isConnecting={wallet.isConnecting}
        isCorrectNetwork={wallet.isCorrectNetwork}
        balanceGen={wallet.balanceGen}
        hasProvider={wallet.hasProvider}
        onConnectWallet={handleConnectWallet}
        onDisconnectWallet={handleDisconnectWallet}
        onSwitchNetwork={() => void wallet.switchNetwork()}
        onOpenDevModal={() => setIsDevModalOpen(true)}
      />

      <main>
        {activeTab === 'sentinel' && (
          <section className="hero">
            <div className="wrap split split-hero">
              <div>
                <p className="kicker">
                  <span className="pulse" />
                  Live on GenLayer Studio-dev
                </p>
                <h1 className="display">Hunt. Isolate. Inoculate.</h1>
                <p className="lede">
                  Phage is the on-chain immune system for autonomous agents. Multi-LLM validators classify forensic logs, quarantine compromised callers, and mint antibodies before a treasury can drain.
                </p>
                <div className="hero-actions">
                  <button type="button" className="btn btn-stain" onClick={() => handleSelectTab('inspector')}>
                    <Search size={16} aria-hidden="true" />
                    Inspect an agent
                  </button>
                  <button type="button" className="btn btn-hemolysis" onClick={() => handleSelectTab('report')}>
                    <ShieldAlert size={16} aria-hidden="true" />
                    Report a pathogen
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={() => setIsDevModalOpen(true)}>
                    <Terminal size={16} aria-hidden="true" />
                    SDK
                  </button>
                </div>
                <div className="hero-meta">
                  <div>
                    <div className="meta-label">Consensus</div>
                    <div className="meta-value">Optimistic swarm</div>
                  </div>
                  <div>
                    <div className="meta-label">Execution guard</div>
                    <div className="meta-value mono">onlyHealthyAgent</div>
                  </div>
                  <div>
                    <div className="meta-label">Network</div>
                    <div className="meta-value">Studio-dev 61997</div>
                  </div>
                </div>
              </div>
              <ThreeImmuneCanvas quarantinedCount={quarantinedAgents.filter((q) => q.is_active).length} />
            </div>
          </section>
        )}

        <div className="wrap" style={{ paddingBottom: activeTab === 'sentinel' ? 0 : 24, paddingTop: activeTab === 'sentinel' ? 0 : 28 }}>
          <ImmuneStatsBanner stats={stats} onFundPoolClick={handleFundPool} />
        </div>

        <div className="bench" id="workbench">
          <div className="wrap">
            <div className="tabs" role="tablist" aria-label="Protocol workbench">
              {TABS.map((tab) => {
                const Icon = tab.icon;
                const label = tab.id === 'antibodies' ? `Antibodies (${activeAntibodies})` : tab.label;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={activeTab === tab.id}
                    className={`tab${activeTab === tab.id ? ' is-active' : ''}`}
                    onClick={() => handleSelectTab(tab.id)}
                  >
                    <Icon size={14} aria-hidden="true" />
                    {label}
                  </button>
                );
              })}
              <button type="button" className="tab" onClick={() => setIsDevModalOpen(true)} style={{ marginLeft: 'auto' }}>
                <Terminal size={14} aria-hidden="true" />
                SDK
              </button>
            </div>

            {activeTab === 'sentinel' && (
              <div className="stack" style={{ gap: 56 }}>
                <AgentHealthInspector
                  quarantinedAgents={quarantinedAgents}
                  onSelectAgentForReport={() => handleSelectTab('report')}
                  onSelectAgentForAppeal={() => handleSelectTab('appeal')}
                />
                <AboutSection />
                <FaqSection />
              </div>
            )}

            {activeTab === 'inspector' && (
              <AgentHealthInspector
                quarantinedAgents={quarantinedAgents}
                onSelectAgentForReport={() => handleSelectTab('report')}
                onSelectAgentForAppeal={() => handleSelectTab('appeal')}
              />
            )}

            {activeTab === 'report' && (
              <PathogenReportingPortal
                quarantinedAgents={quarantinedAgents}
                onSubmitReport={(data) => {
                  setPendingReportData(data);
                  setIsConsensusModalOpen(true);
                }}
                walletConnected={wallet.isConnected}
                userAddress={wallet.address}
                onConnectWallet={handleConnectWallet}
              />
            )}

            {activeTab === 'antibodies' && (
              <AntibodyRegistryGrid antibodies={antibodies} onInspectAgent={() => handleSelectTab('inspector')} />
            )}

            {activeTab === 'appeal' && (
              <AppealChamber
                quarantinedAgents={quarantinedAgents}
                onSubmitAppeal={handleSubmitAppeal}
                walletConnected={wallet.isConnected}
                onConnectWallet={handleConnectWallet}
              />
            )}

            {activeTab === 'about' && <AboutSection />}
            {activeTab === 'faq' && <FaqSection />}
          </div>
        </div>
      </main>

      <ConsensusTriageModal
        isOpen={isConsensusModalOpen}
        onClose={() => setIsConsensusModalOpen(false)}
        reportData={pendingReportData}
        onCompleteConsensus={handleCompleteConsensus}
      />

      <DeveloperIntegrationModal isOpen={isDevModalOpen} onClose={() => setIsDevModalOpen(false)} />

      <ModernFooter onSelectTab={handleSelectTab} onOpenDevModal={() => setIsDevModalOpen(true)} />
    </div>
  );
}

export default App;
