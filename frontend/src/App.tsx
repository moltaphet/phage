import { useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, BookOpen, Dna, HelpCircle, RefreshCw, Scale, Search, ShieldAlert, Terminal } from 'lucide-react';
import type { Antibody, AppealRecord, ProtocolStats, QuarantineInfo } from './lib/contract';
import { STUDIONET_CHAIN_ID } from './lib/contract';
import { attoToGen, genToAtto, shortHex } from './lib/format';
import { describeError } from './lib/errors';
import { useWallet } from './lib/useWallet';
import {
  appealQuarantine,
  deriveAppealId,
  fundBountyPool,
  getAppeal,
  getRequiredReporterBondAtto,
  getTotalAppeals,
  getWriteClient,
  loadProtocolState,
  recoverAgent,
  waitForReceipt,
  withdraw,
} from './lib/genlayer';
import type { GenClient } from './lib/genlayer';
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
import { ClaimVault } from './components/ClaimVault';
import { FundPoolModal } from './components/FundPoolModal';
import { ConsensusTriageModal } from './components/ConsensusTriageModal';
import type { TriageReportData } from './components/ConsensusTriageModal';
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

const EMPTY_STATS: ProtocolStats = {
  owner: '',
  bounty_pool_gen: '0.0000',
  protocol_reserves_gen: '0.0000',
  total_deposited_gen: '0.0000',
  total_claimed_gen: '0.0000',
  total_quarantines_active: 0,
  total_antibodies_minted: 0,
  total_reports_evaluated: 0,
  total_appeals_processed: 0,
  system_health_pct: 100,
};

const APPEAL_BOND_GEN = '0.20'; // APPEAL_BOND = 0.2 GEN, enforced on-chain.

type Toast = { text: string; type: 'success' | 'info' | 'error'; href?: string };

export function App() {
  const [activeTab, setActiveTab] = useState('sentinel');
  const [isDevModalOpen, setIsDevModalOpen] = useState(false);
  const [isConsensusModalOpen, setIsConsensusModalOpen] = useState(false);
  const [isFundModalOpen, setIsFundModalOpen] = useState(false);

  const [stats, setStats] = useState<ProtocolStats>(EMPTY_STATS);
  const [quarantinedAgents, setQuarantinedAgents] = useState<QuarantineInfo[]>([]);
  const [antibodies, setAntibodies] = useState<Antibody[]>([]);
  const [appeals, setAppeals] = useState<AppealRecord[]>([]);
  const [loadStatus, setLoadStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [loadError, setLoadError] = useState<string | null>(null);
  const [vaultRefreshKey, setVaultRefreshKey] = useState(0);

  const wallet = useWallet();
  const [pendingReportData, setPendingReportData] = useState<TriageReportData | null>(null);
  const [reportClient, setReportClient] = useState<GenClient | null>(null);
  const [prefillTarget, setPrefillTarget] = useState('');
  const [toastMessage, setToastMessage] = useState<Toast | null>(null);

  const showToast = useCallback((text: string, type: Toast['type'] = 'success', href?: string) => {
    setToastMessage({ text, type, href });
    setTimeout(() => setToastMessage(null), href ? 9000 : 5000);
  }, []);

  // Hydrate the entire dashboard from live contract reads. No seeded/mock state.
  const refreshAll = useCallback(async () => {
    try {
      const state = await loadProtocolState();
      setStats(state.stats);
      setQuarantinedAgents(state.quarantinedAgents);
      setAntibodies(state.antibodies);
      setLoadStatus('ready');
      setLoadError(null);
    } catch (err) {
      setLoadStatus('error');
      setLoadError(describeError(err));
    }
  }, []);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  // Surface wallet errors (rejections, pending requests, network issues) as toasts.
  useEffect(() => {
    if (wallet.error) showToast(wallet.error, 'info');
  }, [wallet.error, showToast]);

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

  // Resolve a signing client, guarding on connection + network. Returns null and
  // toasts if the wallet is not ready — we never proceed without a real signer.
  const getSigner = useCallback((): GenClient | null => {
    if (!wallet.isConnected || !wallet.address) {
      showToast('Connect your wallet to sign this transaction.', 'info');
      return null;
    }
    if (!wallet.isCorrectNetwork) {
      showToast('Switch to GenLayer Studio-dev (chain 61997) to continue.', 'info');
      void wallet.switchNetwork();
      return null;
    }
    const provider = wallet.getProvider();
    if (!provider) {
      showToast('No wallet provider available.', 'info');
      return null;
    }
    return getWriteClient(wallet.address, provider);
  }, [wallet, showToast]);

  const handleSelectTab = (tab: string) => {
    setActiveTab(tab);
    window.scrollTo({ top: 0 });
  };

  const handleFundPool = useCallback(
    async (amountGen: string) => {
      const client = getSigner();
      if (!client) throw new Error('Wallet not connected.');
      const valueAtto = genToAtto(amountGen);
      if (valueAtto <= 0n) throw new Error('Enter an amount greater than zero.');

      showToast('Confirm the deposit in your wallet…', 'info');
      const hash = await fundBountyPool(client, valueAtto);
      showToast('Deposit submitted — awaiting confirmation.', 'info', hash);
      await waitForReceipt(client, hash);
      showToast(`Deposited ${amountGen} GEN into the bounty pool.`, 'success', hash);
      setVaultRefreshKey((k) => k + 1);
      wallet.refreshBalance();
      await refreshAll();
    },
    [getSigner, showToast, refreshAll, wallet],
  );

  // Report flow: read the authoritative required bond, then hand the review to the
  // triage modal which signs report_pathogen + evaluate_pathogen for real.
  const handleReportSubmit = async (data: {
    targetAgent: string;
    platform: string;
    traceId: string;
    category: string;
    description: string;
  }) => {
    const client = getSigner();
    if (!client) return;

    let bondAtto: bigint;
    try {
      bondAtto = await getRequiredReporterBondAtto(data.targetAgent);
      if (bondAtto <= 0n) bondAtto = genToAtto('0.10');
    } catch {
      // The contract still enforces the true bond; fall back to the 0.1 GEN base.
      bondAtto = genToAtto('0.10');
    }

    const reportId = `report-${data.targetAgent.slice(2, 10).toLowerCase()}-${Date.now()}`;
    setReportClient(client);
    setPendingReportData({
      reportId,
      targetAgent: data.targetAgent,
      platform: data.platform,
      traceId: data.traceId,
      bondAtto,
      bondGen: attoToGen(bondAtto.toString()),
      category: data.category,
      description: data.description,
    });
    setIsConsensusModalOpen(true);
  };

  const handleSubmitAppeal = async (data: {
    targetAgent: string;
    proofTraceId: string;
    platform: string;
    reason: string;
  }) => {
    const client = getSigner();
    if (!client) throw new Error('Wallet not connected.');

    const bondAtto = genToAtto(APPEAL_BOND_GEN);
    let totalBefore = 0;
    try {
      totalBefore = await getTotalAppeals();
    } catch {
      /* non-fatal: we still submit; id derivation may be skipped below */
    }

    showToast('Confirm the appeal bond in your wallet…', 'info');
    const hash = await appealQuarantine(client, {
      targetAgent: data.targetAgent,
      proofTraceId: data.proofTraceId,
      platform: data.platform,
      bondAtto,
    });
    showToast('Appeal submitted — running consensus on-chain…', 'info', hash);
    await waitForReceipt(client, hash);

    // Read the real appeal verdict the contract just recorded.
    try {
      const appealId = deriveAppealId(data.targetAgent, totalBefore + 1);
      const record = await getAppeal(appealId);
      setAppeals((prev) => [record, ...prev.filter((a) => a.appeal_id !== record.appeal_id)]);
      showToast(
        record.state === 'UPHELD' ? 'Appeal upheld — quarantine lifted.' : `Appeal ${record.state.toLowerCase()}.`,
        record.state === 'UPHELD' ? 'success' : 'info',
        hash,
      );
    } catch {
      showToast('Appeal recorded on-chain.', 'success', hash);
    }

    setVaultRefreshKey((k) => k + 1);
    wallet.refreshBalance();
    await refreshAll();
  };

  const handleWithdraw = useCallback(async () => {
    const client = getSigner();
    if (!client) throw new Error('Wallet not connected.');
    showToast('Confirm the withdrawal in your wallet…', 'info');
    const hash = await withdraw(client);
    showToast('Withdrawal submitted — settling on finalization.', 'info', hash);
    await waitForReceipt(client, hash);
    showToast('Withdrawal settled.', 'success', hash);
    setVaultRefreshKey((k) => k + 1);
    wallet.refreshBalance();
    await refreshAll();
  }, [getSigner, showToast, refreshAll, wallet]);

  const handleRecoverAgent = useCallback(
    async (address: string) => {
      const client = getSigner();
      if (!client) throw new Error('Wallet not connected.');
      showToast('Confirm recovery in your wallet…', 'info');
      const hash = await recoverAgent(client, address);
      showToast('Recovery submitted.', 'info', hash);
      await waitForReceipt(client, hash);
      showToast('Agent recovered from expired quarantine.', 'success', hash);
      await refreshAll();
    },
    [getSigner, showToast, refreshAll],
  );

  const selectForReport = (address: string) => {
    setPrefillTarget(address);
    handleSelectTab('report');
  };
  const selectForAppeal = (address: string) => {
    setPrefillTarget(address);
    handleSelectTab('appeal');
  };
  const selectForInspect = (address: string) => {
    setPrefillTarget(address);
    handleSelectTab('inspector');
  };

  const activeAntibodies = antibodies.filter((a) => a.is_active).length;

  return (
    <div className="shell">
      <a className="skip" href="#workbench">Skip to workbench</a>

      {toastMessage && (
        <div className="toast" role="status">
          <span className="pulse" />
          <span>{toastMessage.text}</span>
          {toastMessage.href && (
            <a
              href={`https://explorer-studio-dev.genlayer.com/tx/${toastMessage.href}`}
              target="_blank"
              rel="noopener noreferrer"
              className="mono"
              style={{ fontSize: 12, color: 'inherit' }}
            >
              {shortHex(toastMessage.href, 6, 4)} ↗
            </a>
          )}
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
          {loadStatus === 'error' && (
            <div className="alert" role="alert" style={{ marginBottom: 16 }}>
              <AlertTriangle size={16} aria-hidden="true" />
              <span>
                Live contract read failed: {loadError}. Showing no fabricated data.{' '}
                <button type="button" className="btn btn-ghost" style={{ minHeight: 30, fontSize: 12 }} onClick={() => void refreshAll()}>
                  <RefreshCw size={13} /> Retry
                </button>
              </span>
            </div>
          )}
          <ImmuneStatsBanner
            stats={stats}
            loading={loadStatus === 'loading'}
            onFundPoolClick={() => setIsFundModalOpen(true)}
            onRefresh={() => void refreshAll()}
          />
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
                <ClaimVault
                  address={wallet.address}
                  walletConnected={wallet.isConnected}
                  refreshKey={vaultRefreshKey}
                  onWithdraw={handleWithdraw}
                />
                <AgentHealthInspector
                  quarantinedAgents={quarantinedAgents}
                  onSelectAgentForReport={selectForReport}
                  onSelectAgentForAppeal={selectForAppeal}
                  onRecoverAgent={handleRecoverAgent}
                />
                <AboutSection />
                <FaqSection />
              </div>
            )}

            {activeTab === 'inspector' && (
              <div className="stack" style={{ gap: 32 }}>
                <ClaimVault
                  address={wallet.address}
                  walletConnected={wallet.isConnected}
                  refreshKey={vaultRefreshKey}
                  onWithdraw={handleWithdraw}
                />
                <AgentHealthInspector
                  quarantinedAgents={quarantinedAgents}
                  onSelectAgentForReport={selectForReport}
                  onSelectAgentForAppeal={selectForAppeal}
                  onRecoverAgent={handleRecoverAgent}
                  initialTarget={prefillTarget}
                />
              </div>
            )}

            {activeTab === 'report' && (
              <PathogenReportingPortal
                initialTarget={prefillTarget}
                onSubmitReport={handleReportSubmit}
                walletConnected={wallet.isConnected}
                onConnectWallet={handleConnectWallet}
              />
            )}

            {activeTab === 'antibodies' && (
              <AntibodyRegistryGrid antibodies={antibodies} onInspectAgent={selectForInspect} loading={loadStatus === 'loading'} />
            )}

            {activeTab === 'appeal' && (
              <AppealChamber
                quarantinedAgents={quarantinedAgents}
                recentAppeals={appeals}
                initialTarget={prefillTarget}
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
        client={reportClient}
        onResolved={refreshAll}
      />

      <FundPoolModal
        isOpen={isFundModalOpen}
        onClose={() => setIsFundModalOpen(false)}
        onFund={handleFundPool}
        walletConnected={wallet.isConnected}
        onConnectWallet={handleConnectWallet}
      />

      <DeveloperIntegrationModal isOpen={isDevModalOpen} onClose={() => setIsDevModalOpen(false)} />

      <ModernFooter onSelectTab={handleSelectTab} onOpenDevModal={() => setIsDevModalOpen(true)} />
    </div>
  );
}

export default App;
