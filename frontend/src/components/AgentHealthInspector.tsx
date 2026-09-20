import { useEffect, useState } from 'react';
import { Clock, Loader2, RotateCcw, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { QuarantineInfo } from '../lib/contract';
import { inspectAgent } from '../lib/genlayer';
import { describeError } from '../lib/errors';
import { formatIso, shortHex, tierLabel } from '../lib/format';

interface AgentHealthInspectorProps {
  quarantinedAgents: QuarantineInfo[];
  onSelectAgentForReport: (agentAddress: string) => void;
  onSelectAgentForAppeal: (agentAddress: string) => void;
  onRecoverAgent: (agentAddress: string) => Promise<void>;
  initialTarget?: string;
}

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

export function AgentHealthInspector({
  quarantinedAgents,
  onSelectAgentForReport,
  onSelectAgentForAppeal,
  onRecoverAgent,
  initialTarget,
}: AgentHealthInspectorProps) {
  const [searchAddress, setSearchAddress] = useState('');
  const [searchedAgent, setSearchedAgent] = useState<QuarantineInfo | null>(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovering, setRecovering] = useState(false);

  const runInspect = async (rawAddress: string) => {
    const address = rawAddress.trim();
    if (!ADDRESS_RE.test(address)) {
      setError('Enter a valid 40-character hexadecimal address (0x…).');
      setSearchedAgent(null);
      return;
    }
    setError(null);
    setSearching(true);
    try {
      // Live on-chain read: get_quarantine_info + is_quarantined + defended count + bond.
      const info = await inspectAgent(address);
      setSearchedAgent(info);
    } catch (err) {
      setError(describeError(err));
      setSearchedAgent(null);
    } finally {
      setSearching(false);
    }
  };

  // Auto-inspect when navigated here with a prefilled target (e.g. from the
  // antibody registry). Runs a live contract read for that address.
  useEffect(() => {
    if (initialTarget && ADDRESS_RE.test(initialTarget.trim())) {
      setSearchAddress(initialTarget);
      void runInspect(initialTarget);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialTarget]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    void runInspect(searchAddress);
  };

  const handleQuickInspect = (agent: QuarantineInfo) => {
    setSearchAddress(agent.target_agent);
    void runInspect(agent.target_agent);
  };

  const handleRecover = async (address: string) => {
    setRecovering(true);
    try {
      await onRecoverAgent(address);
      await runInspect(address);
    } catch {
      /* toast surfaced by the caller */
    } finally {
      setRecovering(false);
    }
  };

  const active = quarantinedAgents.filter((a) => a.is_active);
  const nowSec = Math.floor(Date.now() / 1000);
  const showRecover =
    searchedAgent !== null &&
    !searchedAgent.is_active &&
    searchedAgent.quarantine_until_utc > 0 &&
    searchedAgent.quarantine_until_utc < nowSec &&
    searchedAgent.total_quarantines > 0;

  return (
    <div className="stack" style={{ gap: 24 }}>
      <div>
        <h2 className="section-title">Immune inspector</h2>
        <p className="section-copy">
          Look up any agent address. Phage reads the live quarantine verdict, required reporter bond, and defended-appeal count straight from the contract.
        </p>
      </div>

      <form className="searchbar" onSubmit={handleSearch}>
        <Search size={16} color="#7d7464" aria-hidden="true" />
        <input
          className="input"
          value={searchAddress}
          onChange={(e) => setSearchAddress(e.target.value)}
          placeholder="Paste agent address (0x…)"
          aria-label="Agent address"
        />
        <button type="submit" className="btn btn-stain" style={{ minHeight: 40 }} disabled={searching}>
          {searching ? <Loader2 size={15} className="spin" /> : 'Inspect'}
        </button>
      </form>

      {error && (
        <div className="alert" role="alert">
          <span>{error}</span>
        </div>
      )}

      {searchedAgent && (
        <article className={`specimen ${searchedAgent.is_active ? 'is-iso' : 'is-ok'}`}>
          <div className="cluster" style={{ justifyContent: 'space-between', gap: 16 }}>
            <div className="cluster" style={{ gap: 14 }}>
              {searchedAgent.is_active ? (
                <ShieldAlert size={28} color="#c45c52" aria-hidden="true" />
              ) : (
                <ShieldCheck size={28} color="#5a9a96" aria-hidden="true" />
              )}
              <div>
                <div className="cluster" style={{ gap: 10 }}>
                  <span className="hash">{shortHex(searchedAgent.target_agent, 10, 8)}</span>
                  {searchedAgent.is_active ? (
                    <span className="chip chip-iso"><span className="pulse pulse-iso" /> Isolated</span>
                  ) : (
                    <span className="chip chip-ok"><span className="pulse" /> Healthy</span>
                  )}
                </div>
                <p className="help" style={{ marginTop: 6 }}>
                  {searchedAgent.is_active
                    ? 'Multi-LLM consensus verified a semantic threat. Integrated vaults must refuse this caller.'
                    : 'No active pathogen. This agent is cleared for autonomous execution.'}
                </p>
              </div>
            </div>
            <div className="cluster" style={{ gap: 8 }}>
              {showRecover && (
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => void handleRecover(searchedAgent.target_agent)}
                  disabled={recovering}
                >
                  {recovering ? <Loader2 size={14} className="spin" /> : <RotateCcw size={14} aria-hidden="true" />}
                  Recover
                </button>
              )}
              {searchedAgent.is_active ? (
                <button type="button" className="btn btn-ghost" onClick={() => onSelectAgentForAppeal(searchedAgent.target_agent)}>
                  File appeal
                </button>
              ) : (
                <button type="button" className="btn btn-hemolysis" onClick={() => onSelectAgentForReport(searchedAgent.target_agent)}>
                  Report pathogen
                </button>
              )}
            </div>
          </div>

          <dl className="kv">
            <div>
              <dt>Reason tier</dt>
              <dd>{tierLabel(searchedAgent.reason_tier)}</dd>
            </div>
            <div>
              <dt>Quarantine until</dt>
              <dd className="cluster" style={{ gap: 6 }}>
                <Clock size={13} aria-hidden="true" />
                {formatIso(searchedAgent.quarantine_until_iso)}
              </dd>
            </div>
            <div>
              <dt>Required bond</dt>
              <dd>{searchedAgent.current_required_bond_gen} GEN</dd>
            </div>
            <div>
              <dt>Defended appeals</dt>
              <dd>{searchedAgent.defended_appeals}</dd>
            </div>
          </dl>

          {searchedAgent.antibody_hash !== 'NONE' && searchedAgent.antibody_hash !== '' && (
            <div className="hashbox">
              <div>
                <div className="label">Linked antibody</div>
                <p className="hash" style={{ marginTop: 4 }}>{searchedAgent.antibody_hash}</p>
              </div>
            </div>
          )}
        </article>
      )}

      <section className="plate">
        <div className="plate-head">
          <h3 className="h3">Active quarantine registry</h3>
          <span className="chip chip-iso">{active.length} isolated</span>
        </div>
        <div className="ledger-wrap">
          {active.length === 0 ? (
            <p className="help" style={{ padding: '8px 2px' }}>
              No agents are currently quarantined on-chain.
            </p>
          ) : (
            <table className="ledger">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Tier</th>
                  <th>Report</th>
                  <th>Until</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {active.map((agent) => (
                  <tr key={agent.target_agent}>
                    <td className="hash">{shortHex(agent.target_agent, 10, 6)}</td>
                    <td>
                      <span className={`chip ${agent.reason_tier === 'TIER_PATHOGEN_CRITICAL' ? 'chip-iso' : 'chip-warn'}`}>
                        {tierLabel(agent.reason_tier)}
                      </span>
                    </td>
                    <td className="hash">{agent.last_report_id || '—'}</td>
                    <td>{formatIso(agent.quarantine_until_iso)}</td>
                    <td>
                      <button type="button" className="btn btn-ghost" style={{ minHeight: 36, fontSize: 12 }} onClick={() => handleQuickInspect(agent)}>
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}
