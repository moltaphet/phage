import { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, Clock } from 'lucide-react';
import type { QuarantineInfo } from '../lib/contract';
import { formatIso, shortHex, tierLabel } from '../lib/format';

interface AgentHealthInspectorProps {
  quarantinedAgents: QuarantineInfo[];
  onSelectAgentForReport: (agentAddress: string) => void;
  onSelectAgentForAppeal: (agentAddress: string) => void;
}

export function AgentHealthInspector({
  quarantinedAgents,
  onSelectAgentForReport,
  onSelectAgentForAppeal,
}: AgentHealthInspectorProps) {
  const [searchAddress, setSearchAddress] = useState('');
  const [searchedAgent, setSearchedAgent] = useState<QuarantineInfo | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const query = searchAddress.trim().toLowerCase();
    if (!query) return;

    const match = quarantinedAgents.find((q) => q.target_agent.toLowerCase() === query);
    if (match) {
      setSearchedAgent(match);
    } else {
      setSearchedAgent({
        target_agent: searchAddress.trim(),
        is_active: false,
        quarantine_until_utc: 0,
        quarantine_until_iso: 'N/A',
        reason_tier: 'TIER_BENIGN_NOMINAL',
        last_report_id: 'NONE',
        total_quarantines: 0,
        antibody_hash: 'NONE',
        defended_appeals: 0,
        current_required_bond_gen: '0.10',
      });
    }
    setHasSearched(true);
  };

  const handleQuickInspect = (agent: QuarantineInfo) => {
    setSearchAddress(agent.target_agent);
    setSearchedAgent(agent);
    setHasSearched(true);
  };

  const active = quarantinedAgents.filter((a) => a.is_active);

  return (
    <div className="stack" style={{ gap: 24 }}>
      <div>
        <h2 className="section-title">Immune inspector</h2>
        <p className="section-copy">
          Look up any agent address. Phage returns the live quarantine verdict, required reporter bond, and linked antibody if one exists.
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
        <button type="submit" className="btn btn-stain" style={{ minHeight: 40 }}>
          Inspect
        </button>
      </form>

      {hasSearched && searchedAgent && (
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

          {searchedAgent.antibody_hash !== 'NONE' && (
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
                  <td className="hash">{agent.last_report_id}</td>
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
        </div>
      </section>
    </div>
  );
}
