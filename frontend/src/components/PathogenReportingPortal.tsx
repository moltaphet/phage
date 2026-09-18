import { useState } from 'react';
import { Info, Lock, Send } from 'lucide-react';
import type { QuarantineInfo } from '../lib/contract';

interface PathogenReportingPortalProps {
  quarantinedAgents: QuarantineInfo[];
  onSubmitReport: (reportData: {
    targetAgent: string;
    platform: string;
    traceId: string;
    category: string;
    description: string;
    bondGen: string;
  }) => void;
  walletConnected: boolean;
  userAddress: string | null;
  onConnectWallet: () => void;
}

export function PathogenReportingPortal({
  quarantinedAgents,
  onSubmitReport,
  walletConnected,
  onConnectWallet,
}: PathogenReportingPortalProps) {
  const [targetAgent, setTargetAgent] = useState('');
  const [platform, setPlatform] = useState('AGENT_RPC');
  const [traceId, setTraceId] = useState('');
  const [category, setCategory] = useState('PROMPT_INJECTION');
  const [description, setDescription] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const existingRecord = quarantinedAgents.find(
    (q) => q.target_agent.toLowerCase() === targetAgent.trim().toLowerCase()
  );
  const defendedAppeals = existingRecord ? existingRecord.defended_appeals : 0;
  const requiredBond = (0.1 * (1 + defendedAppeals)).toFixed(2);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const cleanAddress = targetAgent.trim();
    if (!cleanAddress || !/^0x[a-fA-F0-9]{40}$/.test(cleanAddress)) {
      setFormError('Enter a valid 40-character hexadecimal address (0x…).');
      return;
    }
    if (!traceId.trim()) {
      setFormError('A telemetry trace ID or transaction hash is required.');
      return;
    }
    if (!description.trim() || description.trim().length < 15) {
      setFormError('Describe the incident with at least 15 characters.');
      return;
    }
    onSubmitReport({
      targetAgent: cleanAddress,
      platform,
      traceId: traceId.trim(),
      category,
      description: description.trim(),
      bondGen: requiredBond,
    });
  };

  const loadSample = () => {
    setTargetAgent('0x98522e861a29E10f36f9037323B06927d7E41C70');
    setPlatform('AGENT_RPC');
    setTraceId('rpc-sec-payload-unauthorized-exec-call-99');
    setCategory('REENTRANCY_DRAIN');
    setDescription('Autonomous agent attempted recursive re-entrancy siphon on liquidity pool router during flash-loan settlement window.');
  };

  return (
    <section className="plate" style={{ maxWidth: 860, marginInline: 'auto' }}>
      <div className="plate-head">
        <div>
          <h2 className="section-title">Report a pathogen</h2>
          <p className="section-copy">
            Stake a reporter bond and submit forensic telemetry. GenLayer validators fetch the trace, classify the threat, and either quarantine the agent or slash the bond.
          </p>
        </div>
        <button type="button" className="btn btn-ghost" onClick={loadSample}>
          Load sample
        </button>
      </div>

      <form className="stack" style={{ gap: 22 }} onSubmit={handleSubmit}>
        {formError && (
          <div className="alert" role="alert">
            <Info size={16} aria-hidden="true" />
            <span>{formError}</span>
          </div>
        )}

        <div className="form-grid form-grid-2">
          <div className="field">
            <label className="label" htmlFor="target-agent">
              Suspect agent address <span className="req">*</span>
            </label>
            <input
              id="target-agent"
              className="input mono"
              value={targetAgent}
              onChange={(e) => setTargetAgent(e.target.value)}
              placeholder="0x71C87050f443831F9Ac9B69B132b35a7455d5b7a"
            />
            <p className="help">On-chain address of the autonomous agent or contract.</p>
          </div>
          <div className="field">
            <label className="label" htmlFor="platform">
              Telemetry origin <span className="req">*</span>
            </label>
            <select id="platform" className="select" value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="AGENT_RPC">AGENT_RPC — JSON-RPC call log</option>
              <option value="TX_TRACE">TX_TRACE — on-chain execution</option>
              <option value="SECURITY_FEED">SECURITY_FEED — watchdog alert</option>
              <option value="GITHUB_AUDIT">GITHUB_AUDIT — repository commit</option>
            </select>
            <p className="help">Where validators should fetch and verify the incident.</p>
          </div>
          <div className="field">
            <label className="label" htmlFor="trace">
              Trace ID / payload hash <span className="req">*</span>
            </label>
            <input
              id="trace"
              className="input mono"
              value={traceId}
              onChange={(e) => setTraceId(e.target.value)}
              placeholder="rpc-payload-prompt-hijack-v3"
            />
            <p className="help">Deterministic identifier used to fetch web telemetry.</p>
          </div>
          <div className="field">
            <label className="label" htmlFor="category">
              Observed indicator <span className="req">*</span>
            </label>
            <select id="category" className="select" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="PROMPT_INJECTION">Prompt injection / system hijack</option>
              <option value="REENTRANCY_DRAIN">Re-entrancy / recursive drain</option>
              <option value="UNAUTHORIZED_CALL">Unauthorized contract call</option>
              <option value="SYBIL_ORACLE_POISON">Oracle manipulation</option>
              <option value="AGENT_MALICIOUS_FORK">Hostile agent fork</option>
            </select>
            <p className="help">Primary exploit vector for classification.</p>
          </div>
        </div>

        <div className="field">
          <label className="label" htmlFor="desc">
            Incident evidence <span className="req">*</span>
          </label>
          <textarea
            id="desc"
            className="textarea"
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe the malicious behaviour, parameter manipulation, or unauthorized execution trace…"
          />
        </div>

        <div className="bond">
          <div>
            <h4 className="h3" style={{ fontSize: 16 }}>Anti-spam staking bond</h4>
            <p className="help" style={{ marginTop: 6, maxWidth: '52ch' }}>
              {'Formula: 0.10 GEN × (1 + defended_appeals). Refunded plus a 0.15 GEN bounty if the pathogen is verified. Slashed if the report is fabricated.'}
              {defendedAppeals > 0 ? ` This target has ${defendedAppeals} defended appeal(s).` : ''}
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="label">Required bond</div>
            <div className="bond-value">{requiredBond} GEN</div>
          </div>
        </div>

        {walletConnected ? (
          <button type="submit" className="btn btn-hemolysis btn-block">
            <Send size={16} aria-hidden="true" />
            Submit to consensus ({requiredBond} GEN)
          </button>
        ) : (
          <button type="button" className="btn btn-stain btn-block" onClick={onConnectWallet}>
            <Lock size={16} aria-hidden="true" />
            Connect wallet to stake bond
          </button>
        )}
      </form>
    </section>
  );
}
