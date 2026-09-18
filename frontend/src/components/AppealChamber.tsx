import { useEffect, useState } from 'react';
import { AlertCircle, Loader2, Lock, Send } from 'lucide-react';
import type { AppealRecord, QuarantineInfo } from '../lib/contract';
import { formatIso, shortHex, tierLabel } from '../lib/format';

interface AppealChamberProps {
  quarantinedAgents: QuarantineInfo[];
  recentAppeals: AppealRecord[];
  initialTarget: string;
  onSubmitAppeal: (data: {
    targetAgent: string;
    proofTraceId: string;
    platform: string;
    reason: string;
  }) => Promise<void>;
  walletConnected: boolean;
  onConnectWallet: () => void;
}

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

export function AppealChamber({
  quarantinedAgents,
  recentAppeals,
  initialTarget,
  onSubmitAppeal,
  walletConnected,
  onConnectWallet,
}: AppealChamberProps) {
  const [selectedAgent, setSelectedAgent] = useState(initialTarget);
  const [proofTraceId, setProofTraceId] = useState('');
  const [platform, setPlatform] = useState('GITHUB_AUDIT');
  const [reason, setReason] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (initialTarget) setSelectedAgent(initialTarget);
  }, [initialTarget]);

  const activeQuarantined = quarantinedAgents.filter((q) => q.is_active);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    const cleanAddress = selectedAgent.trim();
    if (!ADDRESS_RE.test(cleanAddress)) {
      setErrorMsg('Select or enter a valid 40-character target agent address.');
      return;
    }
    if (!proofTraceId.trim()) {
      setErrorMsg('A counter-evidence trace ID or patch commit is required.');
      return;
    }
    if (!reason.trim() || reason.trim().length < 15) {
      setErrorMsg('State grounds for appeal with at least 15 characters.');
      return;
    }
    setSubmitting(true);
    try {
      await onSubmitAppeal({
        targetAgent: cleanAddress,
        proofTraceId: proofTraceId.trim(),
        platform,
        reason: reason.trim(),
      });
      setProofTraceId('');
      setReason('');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message.split('\n')[0] : 'Appeal transaction failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="stack" style={{ gap: 24, maxWidth: 860, marginInline: 'auto' }}>
      <section className="plate">
        <div className="plate-head">
          <div>
            <h2 className="section-title">Appeal chamber</h2>
            <p className="section-copy">
              Contest a false-positive quarantine with patched code or clean telemetry. Validators re-audit on-chain. If upheld, isolation lifts and the antibody is revoked.
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="label">Appeal bond</div>
            <div className="bond-value" style={{ color: 'var(--cytoplasm)' }}>0.20 GEN</div>
          </div>
        </div>

        <form className="stack" style={{ gap: 22 }} onSubmit={handleSubmit}>
          {errorMsg && (
            <div className="alert" role="alert">
              <AlertCircle size={16} aria-hidden="true" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="form-grid form-grid-2">
            <div className="field">
              <label className="label" htmlFor="appeal-target">
                Quarantined agent <span className="req">*</span>
              </label>
              {activeQuarantined.length > 0 ? (
                <select id="appeal-target" className="select mono" value={selectedAgent} onChange={(e) => setSelectedAgent(e.target.value)}>
                  <option value="">Select an isolated agent</option>
                  {activeQuarantined.map((q) => (
                    <option key={q.target_agent} value={q.target_agent}>
                      {shortHex(q.target_agent, 10, 6)} · {tierLabel(q.reason_tier)}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  id="appeal-target"
                  className="input mono"
                  value={selectedAgent}
                  onChange={(e) => setSelectedAgent(e.target.value)}
                  placeholder="0x…"
                />
              )}
            </div>
            <div className="field">
              <label className="label" htmlFor="appeal-platform">
                Counter-proof platform <span className="req">*</span>
              </label>
              <select id="appeal-platform" className="select" value={platform} onChange={(e) => setPlatform(e.target.value)}>
                <option value="GITHUB_AUDIT">GITHUB_AUDIT — verified patch</option>
                <option value="AGENT_RPC">AGENT_RPC — sanitized log</option>
                <option value="TX_TRACE">TX_TRACE — state proof</option>
                <option value="SECURITY_FEED">SECURITY_FEED — whitehat retraction</option>
              </select>
            </div>
          </div>

          <div className="field">
            <label className="label" htmlFor="proof">
              Remediation commit / trace ID <span className="req">*</span>
            </label>
            <input
              id="proof"
              className="input mono"
              value={proofTraceId}
              onChange={(e) => setProofTraceId(e.target.value)}
              placeholder="org/repo/commit-9f38c1a"
            />
          </div>

          <div className="field">
            <label className="label" htmlFor="grounds">
              Grounds for appeal <span className="req">*</span>
            </label>
            <textarea
              id="grounds"
              className="textarea"
              rows={4}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Explain why the quarantine was a false positive, or how the patch neutralizes the flagged vector…"
            />
          </div>

          <p className="help">
            Deposit 0.20 GEN. If consensus verifies remediation, the bond is refunded to your claimable vault, quarantine lifts, and the antibody is revoked. Rejected appeals forfeit the bond to protocol reserves.
          </p>

          {walletConnected ? (
            <button type="submit" className="btn btn-cytoplasm btn-block" disabled={submitting}>
              {submitting ? <Loader2 size={16} className="spin" /> : <Send size={16} aria-hidden="true" />}
              {submitting ? 'Running consensus on-chain…' : 'Submit appeal (0.20 GEN)'}
            </button>
          ) : (
            <button type="button" className="btn btn-stain btn-block" onClick={onConnectWallet}>
              <Lock size={16} aria-hidden="true" />
              Connect wallet to lodge appeal
            </button>
          )}
        </form>
      </section>

      <section className="plate">
        <div className="plate-head">
          <h3 className="h3">Recent decisions</h3>
          <span className="chip">On-chain verdicts</span>
        </div>
        {recentAppeals.length === 0 ? (
          <p className="help" style={{ padding: '8px 2px' }}>
            No appeals recorded in this session yet. Submitted appeals and their real consensus verdicts appear here.
          </p>
        ) : (
          <div className="stack" style={{ gap: 10 }}>
            {recentAppeals.map((app) => (
              <div key={app.appeal_id} className="appeal-row">
                <div>
                  <div className="cluster" style={{ gap: 8 }}>
                    <span className="hash">{app.appeal_id}</span>
                    <span className={`chip ${app.state === 'UPHELD' ? 'chip-ok' : 'chip-iso'}`}>
                      {app.state === 'UPHELD' ? 'Upheld' : app.state === 'REJECTED' ? 'Rejected' : 'Pending'}
                    </span>
                    <span className="chip">{app.platform}</span>
                  </div>
                  <p className="hash" style={{ marginTop: 8 }}>Agent {shortHex(app.target_agent, 10, 8)}</p>
                  <p className="help" style={{ marginTop: 4 }}>Proof: {app.proof_trace_id}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontWeight: 700 }}>
                    {app.state === 'UPHELD' ? `+${app.appeal_bond_gen} GEN refunded` : `−${app.appeal_bond_gen} GEN forfeited`}
                  </div>
                  <div className="help">{formatIso(app.timestamp_iso)}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
