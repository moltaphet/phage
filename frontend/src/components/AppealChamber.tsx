import { useEffect, useState } from 'react';
import { AlertCircle, Loader2, Lock, Send } from 'lucide-react';
import type { AppealRecord, Platform, QuarantineInfo } from '../lib/contract';
import { PLATFORM_IDENTIFIER_HINT, PLATFORM_LABELS, VALID_PLATFORMS } from '../lib/contract';
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
// Mirrors the contract's `_validate_trace_id`: every platform takes a transaction
// hash. The transaction must also involve the quarantined agent — proof about
// someone else rejects the appeal and forfeits the bond.
const TX_HASH_RE = /^0x[a-fA-F0-9]{64}$/;

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
  const [platform, setPlatform] = useState<Platform>('EVM_TX');
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
    if (!TX_HASH_RE.test(proofTraceId.trim())) {
      setErrorMsg('Enter the 0x-prefixed 32-byte transaction hash the agent is a party to.');
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
              Contest a false-positive quarantine with a transaction the agent is a party to. Filing freezes the reporter's payout until validators rule; if upheld, the reporter is slashed, isolation lifts and the antibody is revoked.
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="label">Appeal bond</div>
            <div className="bond-value" style={{ color: 'var(--cytoplasm)' }}>from 0.20 GEN</div>
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
              <select
                id="appeal-platform"
                className="select"
                value={platform}
                onChange={(e) => setPlatform(e.target.value as Platform)}
              >
                {VALID_PLATFORMS.map((p) => (
                  <option key={p} value={p}>
                    {PLATFORM_LABELS[p]}
                  </option>
                ))}
              </select>
              <p className="help">
                The proof is checked against the agent you are appealing for. Records about a
                different address are rejected and forfeit the bond.
              </p>
            </div>
          </div>

          <div className="field">
            <label className="label" htmlFor="proof">
              Counter-evidence identifier <span className="req">*</span>
            </label>
            <input
              id="proof"
              className="input mono"
              value={proofTraceId}
              onChange={(e) => setProofTraceId(e.target.value)}
              placeholder="0x8c1e0f3d9a5b7c4e2f6a8d0b1c3e5f7092a4b6d8e0f2a4c6b8d0e2f4a6c8b0d2"
            />
            <p className="help">{PLATFORM_IDENTIFIER_HINT[platform]}.</p>
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
            Two transactions: filing posts the bond (0.20 GEN, doubling with each rejected appeal on the same report) and freezes the disputed payout; resolving runs consensus. Upheld: your bond is refunded, the reporter's bond is slashed and the bounty returns to the pool. Rejected: your bond is forfeit to reserves, and the window stays open 24h for a further appeal.
          </p>

          {walletConnected ? (
            <button type="submit" className="btn btn-cytoplasm btn-block" disabled={submitting}>
              {submitting ? <Loader2 size={16} className="spin" /> : <Send size={16} aria-hidden="true" />}
              {submitting ? 'Filing and resolving on-chain…' : 'File and resolve appeal'}
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
                      {app.state === 'UPHELD'
                        ? 'Upheld'
                        : app.state === 'REJECTED'
                          ? 'Rejected'
                          : app.state === 'EXPIRED'
                            ? 'Expired'
                            : 'Under appeal'}
                    </span>
                    <span className="chip">{app.platform}</span>
                  </div>
                  <p className="hash" style={{ marginTop: 8 }}>
                    Agent {shortHex(app.target_agent, 10, 8)} · report {app.report_id}
                  </p>
                  <p className="help" style={{ marginTop: 4 }}>Proof: {app.proof_trace_id}</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontWeight: 700 }}>
                    {app.state === 'REJECTED'
                      ? `−${app.appeal_bond_gen} GEN forfeited`
                      : app.state === 'PENDING'
                        ? `${app.appeal_bond_gen} GEN held`
                        : `+${app.appeal_bond_gen} GEN refunded`}
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
