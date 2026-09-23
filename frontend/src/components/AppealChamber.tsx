import { useEffect, useState } from 'react';
import { AlertCircle, Loader2, Lock, Send } from 'lucide-react';
import type { AppealRecord, QuarantineInfo, RebuttalKind } from '../lib/contract';
import {
  MAX_JUSTIFICATION_CHARS,
  MIN_JUSTIFICATION_CHARS,
  REBUTTAL_KIND_LABELS,
  REBUTTAL_KINDS,
} from '../lib/contract';
import { formatIso, shortHex, tierLabel } from '../lib/format';

interface AppealChamberProps {
  quarantinedAgents: QuarantineInfo[];
  recentAppeals: AppealRecord[];
  initialTarget: string;
  onSubmitAppeal: (data: {
    targetAgent: string;
    rebuttalKind: RebuttalKind;
    justification: string;
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
  const [rebuttalKind, setRebuttalKind] = useState<RebuttalKind>('AUTHORIZED_ADMIN_ACTION');
  const [justification, setJustification] = useState('');
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
    const text = justification.trim();
    if (text.length < MIN_JUSTIFICATION_CHARS || text.length > MAX_JUSTIFICATION_CHARS) {
      setErrorMsg(
        `Justify the rebuttal in ${MIN_JUSTIFICATION_CHARS}–${MAX_JUSTIFICATION_CHARS} characters.`,
      );
      return;
    }
    setSubmitting(true);
    try {
      await onSubmitAppeal({ targetAgent: cleanAddress, rebuttalKind, justification: text });
      setJustification('');
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
              Rebut the report behind a quarantine. An appeal cannot cite some other transaction: it argues that the report's own flagged transaction was legitimate, and validators re-judge that transaction with your rebuttal in view. Filing freezes the reporter's payout until they rule; if upheld, the reporter is slashed, isolation lifts and the antibody is revoked.
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
              <label className="label" htmlFor="rebuttal-kind">
                Rebuttal <span className="req">*</span>
              </label>
              <select
                id="rebuttal-kind"
                className="select"
                value={rebuttalKind}
                onChange={(e) => setRebuttalKind(e.target.value as RebuttalKind)}
              >
                {REBUTTAL_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {REBUTTAL_KIND_LABELS[k]}
                  </option>
                ))}
              </select>
              <p className="help">
                The appeal targets the flagged transaction of the report that defines this
                quarantine — it is filled in for you and cannot be substituted.
              </p>
            </div>
          </div>

          <div className="field">
            <label className="label" htmlFor="grounds">
              Justification <span className="req">*</span>
            </label>
            <textarea
              id="grounds"
              className="textarea"
              rows={4}
              maxLength={MAX_JUSTIFICATION_CHARS}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Explain why the flagged transaction was legitimate protocol execution — who was authorised to make the call, where the borrowed value went, which documented routine it belongs to…"
            />
            <p className="help">
              {justification.trim().length}/{MAX_JUSTIFICATION_CHARS} · validators accept it only if the
              flagged transaction itself is consistent with it.
            </p>
          </div>

          <p className="help">
            Two transactions: filing posts the bond (0.20 GEN, rising by 0.20 GEN with each rejected appeal on the same report) and freezes the disputed payout; resolving runs consensus. Upheld: your bond is refunded, the reporter's bond is slashed and the bounty returns to the pool. Rejected: your bond is forfeit to reserves, and the window stays open 24h for a further appeal.
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
                    <span className="chip">{app.rebuttal_kind || app.platform}</span>
                  </div>
                  <p className="hash" style={{ marginTop: 8 }}>
                    Agent {shortHex(app.target_agent, 10, 8)} · report {app.report_id}
                  </p>
                  <p className="help" style={{ marginTop: 4 }}>Rebutted: {app.rebutted_trace_id}</p>
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
