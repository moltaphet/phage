import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Check, Copy, ExternalLink, Loader2, ShieldAlert } from 'lucide-react';
import type { PathogenReport } from '../lib/contract';
import { explorerTxUrl, TIER_FABRICATED_ATTACK, TIER_PATHOGEN_CRITICAL } from '../lib/contract';
import { evaluatePathogen, getReport, reportPathogen, waitForReceipt } from '../lib/genlayer';
import type { GenClient } from '../lib/genlayer';
import { tierLabel } from '../lib/format';

export interface TriageReportData {
  reportId: string;
  targetAgent: string;
  platform: string;
  traceId: string;
  bondAtto: bigint;
  bondGen: string;
  category: string;
  description: string;
}

interface ConsensusTriageModalProps {
  isOpen: boolean;
  onClose: () => void;
  reportData: TriageReportData | null;
  client: GenClient | null;
  onResolved: () => Promise<void> | void;
}

type Phase =
  | 'REVIEW'
  | 'SIGNING_REPORT'
  | 'CONFIRMING_REPORT'
  | 'SIGNING_EVAL'
  | 'CONFIRMING_EVAL'
  | 'READING_RESULT'
  | 'RESOLVED'
  | 'ERROR';

function TxLink({ label, hash }: { label: string; hash: string }) {
  return (
    <div className="cluster" style={{ justifyContent: 'space-between', gap: 8 }}>
      <span className="help">{label}</span>
      <a
        href={explorerTxUrl(hash)}
        target="_blank"
        rel="noopener noreferrer"
        className="cluster hash"
        style={{ gap: 4, fontSize: 12, textDecoration: 'none' }}
      >
        {hash.slice(0, 10)}…{hash.slice(-8)}
        <ExternalLink size={11} aria-hidden="true" />
      </a>
    </div>
  );
}

export function ConsensusTriageModal({ isOpen, onClose, reportData, client, onResolved }: ConsensusTriageModalProps) {
  const [phase, setPhase] = useState<Phase>('REVIEW');
  const [reportTx, setReportTx] = useState<string | null>(null);
  const [evalTx, setEvalTx] = useState<string | null>(null);
  const [resolved, setResolved] = useState<PathogenReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const runningRef = useRef(false);

  // Reset whenever a fresh report is loaded into the modal.
  useEffect(() => {
    if (isOpen) {
      setPhase('REVIEW');
      setReportTx(null);
      setEvalTx(null);
      setResolved(null);
      setError(null);
      runningRef.current = false;
    }
  }, [isOpen, reportData?.reportId]);

  const runTriage = useCallback(async () => {
    if (!reportData || !client || runningRef.current) return;
    runningRef.current = true;
    setError(null);
    try {
      // 1. Bond + register the pathogen report on-chain (payable).
      setPhase('SIGNING_REPORT');
      const reportHash = await reportPathogen(client, {
        reportId: reportData.reportId,
        targetAgent: reportData.targetAgent,
        platform: reportData.platform,
        traceId: reportData.traceId,
        bondAtto: reportData.bondAtto,
      });
      setReportTx(reportHash);
      setPhase('CONFIRMING_REPORT');
      await waitForReceipt(client, reportHash);

      // 2. Trigger the on-chain multi-LLM consensus evaluation.
      setPhase('SIGNING_EVAL');
      const evalHash = await evaluatePathogen(client, reportData.reportId);
      setEvalTx(evalHash);
      setPhase('CONFIRMING_EVAL');
      await waitForReceipt(client, evalHash);

      // 3. Read the real resolved verdict back from contract state.
      setPhase('READING_RESULT');
      const report = await getReport(reportData.reportId);
      setResolved(report);
      setPhase('RESOLVED');
      await onResolved();
    } catch (err) {
      setError(err instanceof Error ? err.message.split('\n')[0] : 'Transaction failed.');
      setPhase('ERROR');
      runningRef.current = false;
    }
  }, [client, reportData, onResolved]);

  if (!isOpen || !reportData) return null;

  const busy =
    phase === 'SIGNING_REPORT' ||
    phase === 'CONFIRMING_REPORT' ||
    phase === 'SIGNING_EVAL' ||
    phase === 'CONFIRMING_EVAL' ||
    phase === 'READING_RESULT';

  const phaseCopy: Record<Phase, string> = {
    REVIEW: 'Review the report. Two signatures are required: the bonded report, then the evaluation trigger.',
    SIGNING_REPORT: 'Confirm the bonded report transaction in your wallet…',
    CONFIRMING_REPORT: 'Report accepted — waiting for consensus confirmation…',
    SIGNING_EVAL: 'Confirm the evaluation transaction in your wallet…',
    CONFIRMING_EVAL: 'Validators are fetching telemetry and running multi-LLM consensus on-chain…',
    READING_RESULT: 'Reading the resolved verdict from contract state…',
    RESOLVED: 'Triage finalized on-chain.',
    ERROR: 'The transaction did not complete.',
  };

  const tier = resolved?.evaluated_tier ?? '';
  const isCritical = tier === TIER_PATHOGEN_CRITICAL;
  const isFabricated = tier === TIER_FABRICATED_ATTACK;

  const stepClass = (active: Phase[], done: Phase[]) =>
    `phase${active.includes(phase) ? ' is-on' : done.includes(phase) ? ' is-done' : ''}`;

  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="triage-title">
      <div className="modal">
        <div className="modal-head">
          <div>
            <h3 id="triage-title" className="h3">On-chain pathogen triage</h3>
            <p className="help mono" style={{ marginTop: 4 }}>report_pathogen → evaluate_pathogen</p>
          </div>
          {phase === 'RESOLVED' && (
            <span className={`chip ${isFabricated ? 'chip-iso' : 'chip-ok'}`}>{tierLabel(tier)}</span>
          )}
        </div>

        <div className="modal-body">
          <div className="cluster" style={{ justifyContent: 'space-between', gap: 10 }}>
            <span className="hash">{reportData.targetAgent}</span>
            <span className="help">{reportData.platform} · {reportData.bondGen} GEN bond</span>
          </div>

          <div className="phase-grid">
            <div className={stepClass(['SIGNING_REPORT', 'CONFIRMING_REPORT'], ['SIGNING_EVAL', 'CONFIRMING_EVAL', 'READING_RESULT', 'RESOLVED'])}>
              1. Bond &amp; report
            </div>
            <div className={stepClass(['SIGNING_EVAL', 'CONFIRMING_EVAL'], ['READING_RESULT', 'RESOLVED'])}>
              2. Multi-LLM consensus
            </div>
            <div className={stepClass(['READING_RESULT'], ['RESOLVED'])}>3. Verdict</div>
          </div>

          {(reportTx || evalTx) && (
            <div className="stack" style={{ gap: 8 }}>
              {reportTx && <TxLink label="Report tx" hash={reportTx} />}
              {evalTx && <TxLink label="Evaluation tx" hash={evalTx} />}
            </div>
          )}

          {busy && (
            <div className="validator">
              <div className="cluster" style={{ gap: 10 }}>
                <Loader2 size={16} className="spin" />
                <p className="help" style={{ margin: 0 }}>{phaseCopy[phase]}</p>
              </div>
            </div>
          )}

          {phase === 'ERROR' && (
            <div className="alert" role="alert">
              <AlertTriangle size={16} aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          {phase === 'RESOLVED' && resolved && (
            <div className={`specimen ${isFabricated ? 'is-iso' : 'is-ok'}`}>
              <div className="cluster" style={{ justifyContent: 'space-between' }}>
                <strong>{isFabricated ? 'Report slashed as fabricated' : 'Verdict recorded on-chain'}</strong>
                {resolved.quarantine_seconds > 0 && (
                  <span className="chip chip-iso">{Math.round(resolved.quarantine_seconds / 86400)}d quarantine</span>
                )}
              </div>
              <dl className="kv">
                <div>
                  <dt>Tier</dt>
                  <dd>{tierLabel(tier)}</dd>
                </div>
                <div>
                  <dt>Report bond</dt>
                  <dd>{isFabricated ? `−${reportData.bondGen} GEN (slashed)` : `${reportData.bondGen} GEN (refundable)`}</dd>
                </div>
                <div>
                  <dt>Bounty payout</dt>
                  <dd>{resolved.bounty_payout_gen} GEN</dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>{resolved.state}</dd>
                </div>
              </dl>
              {isCritical && resolved.target_agent && (
                <div className="hashbox">
                  <span className="hash" style={{ flex: 1 }}>Antibody minted for {resolved.target_agent}</span>
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label="Copy target agent"
                    onClick={() => {
                      void navigator.clipboard.writeText(resolved.target_agent);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
              )}
              <p className="help" style={{ marginTop: 8 }}>
                {isFabricated
                  ? 'Consensus found no verifiable threat, so the bond was forfeited to protocol reserves. No claimable balance was credited.'
                  : 'Your bond is now claimable from your settlement vault, along with any bounty above.'}
              </p>
            </div>
          )}
        </div>

        <div className="modal-foot">
          <span className="help">{phaseCopy[phase]}</span>
          {phase === 'REVIEW' && (
            <button type="button" className="btn btn-hemolysis" onClick={() => void runTriage()}>
              <ShieldAlert size={16} aria-hidden="true" />
              Sign &amp; submit ({reportData.bondGen} GEN)
            </button>
          )}
          {phase === 'ERROR' && (
            <div className="cluster" style={{ gap: 8 }}>
              <button type="button" className="btn btn-ghost" onClick={onClose}>Close</button>
              <button type="button" className="btn btn-hemolysis" onClick={() => void runTriage()}>Retry</button>
            </div>
          )}
          {phase === 'RESOLVED' && (
            <button type="button" className="btn btn-stain" onClick={onClose}>Done</button>
          )}
          {busy && (
            <button type="button" className="btn btn-ghost" disabled>
              <Loader2 size={14} className="spin" /> Working…
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
