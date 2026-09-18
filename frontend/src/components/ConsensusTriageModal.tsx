import { useEffect, useState } from 'react';
import { Check, Copy, Loader2 } from 'lucide-react';

interface ConsensusTriageModalProps {
  isOpen: boolean;
  onClose: () => void;
  reportData: {
    targetAgent: string;
    platform: string;
    traceId: string;
    category: string;
    description: string;
    bondGen: string;
  } | null;
  onCompleteConsensus: (result: {
    targetAgent: string;
    quarantineSeconds: number;
    reasonTier: string;
    antibodyHash: string;
    bountyPayoutGen: string;
    traceId: string;
    platform: string;
  }) => void;
}

interface ValidatorState {
  id: string;
  name: string;
  model: string;
  status: 'PENDING' | 'ANALYZING' | 'AGREED';
  verdict?: string;
  threatScore?: number;
  timeMs?: number;
}

const INITIAL: ValidatorState[] = [
  { id: 'val-1', name: 'Node 0x1A4F', model: 'Llama-3-70b-instruct', status: 'PENDING' },
  { id: 'val-2', name: 'Node 0x7E92', model: 'Mixtral-8x22b-instruct', status: 'PENDING' },
  { id: 'val-3', name: 'Node 0xC83B', model: 'Claude-3.5-Sonnet', status: 'PENDING' },
];

export function ConsensusTriageModal({
  isOpen,
  onClose,
  reportData,
  onCompleteConsensus,
}: ConsensusTriageModalProps) {
  const [phase, setPhase] = useState<'BROADCASTING' | 'INSPECTING' | 'CONSENSUS_REACHED' | 'ANTIBODY_MINTED'>('BROADCASTING');
  const [copiedHash, setCopiedHash] = useState(false);
  const [validators, setValidators] = useState<ValidatorState[]>(INITIAL);
  const [generatedAntibody, setGeneratedAntibody] = useState('');

  useEffect(() => {
    if (!isOpen || !reportData) {
      setPhase('BROADCASTING');
      setValidators(INITIAL);
      return;
    }

    const hashSegment = Math.random().toString(16).substring(2, 10);
    setGeneratedAntibody(`0x${hashSegment}9f84b12c801e74a6d912e5c84719028374a5e6f1${hashSegment}`);

    const t1 = setTimeout(() => {
      setPhase('INSPECTING');
      setValidators((prev) => prev.map((v, i) => (i === 0 ? { ...v, status: 'ANALYZING' } : v)));
    }, 700);
    const t2 = setTimeout(() => {
      setValidators((prev) =>
        prev.map((v, i) => {
          if (i === 0) return { ...v, status: 'AGREED', verdict: 'TIER_PATHOGEN_CRITICAL', threatScore: 96, timeMs: 820 };
          if (i === 1) return { ...v, status: 'ANALYZING' };
          return v;
        })
      );
    }, 1600);
    const t3 = setTimeout(() => {
      setValidators((prev) =>
        prev.map((v, i) => {
          if (i === 1) return { ...v, status: 'AGREED', verdict: 'TIER_PATHOGEN_CRITICAL', threatScore: 94, timeMs: 1410 };
          if (i === 2) return { ...v, status: 'ANALYZING' };
          return v;
        })
      );
    }, 2400);
    const t4 = setTimeout(() => {
      setValidators((prev) =>
        prev.map((v, i) =>
          i === 2 ? { ...v, status: 'AGREED', verdict: 'TIER_PATHOGEN_CRITICAL', threatScore: 95, timeMs: 1980 } : v
        )
      );
      setPhase('CONSENSUS_REACHED');
    }, 3200);
    const t5 = setTimeout(() => setPhase('ANTIBODY_MINTED'), 4200);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      clearTimeout(t5);
    };
  }, [isOpen, reportData]);

  if (!isOpen || !reportData) return null;

  const handleFinalize = () => {
    onCompleteConsensus({
      targetAgent: reportData.targetAgent,
      quarantineSeconds: 604800,
      reasonTier: 'TIER_PATHOGEN_CRITICAL',
      antibodyHash: generatedAntibody,
      bountyPayoutGen: '0.15',
      traceId: reportData.traceId,
      platform: reportData.platform,
    });
    onClose();
  };

  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="triage-title">
      <div className="modal">
        <div className="modal-head">
          <div>
            <h3 id="triage-title" className="h3">Multi-LLM triage</h3>
            <p className="help mono" style={{ marginTop: 4 }}>gl.exec_prompt · equivalence principle</p>
          </div>
          {phase === 'ANTIBODY_MINTED' && <span className="chip chip-ok">3/3 consensus</span>}
        </div>

        <div className="modal-body">
          <div className="cluster" style={{ justifyContent: 'space-between', gap: 10 }}>
            <span className="hash">{reportData.targetAgent}</span>
            <span className="help">{reportData.platform} · {reportData.bondGen} GEN bonded</span>
          </div>

          <div className="phase-grid">
            <div className={`phase${phase === 'BROADCASTING' ? ' is-on' : ' is-done'}`}>1. Fetch telemetry</div>
            <div className={`phase${phase === 'INSPECTING' ? ' is-on' : phase === 'CONSENSUS_REACHED' || phase === 'ANTIBODY_MINTED' ? ' is-done' : ''}`}>2. Equivalence</div>
            <div className={`phase${phase === 'ANTIBODY_MINTED' ? ' is-done' : ''}`}>3. Antibody</div>
          </div>

          <div className="stack" style={{ gap: 8 }}>
            {validators.map((val) => (
              <div key={val.id} className="validator">
                <div>
                  <div style={{ fontWeight: 650, fontSize: 13 }}>
                    {val.name} <span className="help">({val.model})</span>
                  </div>
                  <p className="help" style={{ marginTop: 4 }}>
                    {val.status === 'PENDING' && 'Queued for dispatch'}
                    {val.status === 'ANALYZING' && 'Evaluating payload against the security ruleset'}
                    {val.status === 'AGREED' && `Agreed: ${val.verdict} · ${val.threatScore}/100 in ${val.timeMs}ms`}
                  </p>
                </div>
                <span className={`chip ${val.status === 'AGREED' ? 'chip-ok' : val.status === 'ANALYZING' ? 'chip-warn' : 'chip-mute'}`}>
                  {val.status === 'ANALYZING' && <Loader2 size={11} className="spin" />}
                  {val.status === 'PENDING' ? 'Queued' : val.status === 'ANALYZING' ? 'Analyzing' : 'Verified'}
                </span>
              </div>
            ))}
          </div>

          {phase === 'ANTIBODY_MINTED' && (
            <div className="specimen is-ok">
              <div className="cluster" style={{ justifyContent: 'space-between' }}>
                <strong>Quarantine executed</strong>
                <span className="chip chip-iso">7 days</span>
              </div>
              <dl className="kv">
                <div>
                  <dt>Tier</dt>
                  <dd>PATHOGEN CRITICAL</dd>
                </div>
                <div>
                  <dt>Bond returned</dt>
                  <dd>+{reportData.bondGen} GEN</dd>
                </div>
                <div>
                  <dt>Bounty</dt>
                  <dd>{'+0.15 GEN'}</dd>
                </div>
              </dl>
              <div className="hashbox">
                <span className="hash" style={{ flex: 1 }}>{generatedAntibody}</span>
                <button
                  type="button"
                  className="icon-btn"
                  aria-label="Copy antibody hash"
                  onClick={() => {
                    navigator.clipboard.writeText(generatedAntibody);
                    setCopiedHash(true);
                    setTimeout(() => setCopiedHash(false), 2000);
                  }}
                >
                  {copiedHash ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="modal-foot">
          <span className="help">
            {phase === 'ANTIBODY_MINTED' ? 'Triage finalized.' : 'Awaiting validator equivalence…'}
          </span>
          {phase === 'ANTIBODY_MINTED' ? (
            <button type="button" className="btn btn-stain" onClick={handleFinalize}>
              Record to ledger
            </button>
          ) : (
            <button type="button" className="btn btn-ghost" onClick={onClose}>
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
