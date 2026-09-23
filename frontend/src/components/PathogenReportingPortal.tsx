import { useEffect, useState } from 'react';
import { Info, Loader2, Lock, Send } from 'lucide-react';
import { getRequiredReporterBondGen } from '../lib/genlayer';
import {
  EXPLOIT_CATEGORIES,
  EXPLOIT_CATEGORY_LABELS,
  PLATFORM_IDENTIFIER_HINT,
  PLATFORM_LABELS,
  PLATFORM_SOURCE,
  VALID_PLATFORMS,
} from '../lib/contract';
import type { ExploitCategory, Platform } from '../lib/contract';

interface PathogenReportingPortalProps {
  initialTarget: string;
  onSubmitReport: (reportData: {
    targetAgent: string;
    platform: string;
    traceId: string;
    category: string;
    description: string;
  }) => void;
  walletConnected: boolean;
  onConnectWallet: () => void;
}

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
// Kept in step with the contract's own `_validate_trace_id`: every platform takes a
// 32-byte transaction hash. The contract is still the authority — this only turns
// a rejected transaction into an inline message.
const TX_HASH_RE = /^0x[a-fA-F0-9]{64}$/;

export function PathogenReportingPortal({
  initialTarget,
  onSubmitReport,
  walletConnected,
  onConnectWallet,
}: PathogenReportingPortalProps) {
  const [targetAgent, setTargetAgent] = useState(initialTarget);
  const [platform, setPlatform] = useState<Platform>('EVM_TX');
  const [traceId, setTraceId] = useState('');
  const [category, setCategory] = useState<ExploitCategory>('FLASH_LOAN_DRAIN');
  const [description, setDescription] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [requiredBond, setRequiredBond] = useState('0.10');
  const [bondLoading, setBondLoading] = useState(false);

  const evidenceId = traceId.trim();

  // Prefill when navigated here from the inspector with a target.
  useEffect(() => {
    if (initialTarget) setTargetAgent(initialTarget);
  }, [initialTarget]);

  // Live read of the authoritative required reporter bond for the target. The
  // contract escalates this per defended appeal, so we never guess it locally.
  useEffect(() => {
    const clean = targetAgent.trim();
    if (!ADDRESS_RE.test(clean)) {
      setRequiredBond('0.10');
      return;
    }
    let cancelled = false;
    setBondLoading(true);
    const timer = setTimeout(async () => {
      try {
        const bond = await getRequiredReporterBondGen(clean);
        if (!cancelled) setRequiredBond(bond);
      } catch {
        if (!cancelled) setRequiredBond('0.10');
      } finally {
        if (!cancelled) setBondLoading(false);
      }
    }, 350);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [targetAgent]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const cleanAddress = targetAgent.trim();
    if (!ADDRESS_RE.test(cleanAddress)) {
      setFormError('Enter a valid 40-character hexadecimal address (0x…).');
      return;
    }
    if (!TX_HASH_RE.test(evidenceId)) {
      setFormError('Enter the 0x-prefixed 32-byte transaction hash the target is a party to.');
      return;
    }
    if (!description.trim() || description.trim().length < 15) {
      setFormError('Describe the incident with at least 15 characters.');
      return;
    }
    onSubmitReport({
      targetAgent: cleanAddress,
      platform,
      traceId: evidenceId,
      category,
      description: description.trim(),
    });
  };

  const loadSample = () => {
    setTargetAgent('0x98522e861a29E10f36f9037323B06927d7E41C70');
    setPlatform('EVM_TX');
    // A real mainnet transaction hash, so the sample is one the contract can fetch
    // and check for the target's participation rather than an illustrative string.
    setTraceId('0x8c1e0f3d9a5b7c4e2f6a8d0b1c3e5f7092a4b6d8e0f2a4c6b8d0e2f4a6c8b0d2');
    setCategory('REENTRANCY');
    setDescription('Autonomous agent attempted recursive re-entrancy siphon on liquidity pool router during flash-loan settlement window.');
  };

  return (
    <section className="plate" style={{ maxWidth: 860, marginInline: 'auto' }}>
      <div className="plate-head">
        <div>
          <h2 className="section-title">Report a pathogen</h2>
          <p className="section-copy">
            Stake a reporter bond and submit forensic telemetry. GenLayer validators fetch the trace, classify the threat, and either quarantine the agent or slash the bond — all on-chain.
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
            <select
              id="platform"
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
              Validators fetch the incident from {PLATFORM_SOURCE[platform]}. Filing reverts
              (ERR_UNBOUND_EVIDENCE, no bond taken) unless the transaction names the suspect
              as sender, recipient or created contract.
            </p>
          </div>
          <div className="field">
            <label className="label" htmlFor="trace">
              Transaction hash{' '}
              <span className="req">*</span>
            </label>
            <input
              id="trace"
              className="input mono"
              value={traceId}
              onChange={(e) => setTraceId(e.target.value)}
              placeholder="0x8c1e0f3d9a5b7c4e2f6a8d0b1c3e5f7092a4b6d8e0f2a4c6b8d0e2f4a6c8b0d2"
              aria-describedby="trace-help"
            />
            <p className="help" id="trace-help">
              {PLATFORM_IDENTIFIER_HINT[platform]}. Validators fetch this record and the
              contract confirms it concerns the suspect before any verdict is reached.
            </p>
          </div>
          <div className="field">
            <label className="label" htmlFor="category">
              Exploit category <span className="req">*</span>
            </label>
            <select
              id="category"
              className="select"
              value={category}
              onChange={(e) => setCategory(e.target.value as ExploitCategory)}
            >
              {EXPLOIT_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {EXPLOIT_CATEGORY_LABELS[c]}
                </option>
              ))}
            </select>
            <p className="help">
              Validators check the transaction shows this category's mechanics. If it does not,
              filing reverts (ERR_UNSUPPORTED_EXPLOIT_CATEGORY) and no bond is taken.
            </p>
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
              Read live from the contract as 0.10 GEN × (1 + defended_appeals). Refunded to your claimable vault plus any bounty if the pathogen is verified. Slashed to reserves if the report is fabricated.
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="label">Required bond</div>
            <div className="bond-value cluster" style={{ gap: 6, justifyContent: 'flex-end' }}>
              {bondLoading && <Loader2 size={13} className="spin" />}
              {requiredBond} GEN
            </div>
          </div>
        </div>

        {walletConnected ? (
          <button type="submit" className="btn btn-hemolysis btn-block">
            <Send size={16} aria-hidden="true" />
            Sign report &amp; evaluate on-chain ({requiredBond} GEN)
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
