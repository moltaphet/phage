import { useCallback, useEffect, useState } from 'react';
import { Coins, Loader2, RefreshCw, Search } from 'lucide-react';
import type { EscrowRecord, PathogenReport } from '../lib/contract';
import { getClaimableBalanceGen, getEscrow, getReport } from '../lib/genlayer';
import { describeError } from '../lib/errors';
import { formatIso, shortHex } from '../lib/format';

interface ClaimVaultProps {
  address: string | null;
  walletConnected: boolean;
  // Bumps whenever an on-chain action may have changed the caller's balance.
  refreshKey: number;
  onWithdraw: () => Promise<void>;
  onSettleIncident: (reportId: string, action: 'claim' | 'expire') => Promise<void>;
}

interface IncidentView {
  report: PathogenReport;
  escrow: EscrowRecord;
}

export function ClaimVault({ address, walletConnected, refreshKey, onWithdraw, onSettleIncident }: ClaimVaultProps) {
  const [claimable, setClaimable] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [withdrawing, setWithdrawing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [incidentId, setIncidentId] = useState('');
  const [incident, setIncident] = useState<IncidentView | null>(null);
  const [incidentError, setIncidentError] = useState<string | null>(null);
  const [settling, setSettling] = useState<'claim' | 'expire' | 'lookup' | null>(null);

  const load = useCallback(async () => {
    if (!address) {
      setClaimable(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setClaimable(await getClaimableBalanceGen(address));
    } catch (err) {
      setError(describeError(err));
      setClaimable(null);
    } finally {
      setLoading(false);
    }
  }, [address]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  if (!walletConnected || !address) return null;

  const hasClaimable = claimable !== null && Number(claimable) > 0;

  const lookupIncident = async (id: string = incidentId.trim()) => {
    if (!id) return;
    setSettling('lookup');
    setIncidentError(null);
    try {
      const [report, escrow] = await Promise.all([getReport(id), getEscrow(id)]);
      setIncident({ report, escrow });
    } catch (err) {
      setIncident(null);
      setIncidentError(describeError(err));
    } finally {
      setSettling(null);
    }
  };

  const settle = async (action: 'claim' | 'expire') => {
    const id = incidentId.trim();
    if (!id) return;
    setSettling(action);
    setIncidentError(null);
    try {
      await onSettleIncident(id, action);
      await load();
    } catch (err) {
      setIncidentError(describeError(err));
    } finally {
      setSettling(null);
    }
    await lookupIncident(id);
  };

  const handleWithdraw = async () => {
    setWithdrawing(true);
    try {
      await onWithdraw();
      await load();
    } finally {
      setWithdrawing(false);
    }
  };

  return (
    <section className="plate" aria-label="Claimable balance">
      <div className="plate-head">
        <div className="cluster" style={{ gap: 10 }}>
          <Coins size={18} aria-hidden="true" />
          <div>
            <h3 className="h3" style={{ fontSize: 16 }}>Your settlement vault</h3>
            <p className="help mono" style={{ marginTop: 2 }}>{shortHex(address, 8, 6)}</p>
          </div>
        </div>
        <button
          type="button"
          className="icon-btn"
          aria-label="Refresh claimable balance"
          onClick={() => void load()}
        >
          {loading ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />}
        </button>
      </div>

      <div className="cluster" style={{ justifyContent: 'space-between', gap: 16 }}>
        <div>
          <div className="label">Claimable (refunded bonds + bounties)</div>
          <div className="bond-value" style={{ marginTop: 4 }}>
            {error ? '—' : loading && claimable === null ? '…' : `${claimable ?? '0.0000'} GEN`}
          </div>
          {error && <p className="help" style={{ marginTop: 6, color: 'var(--hemolysis, #c45c52)' }}>{error}</p>}
        </div>
        <button
          type="button"
          className="btn btn-cytoplasm"
          onClick={handleWithdraw}
          disabled={!hasClaimable || withdrawing}
        >
          {withdrawing ? <Loader2 size={15} className="spin" /> : <Coins size={15} aria-hidden="true" />}
          {withdrawing ? 'Withdrawing…' : 'Withdraw'}
        </button>
      </div>
      <p className="help" style={{ marginTop: 10 }}>
        Withdrawals settle on <span className="mono">finalized</span> consensus via the contract's pull-payment
        pattern. Bonds and bounties won on a <em>quarantine</em> verdict do not land here straight away — the
        contract holds them in escrow for the length of the challenge window, so a disputed payout can still be
        slashed if an appeal succeeds. Once the window closes with no appeal pending, <em>Claim payout</em> releases
        the escrow here. <em>Expire incident</em> closes an incident whose clock has run out: it refunds a report
        that was never evaluated, refunds a stalled appeal, or settles and closes a standing verdict.
      </p>

      <div className="stack" style={{ gap: 10, marginTop: 18 }}>
        <label className="label" htmlFor="settle-report">Settle an incident</label>
        <div className="cluster" style={{ gap: 8 }}>
          <input
            id="settle-report"
            className="input mono"
            style={{ flex: 1, minWidth: 0 }}
            value={incidentId}
            onChange={(e) => {
              setIncidentId(e.target.value);
              setIncident(null);
            }}
            placeholder="report id"
          />
          <button
            type="button"
            className="icon-btn"
            aria-label="Look up incident"
            onClick={() => void lookupIncident()}
            disabled={!incidentId.trim() || settling !== null}
          >
            {settling === 'lookup' ? <Loader2 size={14} className="spin" /> : <Search size={14} />}
          </button>
        </div>
        {incident && (
          <p className="help mono">
            {incident.report.state} · {incident.report.exploit_category || '—'} · escrow {incident.escrow.status}
            {incident.escrow.exists && incident.escrow.locked_until_utc > 0 &&
              ` · challenge deadline ${formatIso(incident.escrow.locked_until_iso)}`}
          </p>
        )}
        {incidentError && (
          <p className="help" style={{ color: 'var(--hemolysis, #c45c52)' }}>{incidentError}</p>
        )}
        <div className="cluster" style={{ gap: 8 }}>
          <button
            type="button"
            className="btn btn-cytoplasm"
            onClick={() => void settle('claim')}
            disabled={!incidentId.trim() || settling !== null || (incident !== null && !incident.escrow.is_releasable)}
          >
            {settling === 'claim' ? <Loader2 size={15} className="spin" /> : <Coins size={15} aria-hidden="true" />}
            Claim payout
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => void settle('expire')}
            disabled={!incidentId.trim() || settling !== null}
          >
            {settling === 'expire' && <Loader2 size={15} className="spin" />}
            Expire incident
          </button>
        </div>
      </div>
    </section>
  );
}
