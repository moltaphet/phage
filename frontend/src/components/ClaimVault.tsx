import { useCallback, useEffect, useState } from 'react';
import { Coins, Loader2, RefreshCw } from 'lucide-react';
import { getClaimableBalanceGen } from '../lib/genlayer';
import { describeError } from '../lib/errors';
import { shortHex } from '../lib/format';

interface ClaimVaultProps {
  address: string | null;
  walletConnected: boolean;
  // Bumps whenever an on-chain action may have changed the caller's balance.
  refreshKey: number;
  onWithdraw: () => Promise<void>;
}

export function ClaimVault({ address, walletConnected, refreshKey, onWithdraw }: ClaimVaultProps) {
  const [claimable, setClaimable] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [withdrawing, setWithdrawing] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        pattern, so slashed evaluations can never leak value out of escrow.
      </p>
    </section>
  );
}
