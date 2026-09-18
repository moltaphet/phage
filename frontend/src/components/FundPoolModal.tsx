import { useState } from 'react';
import { Loader2, Wallet } from 'lucide-react';

interface FundPoolModalProps {
  isOpen: boolean;
  onClose: () => void;
  onFund: (amountGen: string) => Promise<void>;
  walletConnected: boolean;
  onConnectWallet: () => void;
}

const PRESETS = ['0.5', '1', '5'];

export function FundPoolModal({ isOpen, onClose, onFund, walletConnected, onConnectWallet }: FundPoolModalProps) {
  const [amount, setAmount] = useState('1');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFund = async () => {
    setError(null);
    const value = Number(amount);
    if (!Number.isFinite(value) || value <= 0) {
      setError('Enter an amount greater than zero.');
      return;
    }
    setSubmitting(true);
    try {
      await onFund(amount);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message.split('\n')[0] : 'Deposit failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="fund-title">
      <div className="modal" style={{ maxWidth: 460 }}>
        <div className="modal-head">
          <div>
            <h3 id="fund-title" className="h3">Fund the bounty pool</h3>
            <p className="help mono" style={{ marginTop: 4 }}>fund_bounty_pool · payable</p>
          </div>
        </div>

        <div className="modal-body">
          <p className="help">
            Deposit native GEN into the on-chain immune bounty pool. Funds reward verified pathogen
            reports and are held in the contract's escrow until claimed.
          </p>

          <div className="field" style={{ marginTop: 16 }}>
            <label className="label" htmlFor="fund-amount">Amount (GEN)</label>
            <input
              id="fund-amount"
              className="input mono"
              inputMode="decimal"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="1.0"
            />
          </div>

          <div className="cluster" style={{ gap: 8, marginTop: 10 }}>
            {PRESETS.map((preset) => (
              <button
                key={preset}
                type="button"
                className="btn btn-ghost"
                style={{ minHeight: 34, fontSize: 12 }}
                onClick={() => setAmount(preset)}
              >
                {preset} GEN
              </button>
            ))}
          </div>

          {error && (
            <div className="alert" role="alert" style={{ marginTop: 14 }}>
              <span>{error}</span>
            </div>
          )}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          {walletConnected ? (
            <button type="button" className="btn btn-stain" onClick={handleFund} disabled={submitting}>
              {submitting ? <Loader2 size={15} className="spin" /> : <Wallet size={15} aria-hidden="true" />}
              {submitting ? 'Confirm in wallet…' : `Deposit ${amount || '0'} GEN`}
            </button>
          ) : (
            <button type="button" className="btn btn-stain" onClick={onConnectWallet}>
              <Wallet size={15} aria-hidden="true" />
              Connect wallet
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
