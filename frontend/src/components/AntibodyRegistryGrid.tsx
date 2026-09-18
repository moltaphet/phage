import { useState } from 'react';
import { Check, Copy, ExternalLink, Search } from 'lucide-react';
import type { Antibody } from '../lib/contract';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_EXPLORER } from '../lib/contract';
import { formatIso, shortHex } from '../lib/format';

interface AntibodyRegistryGridProps {
  antibodies: Antibody[];
  onInspectAgent: (address: string) => void;
  loading: boolean;
}

export function AntibodyRegistryGrid({ antibodies, onInspectAgent, loading }: AntibodyRegistryGridProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'REVOKED'>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filtered = antibodies.filter((ab) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      ab.antibody_hash.toLowerCase().includes(q) ||
      ab.target_agent.toLowerCase().includes(q) ||
      ab.trace_id.toLowerCase().includes(q) ||
      ab.platform.toLowerCase().includes(q);
    const matchesStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'ACTIVE' && ab.is_active) ||
      (statusFilter === 'REVOKED' && !ab.is_active);
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="stack" style={{ gap: 20 }}>
      <div className="plate">
        <div className="plate-head">
          <div>
            <h2 className="section-title">Antibody registry</h2>
            <p className="section-copy">
              Cryptographic threat signatures minted after consensus. Integrated protocols query these hashes to refuse known exploit payloads.
            </p>
          </div>
          <span className="chip chip-ok">{antibodies.filter((a) => a.is_active).length} active</span>
        </div>
        <div className="cluster" style={{ gap: 10 }}>
          <div className="searchbar" style={{ flex: 1, minWidth: 220 }}>
            <Search size={14} color="#7d7464" aria-hidden="true" />
            <input
              className="input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search hash, agent, trace…"
              aria-label="Search antibodies"
            />
          </div>
          <div className="filter-row" role="group" aria-label="Status filter">
            {(['ALL', 'ACTIVE', 'REVOKED'] as const).map((status) => (
              <button
                key={status}
                type="button"
                className={statusFilter === status ? 'is-on' : ''}
                onClick={() => setStatusFilter(status)}
              >
                {status === 'ALL' ? `All (${antibodies.length})` : status === 'ACTIVE' ? 'Active' : 'Revoked'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && antibodies.length === 0 ? (
        <div className="empty">
          <h3 className="h3">Loading antibodies…</h3>
          <p className="help" style={{ marginTop: 8 }}>Reading the on-chain antibody registry.</p>
        </div>
      ) : antibodies.length === 0 ? (
        <div className="empty">
          <h3 className="h3">No antibodies minted yet</h3>
          <p className="help" style={{ marginTop: 8 }}>Antibodies are minted on-chain when consensus classifies a report as a critical pathogen.</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="empty">
          <h3 className="h3">No antibodies match</h3>
          <p className="help" style={{ marginTop: 8 }}>Try another hash, agent, or reset the filter.</p>
        </div>
      ) : (
        <div className="cards cards-3">
          {filtered.map((ab) => {
            const copiedHash = copiedId === `hash-${ab.antibody_hash}`;
            const copiedAgent = copiedId === `agent-${ab.antibody_hash}`;
            return (
              <article key={ab.antibody_hash} className={`ab-card${ab.is_active ? ' is-active' : ''}`}>
                <div>
                  <div className="cluster" style={{ justifyContent: 'space-between', marginBottom: 14 }}>
                    <span className={`chip ${ab.is_active ? 'chip-ok' : 'chip-mute'}`}>
                      {ab.is_active ? 'Active' : 'Revoked'}
                    </span>
                    <span className="chip">{ab.platform}</span>
                  </div>
                  <div className="label">Antibody digest</div>
                  <div className="hashbox" style={{ marginTop: 6 }}>
                    <span className="hash" style={{ flex: 1 }}>{shortHex(ab.antibody_hash, 18, 10)}</span>
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => handleCopy(ab.antibody_hash, `hash-${ab.antibody_hash}`)}
                      aria-label="Copy antibody hash"
                    >
                      {copiedHash ? <Check size={14} /> : <Copy size={14} />}
                    </button>
                  </div>
                  <div style={{ marginTop: 14 }}>
                    <div className="label">Target neutralized</div>
                    <div className="cluster" style={{ justifyContent: 'space-between', marginTop: 4 }}>
                      <span className="hash">{shortHex(ab.target_agent, 10, 6)}</span>
                      <div className="cluster" style={{ gap: 4 }}>
                        <button
                          type="button"
                          className="icon-btn"
                          onClick={() => handleCopy(ab.target_agent, `agent-${ab.antibody_hash}`)}
                          aria-label="Copy agent address"
                        >
                          {copiedAgent ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                        <button type="button" className="btn btn-ghost" style={{ minHeight: 32, fontSize: 12, padding: '0 10px' }} onClick={() => onInspectAgent(ab.target_agent)}>
                          Inspect
                        </button>
                      </div>
                    </div>
                  </div>
                  <div style={{ marginTop: 12 }}>
                    <div className="label">Telemetry trace</div>
                    <p className="hash" style={{ marginTop: 4, color: 'var(--filament-dim)' }}>{ab.trace_id}</p>
                  </div>
                </div>
                <div className="cluster" style={{ justifyContent: 'space-between', marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--line)' }}>
                  <span className="help">Minted {formatIso(ab.mint_timestamp_iso)}</span>
                  <a
                    href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="cluster"
                    style={{ gap: 4, fontSize: 12, color: 'var(--filament-mute)', textDecoration: 'none' }}
                  >
                    Contract <ExternalLink size={11} aria-hidden="true" />
                  </a>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
