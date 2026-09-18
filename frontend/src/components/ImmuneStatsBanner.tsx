import type { ProtocolStats } from '../lib/contract';

interface ImmuneStatsBannerProps {
  stats: ProtocolStats;
  onFundPoolClick: () => void;
}

export function ImmuneStatsBanner({ stats, onFundPoolClick }: ImmuneStatsBannerProps) {
  return (
    <section className="strip" aria-label="Protocol telemetry">
      <div className="readout">
        <div className="readout-top">
          <span className="readout-label">Bounty pool</span>
          <button type="button" className="btn btn-ghost" style={{ minHeight: 32, padding: '0 10px', fontSize: 12 }} onClick={onFundPoolClick}>
            Fund
          </button>
        </div>
        <div>
          <span className="readout-value">{stats.bounty_pool_gen}</span>
          <span className="readout-unit">GEN</span>
        </div>
        <p className="readout-note">10% capped release per job</p>
      </div>

      <div className="readout">
        <div className="readout-top">
          <span className="readout-label">Reserves</span>
        </div>
        <div>
          <span className="readout-value">{stats.protocol_reserves_gen}</span>
          <span className="readout-unit">GEN</span>
        </div>
        <p className="readout-note">Slashed bonds · protocol insurance</p>
      </div>

      <div className="readout readout-iso">
        <div className="readout-top">
          <span className="readout-label">Quarantined</span>
        </div>
        <div>
          <span className="readout-value">{stats.total_quarantines_active}</span>
        </div>
        <p className="readout-note">Blocked by onlyHealthyAgent</p>
      </div>

      <div className="readout">
        <div className="readout-top">
          <span className="readout-label">Antibodies</span>
        </div>
        <div>
          <span className="readout-value">{stats.total_antibodies_minted}</span>
        </div>
        <p className="readout-note">SHA-256 threat fingerprints</p>
      </div>

      <div className="readout readout-ok">
        <div className="readout-top">
          <span className="readout-label">Inoculation</span>
        </div>
        <div>
          <span className="readout-value">{stats.system_health_pct}</span>
          <span className="readout-unit">%</span>
        </div>
        <p className="readout-note">{stats.total_reports_evaluated} reports evaluated</p>
      </div>
    </section>
  );
}
