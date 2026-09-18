// GenLayer Studio-dev network configuration (chain 61997), matching the deployed contract.

export const PHAGE_CONTRACT_ADDRESS = "0x07A8d9e769019ccB49Ad2f8CE4e873ad7904D186";
export const STUDIONET_RPC = "https://studio-dev.genlayer.com/api";
export const STUDIONET_CHAIN_ID = 61997;
// 61997 == 0xf22d — the hex chainId MetaMask expects for wallet_switch/addEthereumChain.
export const STUDIONET_CHAIN_ID_HEX = "0xf22d";
export const STUDIONET_CHAIN_NAME = "GenLayer Studio-dev";
export const STUDIONET_EXPLORER = "https://explorer-studio-dev.genlayer.com";
export const STUDIO_WEB = "https://studio-dev.genlayer.com";
export const GEN_CURRENCY = { name: "GenLayer", symbol: "GEN", decimals: 18 } as const;

export interface ProtocolStats {
  bounty_pool_gen: string;
  protocol_reserves_gen: string;
  total_deposited_gen: string;
  total_claimed_gen: string;
  total_quarantines_active: number;
  total_antibodies_minted: number;
  total_reports_evaluated: number;
  total_appeals_processed: number;
  system_health_pct: number;
}

export interface QuarantineInfo {
  target_agent: string;
  is_active: boolean;
  quarantine_until_utc: number;
  quarantine_until_iso: string;
  reason_tier: string;
  last_report_id: string;
  total_quarantines: number;
  antibody_hash: string;
  defended_appeals: number;
  current_required_bond_gen: string;
}

export interface Antibody {
  antibody_hash: string;
  target_agent: string;
  platform: string;
  trace_id: string;
  pathogen_digest: string;
  mint_timestamp_utc: number;
  mint_timestamp_iso: string;
  is_active: boolean;
}

export interface PathogenReport {
  report_id: string;
  reporter: string;
  target_agent: string;
  platform: string;
  trace_id: string;
  bond_amount_gen: string;
  state: 'PENDING' | 'RESOLVED';
  evaluated_tier?: string;
  quarantine_seconds?: number;
  bounty_payout_gen?: string;
  timestamp_iso: string;
}

export interface AppealRecord {
  appeal_id: string;
  target_agent: string;
  appellant: string;
  appeal_bond_gen: string;
  proof_trace_id: string;
  platform: string;
  state: 'PENDING' | 'UPHELD' | 'REJECTED';
  timestamp_iso: string;
}

// Pre-seeded explorer data for the Studio-dev preview
export const INITIAL_STATS: ProtocolStats = {
  bounty_pool_gen: "25.00",
  protocol_reserves_gen: "8.40",
  total_deposited_gen: "33.40",
  total_claimed_gen: "6.20",
  total_quarantines_active: 3,
  total_antibodies_minted: 5,
  total_reports_evaluated: 18,
  total_appeals_processed: 4,
  system_health_pct: 99.8,
};

export const INITIAL_QUARANTINED_AGENTS: QuarantineInfo[] = [
  {
    target_agent: "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7",
    is_active: true,
    quarantine_until_utc: Date.now() / 1000 + 518400,
    quarantine_until_iso: new Date(Date.now() + 518400000).toISOString(),
    reason_tier: "TIER_PATHOGEN_CRITICAL",
    last_report_id: "REP-2026-0891",
    total_quarantines: 1,
    antibody_hash: "0x4b7c12d98a0e23f5109b8374d6c189e472093bf71239cba847291038472910fa",
    defended_appeals: 0,
    current_required_bond_gen: "0.10",
  },
  {
    target_agent: "0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE",
    is_active: true,
    quarantine_until_utc: Date.now() / 1000 + 64800,
    quarantine_until_iso: new Date(Date.now() + 64800000).toISOString(),
    reason_tier: "TIER_SUSPICIOUS_ANOMALY",
    last_report_id: "REP-2026-0894",
    total_quarantines: 2,
    antibody_hash: "0x98124a0b23fec918237461928374619283746192837461928374619283746192",
    defended_appeals: 1,
    current_required_bond_gen: "0.20",
  },
  {
    target_agent: "0xD533a949740bb3306d119CC777fa900bA034cd52",
    is_active: true,
    quarantine_until_utc: Date.now() / 1000 + 432000,
    quarantine_until_iso: new Date(Date.now() + 432000000).toISOString(),
    reason_tier: "TIER_PATHOGEN_CRITICAL",
    last_report_id: "REP-2026-0899",
    total_quarantines: 1,
    antibody_hash: "0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
    defended_appeals: 0,
    current_required_bond_gen: "0.10",
  }
];

export const INITIAL_ANTIBODIES: Antibody[] = [
  {
    antibody_hash: "0x4b7c12d98a0e23f5109b8374d6c189e472093bf71239cba847291038472910fa",
    target_agent: "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7",
    platform: "AGENT_RPC",
    trace_id: "rpc-payload-prompt-hijack-v3",
    pathogen_digest: "sha256:4a819b...ec81",
    mint_timestamp_utc: 1789128000,
    mint_timestamp_iso: "2026-09-11T14:20:00Z",
    is_active: true,
  },
  {
    antibody_hash: "0x98124a0b23fec918237461928374619283746192837461928374619283746192",
    target_agent: "0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE",
    platform: "TX_TRACE",
    trace_id: "tx-exploit-slippage-override-091",
    pathogen_digest: "sha256:7b1029...fa12",
    mint_timestamp_utc: 1789131600,
    mint_timestamp_iso: "2026-09-11T15:15:00Z",
    is_active: true,
  },
  {
    antibody_hash: "0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
    target_agent: "0xD533a949740bb3306d119CC777fa900bA034cd52",
    platform: "SECURITY_FEED",
    trace_id: "sec-alert-treasury-drain-attempt-44",
    pathogen_digest: "sha256:9c4412...018e",
    mint_timestamp_utc: 1789218000,
    mint_timestamp_iso: "2026-09-12T15:00:00Z",
    is_active: true,
  },
  {
    antibody_hash: "0x11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
    target_agent: "0x71C87050f443831F9Ac9B69B132b35a7455d5b7a",
    platform: "GITHUB_AUDIT",
    trace_id: "open-agent/agent-core-poisoned-commit-72a",
    pathogen_digest: "sha256:3d1982...b841",
    mint_timestamp_utc: 1789041600,
    mint_timestamp_iso: "2026-09-10T12:00:00Z",
    is_active: true,
  },
  {
    antibody_hash: "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    target_agent: "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    platform: "AGENT_RPC",
    trace_id: "rpc-exploit-jailbreak-sys-override",
    pathogen_digest: "sha256:1a2b3c...4d5e",
    mint_timestamp_utc: 1788955200,
    mint_timestamp_iso: "2026-09-09T12:00:00Z",
    is_active: false, // Revoked after upheld appeal!
  }
];
