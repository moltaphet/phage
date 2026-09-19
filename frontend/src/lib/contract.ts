// GenLayer Studio-dev network configuration (chain 61997), matching the deployed
// PhageSentinel intelligent contract. Every value the UI renders is read from —
// and every action it takes is written to — this on-chain deployment. There is
// no local simulation, seeded ledger, or fabricated consensus anywhere in the app.

import { studionet } from 'genlayer-js/chains';

export const PHAGE_CONTRACT_ADDRESS = '0xf21E61613F10341a565B9c20298C64d3764A92CB';
export const STUDIONET_RPC = 'https://studio-dev.genlayer.com/api';
export const STUDIONET_CHAIN_ID = 61997;
// 61997 == 0xf22d — the hex chainId MetaMask expects for wallet_switch/addEthereumChain.
export const STUDIONET_CHAIN_ID_HEX = '0xf22d';
export const STUDIONET_CHAIN_NAME = 'GenLayer Studio-dev';
export const STUDIONET_EXPLORER = 'https://explorer-studio-dev.genlayer.com';
export const STUDIO_WEB = 'https://studio-dev.genlayer.com';
export const GEN_CURRENCY = { name: 'GenLayer', symbol: 'GEN', decimals: 18 } as const;

// The genlayer-js `studionet` chain targets studio.genlayer.com (chain 61999). We
// reuse its consensus/staking wiring but retarget the id, name, RPC, and explorer
// at the studio-dev deployment the contract actually lives on. A fresh rpcUrls
// object is critical: createClient mutates chain.rpcUrls.default.http when an
// `endpoint` is supplied, and we must not clobber the shared studionet singleton.
export const STUDIO_DEV_CHAIN = {
  ...studionet,
  id: STUDIONET_CHAIN_ID,
  name: STUDIONET_CHAIN_NAME,
  rpcUrls: { default: { http: [STUDIONET_RPC] } },
  blockExplorers: {
    default: { name: 'GenLayer Explorer', url: STUDIONET_EXPLORER },
  },
};

// Discrete threat tiers mirrored from the contract (contracts/phage_sentinel.py).
export const TIER_PATHOGEN_CRITICAL = 'TIER_PATHOGEN_CRITICAL';
export const TIER_SUSPICIOUS_ANOMALY = 'TIER_SUSPICIOUS_ANOMALY';
export const TIER_BENIGN_NOISE = 'TIER_BENIGN_NOISE';
export const TIER_FABRICATED_ATTACK = 'TIER_FABRICATED_ATTACK';

export const VALID_PLATFORMS = ['AGENT_RPC', 'TX_TRACE', 'SECURITY_FEED', 'GITHUB_AUDIT'] as const;
export type Platform = (typeof VALID_PLATFORMS)[number];

// ---------------------------------------------------------------------------
// UI-facing types. Every field is projected directly from a contract view; the
// `_gen` fields are attoToGen conversions of the u256 strings the contract emits.
// ---------------------------------------------------------------------------
export interface ProtocolStats {
  owner: string;
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
  reporter: string;
}

export interface PathogenReport {
  report_id: string;
  reporter: string;
  target_agent: string;
  platform: string;
  trace_id: string;
  bond_amount_gen: string;
  state: 'PENDING' | 'RESOLVED' | 'EXPIRED';
  evaluated_tier: string;
  quarantine_seconds: number;
  bounty_payout_gen: string;
  timestamp_utc: number;
  timestamp_iso: string;
  seq: number;
}

export interface AppealRecord {
  appeal_id: string;
  target_agent: string;
  appellant: string;
  appeal_bond_gen: string;
  proof_trace_id: string;
  platform: string;
  resolved_tier: string;
  state: 'PENDING' | 'UPHELD' | 'REJECTED';
  timestamp_iso: string;
}

export interface ProtocolState {
  stats: ProtocolStats;
  quarantinedAgents: QuarantineInfo[];
  antibodies: Antibody[];
  reports: PathogenReport[];
}

export function explorerAddressUrl(address: string): string {
  return `${STUDIONET_EXPLORER}/address/${address}`;
}

export function explorerTxUrl(txHash: string): string {
  return `${STUDIONET_EXPLORER}/tx/${txHash}`;
}
