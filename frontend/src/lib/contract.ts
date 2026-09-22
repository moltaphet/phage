// GenLayer Studio-dev network configuration (chain 61997), matching the deployed
// PhageSentinel intelligent contract. Every value the UI renders is read from —
// and every action it takes is written to — this on-chain deployment. There is
// no local simulation, seeded ledger, or fabricated consensus anywhere in the app.

import { studioDevnet } from 'genlayer-js/chains';

// The verified studio-dev deployment. Overridable per environment so a redeploy is a
// config change (Vercel env var) rather than a code change; the literal stays the
// default so a missing variable can never silently point the app at nothing.
//
// `import.meta.env` is injected by Vite and is absent under plain Node, where the live
// test suites in `scripts/` import this module directly — hence the optional chaining
// rather than a bare property read.
export const PHAGE_CONTRACT_ADDRESS =
  import.meta.env?.VITE_PHAGE_CONTRACT_ADDRESS || '0x038d5Fd5082Cb05586C4C7CBcdDE827AC7f6BBa1';
export const STUDIONET_RPC = 'https://studio-dev.genlayer.com/api';
export const STUDIONET_CHAIN_ID = 61997;
// 61997 == 0xf22d — the hex chainId MetaMask expects for wallet_switch/addEthereumChain.
export const STUDIONET_CHAIN_ID_HEX = '0xf22d';
export const STUDIONET_CHAIN_NAME = 'GenLayer Studio-dev';
export const STUDIONET_EXPLORER = 'https://explorer-studio-dev.genlayer.com';
export const STUDIO_WEB = 'https://studio-dev.genlayer.com';
export const GEN_CURRENCY = { name: 'GenLayer', symbol: 'GEN', decimals: 18 } as const;

// studio-dev runs the Consensus v0.6 release-candidate stack, which speaks a
// different `gen_call` calldata encoding than the stable 61999 studionet. The
// matching client ships this network as `studioDevnet`; consuming its definition
// wholesale (rather than retargeting the stable `studionet` object) keeps chain
// identity, consensus addresses, and encoding travelling together, as the v0.6
// migration requires. Running a stable genlayer-js here fails every read with a
// bare `execution failed` / `malformed_entry` from the node.
export const STUDIO_DEV_CHAIN = studioDevnet;

// Discrete threat tiers mirrored from the contract (contracts/phage_sentinel.py).
export const TIER_PATHOGEN_CRITICAL = 'TIER_PATHOGEN_CRITICAL';
export const TIER_SUSPICIOUS_ANOMALY = 'TIER_SUSPICIOUS_ANOMALY';
export const TIER_BENIGN_NOISE = 'TIER_BENIGN_NOISE';
export const TIER_FABRICATED_ATTACK = 'TIER_FABRICATED_ATTACK';

// Telemetry platforms the contract will accept, mirrored from
// `contracts/phage_sentinel.py`. Evidence is always one incident: a transaction on
// Ethereum or Base, fetched from Blockscout (eth. / base.blockscout.com). When the
// report is filed the contract fetches it and requires that it echoes the cited
// hash and names the target as its sender, recipient or created contract;
// otherwise the filing reverts with ERR_UNBOUND_EVIDENCE and no bond is taken.
//
// Anything else is refused by the contract's `[EXPECTED] invalid platform` guard.
export const VALID_PLATFORMS = ['EVM_TX', 'EVM_TX_BASE'] as const;
export type Platform = (typeof VALID_PLATFORMS)[number];

/** Human-readable labels for the evidence picker, keyed by platform. */
export const PLATFORM_LABELS: Record<Platform, string> = {
  EVM_TX: 'EVM_TX — Ethereum transaction',
  EVM_TX_BASE: 'EVM_TX_BASE — Base transaction',
};

/**
 * What the evidence identifier must look like for a platform. The contract
 * enforces these exactly; mirroring them here turns a rejected transaction into
 * an inline form error instead.
 */
export const PLATFORM_IDENTIFIER_HINT: Record<Platform, string> = {
  EVM_TX: '0x-prefixed 32-byte transaction hash the target is a party to',
  EVM_TX_BASE: '0x-prefixed 32-byte transaction hash the target is a party to',
};

/** Hosts the platforms resolve to — the only telemetry sources the contract reads. */
export const PLATFORM_SOURCE: Record<Platform, string> = {
  EVM_TX: 'eth.blockscout.com',
  EVM_TX_BASE: 'base.blockscout.com',
};

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
  /** Bond + bounty held in escrow against quarantine verdicts still disputable. */
  locked_escrow_gen: string;
  /** Appeal bonds filed and awaiting resolve_appeal. */
  pending_appeal_bonds_gen: string;
  total_escrows: number;
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
  /** The target's proven role in the cited transaction: from / to / created_contract. */
  evidence_binding: string;
  bond_amount_gen: string;
  state: 'PENDING' | 'RESOLVED' | 'UNDER_APPEAL' | 'OVERTURNED' | 'EXPIRED';
  evaluated_tier: string;
  quarantine_seconds: number;
  bounty_payout_gen: string;
  timestamp_utc: number;
  timestamp_iso: string;
  seq: number;
}

export interface AppealRecord {
  appeal_id: string;
  report_id: string;
  target_agent: string;
  appellant: string;
  appeal_bond_gen: string;
  proof_trace_id: string;
  platform: string;
  resolved_tier: string;
  state: 'PENDING' | 'UPHELD' | 'REJECTED' | 'EXPIRED';
  timestamp_iso: string;
}

export interface ProtocolState {
  stats: ProtocolStats;
  quarantinedAgents: QuarantineInfo[];
  antibodies: Antibody[];
  reports: PathogenReport[];
}

/**
 * Disputed value held against a report whose verdict quarantined the target.
 *
 * A quarantine verdict does not pay the reporter: the bond and bounty go into an
 * escrow that is appealable until `locked_until_utc`. Filing an appeal moves it
 * to UNDER_APPEAL, where nothing can be paid out (claim_payout reverts with
 * ERR_PAYOUT_LOCKED) until resolve_appeal lands. Upheld → SLASHED; rejected →
 * back to LOCKED with the window kept open a further 24h; window closed with no
 * appeal pending → claim_payout releases it to the reporter.
 */
export type EscrowStatus = 'NONE' | 'LOCKED' | 'UNDER_APPEAL' | 'RELEASED' | 'SLASHED';

export interface EscrowRecord {
  report_id: string;
  exists: boolean;
  target_agent: string;
  reporter: string;
  bond_gen: string;
  payout_gen: string;
  /** Unix seconds until which the escrow cannot be released. */
  locked_until_utc: number;
  locked_until_iso: string;
  status: EscrowStatus;
  created_at_utc: number;
  /** The lock has expired and the reporter's funds are claimable right now. */
  is_releasable: boolean;
  /** An appeal can be filed against this report right now. */
  is_appealable: boolean;
  failed_appeals: number;
  active_appeal_id: string;
  /** 0.2 GEN, scaled by the number of rejected appeals on this report. */
  required_appeal_bond_atto: string;
}

export function explorerAddressUrl(address: string): string {
  return `${STUDIONET_EXPLORER}/address/${address}`;
}

export function explorerTxUrl(txHash: string): string {
  return `${STUDIONET_EXPLORER}/tx/${txHash}`;
}
