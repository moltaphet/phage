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
  import.meta.env?.VITE_PHAGE_CONTRACT_ADDRESS || '0x86a3C3d3B35BD6eF5f0D947EB49a553b8200bd80';
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
// `contracts/phage_sentinel.py`. All three resolve to a live public indexer, and
// each one carries an identifier the contract can check against the reported
// target before any model reads the payload:
//
//   EVM_TX / EVM_TX_BASE  a transaction hash on Ethereum / Base; the target must
//                         appear as a participant of that transaction.
//   EVM_ADDRESS           the target's own address; the trace_id *is* the target,
//                         so the record is the target's by construction.
//
// Anything else is refused by the contract's `[EXPECTED] invalid platform` guard.
export const VALID_PLATFORMS = ['EVM_TX', 'EVM_TX_BASE', 'EVM_ADDRESS'] as const;
export type Platform = (typeof VALID_PLATFORMS)[number];

/** Human-readable labels for the evidence picker, keyed by platform. */
export const PLATFORM_LABELS: Record<Platform, string> = {
  EVM_TX: 'EVM_TX — Ethereum transaction',
  EVM_TX_BASE: 'EVM_TX_BASE — Base transaction',
  EVM_ADDRESS: 'EVM_ADDRESS — the target address itself',
};

/**
 * What the evidence identifier must look like for a platform. The contract
 * enforces these exactly; mirroring them here turns a rejected transaction into
 * an inline form error instead.
 */
export const PLATFORM_IDENTIFIER_HINT: Record<Platform, string> = {
  EVM_TX: '0x-prefixed 32-byte transaction hash the target is a party to',
  EVM_TX_BASE: '0x-prefixed 32-byte transaction hash the target is a party to',
  EVM_ADDRESS: 'the reported target address (must match it exactly)',
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
  /** Bond + bounty held in escrow against quarantines still under appeal. */
  locked_escrow_gen: string;
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

/**
 * Disputed value held against a report whose verdict quarantined the target.
 *
 * A quarantine verdict does not pay the reporter immediately: the bond and
 * bounty go into an escrow locked for the length of the quarantine, and the
 * appeal window is exactly that period. So the money a malicious reporter would
 * otherwise front-run an appeal to withdraw is never in their hands while the
 * appeal can still reverse it — it is settled by whichever way the appeal goes,
 * or released to the reporter once the window closes unopposed.
 */
export type EscrowStatus = 'NONE' | 'LOCKED' | 'RELEASED' | 'SLASHED';

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
}

export function explorerAddressUrl(address: string): string {
  return `${STUDIONET_EXPLORER}/address/${address}`;
}

export function explorerTxUrl(txHash: string): string {
  return `${STUDIONET_EXPLORER}/tx/${txHash}`;
}
