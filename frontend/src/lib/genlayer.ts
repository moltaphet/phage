// -----------------------------------------------------------------------------
// GenLayer contract bridge.
//
// Every function here talks to the deployed PhageSentinel contract on GenLayer
// Studio-dev. Reads go through `gen_call` (readContract); writes are signed by the
// connected wallet via eth_sendTransaction and routed to the GenLayer consensus
// contract. Nothing in this module fabricates state — a failed read throws, and a
// failed/pending write surfaces its real transaction hash and receipt status.
// -----------------------------------------------------------------------------
import { createClient, isSuccessful } from 'genlayer-js';
import type { Eip1193Provider } from '../types/ethereum';

type Address = `0x${string}`;
import {
  PHAGE_CONTRACT_ADDRESS,
  STUDIONET_RPC,
  STUDIO_DEV_CHAIN,
  TIER_PATHOGEN_CRITICAL,
} from './contract';
import type {
  AppealRecord,
  Antibody,
  PathogenReport,
  ProtocolState,
  ProtocolStats,
  QuarantineInfo,
} from './contract';
import { attoToGen } from './format';
import { describeError } from './errors';

type GenClient = ReturnType<typeof createClient>;
type CalldataArg = string | number | bigint | boolean;

const ADDRESS = PHAGE_CONTRACT_ADDRESS as Address;

// A wallet-less client used for all view reads. gen_call only needs a `from`
// address (defaults to the zero address), so no signer is required to read state.
let readClient: GenClient | null = null;
function getReadClient(): GenClient {
  if (!readClient) {
    readClient = createClient({ chain: STUDIO_DEV_CHAIN, endpoint: STUDIONET_RPC });
  }
  return readClient;
}

// A wallet-bound client for writes. Passing the account as a plain address string
// makes genlayer-js route eth_sendTransaction to the injected provider (MetaMask),
// which prompts the user to sign; viem still parses it into an account object with
// `.address` for nonce/gas handling. Re-created whenever the active address changes.
let writeClient: GenClient | null = null;
let writeClientAddress: string | null = null;
export function getWriteClient(address: string, provider: Eip1193Provider): GenClient {
  if (!writeClient || writeClientAddress !== address.toLowerCase()) {
    writeClient = createClient({
      chain: STUDIO_DEV_CHAIN,
      endpoint: STUDIONET_RPC,
      account: address as Address,
      provider: provider as unknown as never,
    });
    writeClientAddress = address.toLowerCase();
  }
  return writeClient;
}

// ---------------------------------------------------------------------------
// Decoding helpers — genlayer-js decodes Python dicts to Map and ints to bigint.
// ---------------------------------------------------------------------------
function toRecord(value: unknown): Record<string, unknown> {
  if (value instanceof Map) return Object.fromEntries(value.entries());
  if (value && typeof value === 'object') return value as Record<string, unknown>;
  return {};
}

function asString(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'bigint') return value.toString();
  return String(value);
}

function asNumber(value: unknown): number {
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number') return value;
  const n = Number(value);
  return Number.isNaN(n) ? 0 : n;
}

function asBool(value: unknown): boolean {
  return value === true || value === 'true' || value === 1n || value === 1;
}

function isoFromUtc(seconds: number): string {
  if (!seconds) return 'N/A';
  return new Date(seconds * 1000).toISOString();
}

async function read(client: GenClient, functionName: string, args: CalldataArg[] = []): Promise<unknown> {
  return client.readContract({ address: ADDRESS, functionName, args });
}

// ---------------------------------------------------------------------------
// Mappers: contract view dict -> UI type.
// ---------------------------------------------------------------------------
function mapQuarantine(raw: unknown): QuarantineInfo {
  const r = toRecord(raw);
  const until = asNumber(r.quarantine_until_utc);
  const nowSec = Math.floor(Date.now() / 1000);
  const isActive = asBool(r.is_active) && until > nowSec;
  return {
    target_agent: asString(r.target_agent),
    is_active: isActive,
    quarantine_until_utc: until,
    quarantine_until_iso: isoFromUtc(until),
    reason_tier: asString(r.reason_tier) || 'NONE',
    last_report_id: asString(r.last_report_id),
    total_quarantines: asNumber(r.total_quarantines),
    antibody_hash: asString(r.antibody_hash) || 'NONE',
    defended_appeals: 0,
    current_required_bond_gen: '0.10',
  };
}

function mapAntibody(raw: unknown): Antibody {
  const r = toRecord(raw);
  const ts = asNumber(r.recorded_at_utc);
  const hash = asString(r.signature_hash);
  return {
    antibody_hash: hash,
    target_agent: asString(r.target_agent),
    platform: asString(r.platform),
    trace_id: asString(r.pathogen_type),
    pathogen_digest: hash ? `sha256:${hash.slice(0, 10)}…` : '',
    mint_timestamp_utc: ts,
    mint_timestamp_iso: isoFromUtc(ts),
    is_active: asBool(r.is_active),
    reporter: asString(r.reporter),
  };
}

function mapReport(raw: unknown): PathogenReport {
  const r = toRecord(raw);
  const ts = asNumber(r.created_at_utc);
  return {
    report_id: asString(r.report_id),
    reporter: asString(r.reporter),
    target_agent: asString(r.target_agent),
    platform: asString(r.platform),
    trace_id: asString(r.trace_id),
    bond_amount_gen: attoToGen(asString(r.bond_atto)),
    state: (asString(r.status) || 'PENDING') as PathogenReport['state'],
    evaluated_tier: asString(r.tier),
    quarantine_seconds: asNumber(r.quarantine_duration_sec),
    bounty_payout_gen: attoToGen(asString(r.payout_atto)),
    timestamp_utc: ts,
    timestamp_iso: isoFromUtc(ts),
    seq: asNumber(r.seq),
  };
}

function mapAppeal(raw: unknown): AppealRecord {
  const r = toRecord(raw);
  const ts = asNumber(r.resolved_at_utc) || asNumber(r.created_at_utc);
  return {
    appeal_id: asString(r.appeal_id),
    target_agent: asString(r.target_agent),
    appellant: asString(r.appellant),
    appeal_bond_gen: attoToGen(asString(r.bond_atto)),
    proof_trace_id: asString(r.appeal_proof_trace_id),
    platform: asString(r.platform),
    resolved_tier: asString(r.resolved_tier),
    state: (asString(r.status) || 'PENDING') as AppealRecord['state'],
    timestamp_iso: isoFromUtc(ts),
  };
}

// ---------------------------------------------------------------------------
// Aggregate live read used to hydrate the whole dashboard from chain state.
// ---------------------------------------------------------------------------
export async function loadProtocolState(): Promise<ProtocolState> {
  const client = getReadClient();
  const [overviewRaw, quarantinesRaw, antibodiesRaw, reportsRaw] = await Promise.all([
    read(client, 'get_registry_overview'),
    read(client, 'list_quarantined_agents_paginated', [0, 50]),
    read(client, 'list_antibodies_paginated', [0, 50]),
    read(client, 'list_reports_paginated', [0, 50]),
  ]);

  const overview = toRecord(overviewRaw);
  const quarantinedAgents = (Array.isArray(quarantinesRaw) ? quarantinesRaw : []).map(mapQuarantine);
  const antibodies = (Array.isArray(antibodiesRaw) ? antibodiesRaw : []).map(mapAntibody);
  const reports = (Array.isArray(reportsRaw) ? reportsRaw : []).map(mapReport);

  const activeQuarantines = quarantinedAgents.filter((q) => q.is_active).length;
  const evaluatedReports = reports.filter((r) => r.state === 'RESOLVED').length;
  const totalReports = asNumber(overview.total_reports) || reports.length;
  // Health is derived purely from real on-chain counts: the fewer live isolations
  // relative to total triaged reports, the healthier the swarm.
  const systemHealth =
    totalReports > 0
      ? Math.max(0, Math.min(100, Math.round(100 - (activeQuarantines / totalReports) * 100)))
      : 100;

  const stats: ProtocolStats = {
    owner: asString(overview.owner),
    bounty_pool_gen: attoToGen(asString(overview.bounty_pool_atto)),
    protocol_reserves_gen: attoToGen(asString(overview.protocol_reserves_atto)),
    total_deposited_gen: attoToGen(asString(overview.total_deposited_atto)),
    total_claimed_gen: attoToGen(asString(overview.total_claimed_atto)),
    total_quarantines_active: activeQuarantines,
    total_antibodies_minted: asNumber(overview.total_antibodies) || antibodies.length,
    total_reports_evaluated: evaluatedReports,
    total_appeals_processed: asNumber(overview.total_appeals),
    system_health_pct: systemHealth,
  };

  return { stats, quarantinedAgents, antibodies, reports };
}

// A single-agent live lookup enriched with defended-appeal count and required bond.
export async function inspectAgent(targetAgent: string): Promise<QuarantineInfo> {
  const client = getReadClient();
  const [infoRaw, defendedRaw, bondRaw, activeRaw] = await Promise.all([
    read(client, 'get_quarantine_info', [targetAgent]),
    read(client, 'get_defended_appeals_count', [targetAgent]),
    read(client, 'get_required_reporter_bond', [targetAgent]),
    read(client, 'is_quarantined', [targetAgent]),
  ]);
  const info = mapQuarantine(infoRaw);
  info.target_agent = info.target_agent || targetAgent;
  info.is_active = asBool(activeRaw);
  info.defended_appeals = asNumber(defendedRaw);
  info.current_required_bond_gen = attoToGen(asString(bondRaw));
  return info;
}

export async function getRequiredReporterBondGen(targetAgent: string): Promise<string> {
  const client = getReadClient();
  const bondRaw = await read(client, 'get_required_reporter_bond', [targetAgent]);
  return attoToGen(asString(bondRaw));
}

export async function getRequiredReporterBondAtto(targetAgent: string): Promise<bigint> {
  const client = getReadClient();
  const bondRaw = await read(client, 'get_required_reporter_bond', [targetAgent]);
  return BigInt(asString(bondRaw) || '0');
}

export async function getClaimableBalanceGen(account: string): Promise<string> {
  const client = getReadClient();
  const raw = await read(client, 'get_claimable_balance', [account]);
  return attoToGen(asString(raw));
}

export async function getReport(reportId: string): Promise<PathogenReport> {
  const client = getReadClient();
  return mapReport(await read(client, 'get_report', [reportId]));
}

export async function getAppeal(appealId: string): Promise<AppealRecord> {
  const client = getReadClient();
  return mapAppeal(await read(client, 'get_appeal', [appealId]));
}

export async function getTotalAppeals(): Promise<number> {
  const client = getReadClient();
  const overview = toRecord(await read(client, 'get_registry_overview'));
  return asNumber(overview.total_appeals);
}

// ---------------------------------------------------------------------------
// Writes. Each returns the real GenLayer transaction hash. Callers wait on the
// receipt via waitForReceipt before reading back the resulting on-chain state.
// ---------------------------------------------------------------------------
type WriteArgs = {
  functionName: string;
  args?: CalldataArg[];
  value?: bigint;
};

async function write(client: GenClient, { functionName, args = [], value = 0n }: WriteArgs): Promise<string> {
  // studio-dev sets no FeeManager, so genlayer-js has nothing to fall back on and
  // every write reverts at submit with `FeeValueMustBeNonZero(1)`. The fee must be
  // derived per call: `estimateTransactionFeesForWrite` simulates the call, prices
  // an execution budget above the chain's current floor, and returns the deposit to
  // attach. Deriving it per write rather than caching a constant keeps us correct if
  // the node's fee policy moves under us.
  const estimate = await client.estimateTransactionFeesForWrite({
    address: ADDRESS,
    functionName,
    args,
    value,
  });
  const hash = await client.writeContract({
    address: ADDRESS,
    functionName,
    args,
    value,
    fees: {
      distribution: estimate.distribution,
      messageAllocations: estimate.messageAllocations,
      feeValue: estimate.feeValue,
    },
  });
  return hash as string;
}

export function fundBountyPool(client: GenClient, valueAtto: bigint): Promise<string> {
  return write(client, { functionName: 'fund_bounty_pool', value: valueAtto });
}

export function reportPathogen(
  client: GenClient,
  params: { reportId: string; targetAgent: string; platform: string; traceId: string; bondAtto: bigint },
): Promise<string> {
  return write(client, {
    functionName: 'report_pathogen',
    args: [params.reportId, params.targetAgent, params.platform, params.traceId],
    value: params.bondAtto,
  });
}

export function evaluatePathogen(client: GenClient, reportId: string): Promise<string> {
  return write(client, { functionName: 'evaluate_pathogen', args: [reportId] });
}

export function appealQuarantine(
  client: GenClient,
  params: { targetAgent: string; proofTraceId: string; platform: string; bondAtto: bigint },
): Promise<string> {
  return write(client, {
    functionName: 'appeal_quarantine',
    args: [params.targetAgent, params.proofTraceId, params.platform],
    value: params.bondAtto,
  });
}

export function recoverAgent(client: GenClient, targetAgent: string): Promise<string> {
  return write(client, { functionName: 'recover_agent', args: [targetAgent] });
}

export function reclaimExpiredReportBond(client: GenClient, reportId: string): Promise<string> {
  return write(client, { functionName: 'reclaim_expired_report_bond', args: [reportId] });
}

export function withdraw(client: GenClient): Promise<string> {
  return write(client, { functionName: 'withdraw' });
}

// Await a GenLayer transaction receipt. On-chain LLM consensus (evaluate_pathogen /
// appeal_quarantine) can take a while, so we poll patiently rather than fabricate an
// outcome.
//
// Reaching ACCEPTED is not the same as succeeding: a transaction that finalizes with
// FINISHED_WITH_ERROR (a reverting call, a contract that failed to load) is still
// "accepted" by consensus, so waiting on status alone would report a failed write as
// a success. The v0.6 migration guide requires checking status *and* execution
// together — `isSuccessful` does both, and we rethrow its verdict as a real error so
// callers never read back stale state believing their write landed.
type ReceiptHash = Parameters<GenClient['waitForTransactionReceipt']>[0]['hash'];

export async function waitForReceipt(client: GenClient, hash: string): Promise<void> {
  const tx = await client.waitForTransactionReceipt({
    hash: hash as unknown as ReceiptHash,
    interval: 4000,
    retries: 45,
  });
  if (!isSuccessful(tx)) {
    throw new Error(describeError(tx));
  }
}

// Reconstruct the deterministic appeal id the contract assigns:
//   appeal_{target_hex[:10]}_{len(appeal_ids)+1}
// target_hex is the lowercase 0x-prefixed address; [:10] keeps 0x + 8 hex chars.
export function deriveAppealId(targetAgent: string, appealIndex: number): string {
  return `appeal_${targetAgent.toLowerCase().slice(0, 10)}_${appealIndex}`;
}

export function isCriticalTier(tier: string): boolean {
  return tier === TIER_PATHOGEN_CRITICAL;
}

export type { GenClient };
