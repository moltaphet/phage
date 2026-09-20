// -----------------------------------------------------------------------------
// Error humanisation for GenLayer RPC failures.
//
// viem classifies every JSON-RPC failure in the -32000..-32099 range as
// `InvalidInputRpcError` and stamps it with the canned message
// "Missing or invalid parameters. Double check you have provided the correct
// parameters." That string describes a *client* mistake, so it is actively
// misleading for read calls whose parameters are provably correct — the far more
// common case is that the node accepted the call and the contract failed to run.
//
// The real cause is carried in the RPC error's `data.receipt`:
//   { execution_result: "ERROR", result: "<base64>", gas_used: 0 }
// where `result` decodes to a length/version-prefixed GenVM error string, e.g.
//   "AmludmFsaWRfY29udHJhY3QgcnVubmVyIG1hbGZvcm1lZA==" -> "invalid_contract runner malformed"
// This module unwraps that so the UI reports what actually happened.
// -----------------------------------------------------------------------------

// Decode the base64 `result` payload from a GenVM receipt into its error string.
// The payload is a borsh-style blob: a leading tag byte followed by UTF-8 text.
function decodeGenvmPayload(encoded: unknown): string | null {
  if (typeof encoded !== 'string' || !encoded) return null;
  try {
    const binary = atob(encoded);
    // Drop leading non-printable framing bytes; GenVM tags errors with 0x02.
    let text = '';
    for (const char of binary) {
      const code = char.charCodeAt(0);
      if (code >= 0x20 && code < 0x7f) text += char;
      else if (text) break;
    }
    return text.trim() || null;
  } catch {
    return null;
  }
}

// Walk viem's error chain (it nests the RPC payload under `cause`/`data`).
function findReceipt(err: unknown, depth = 0): Record<string, unknown> | null {
  if (!err || typeof err !== 'object' || depth > 6) return null;
  const record = err as Record<string, unknown>;
  const data = record.data as Record<string, unknown> | undefined;
  const receipt = (data?.receipt ?? record.receipt) as Record<string, unknown> | undefined;
  if (receipt && typeof receipt === 'object') return receipt;
  return findReceipt(record.cause, depth + 1) ?? findReceipt(data, depth + 1);
}

const CAUSE_LABELS: Record<string, string> = {
  malformed_entry: 'the contract’s on-chain state cannot be decoded by this node',
  'invalid_contract runner malformed':
    'this node cannot load the contract’s declared py-genlayer runner',
};

// Turn any thrown value into one actionable sentence naming the real cause.
export function describeError(err: unknown): string {
  if (err && typeof err === 'object') {
    const record = err as {
      cause?: unknown;
      data?: unknown;
      details?: unknown;
      message?: unknown;
      shortMessage?: unknown;
      result_name?: unknown;
      txExecutionResultName?: unknown;
    };

    const receipt = findReceipt(err);
    const payload = decodeGenvmPayload(receipt?.result);
    const executionResult = typeof receipt?.execution_result === 'string' ? receipt.execution_result : null;
    if (payload) {
      const label = CAUSE_LABELS[payload];
      return label
        ? `Contract execution failed — ${label} (${payload}).`
        : `Contract execution failed: ${payload}.`;
    }

    // A settled-but-failed transaction: consensus accepted it, execution did not.
    const execution = typeof record.txExecutionResultName === 'string' ? record.txExecutionResultName : null;
    if (execution && execution !== 'FINISHED_WITH_RETURN') {
      const outcome = typeof record.result_name === 'string' ? ` (${record.result_name})` : '';
      const detail = execution === 'FINISHED_WITH_ERROR' ? 'the contract call reverted' : 'execution did not complete';
      return `Transaction ${execution}${outcome} — ${detail}.`;
    }

    // The RPC error's own `data.message` is descriptive when present; viem buries
    // the original under `cause.message`, so prefer that over its canned wrapper.
    const cause = record.cause as { message?: unknown } | undefined;
    if (typeof cause?.message === 'string' && cause.message) return cause.message;

    const data = record.data as { message?: unknown } | undefined;
    if (typeof data?.message === 'string' && data.message) return data.message;

    if (executionResult === 'ERROR') return 'Contract execution failed on the GenLayer node.';
    if (typeof record.details === 'string' && record.details) return record.details;
    if (typeof record.shortMessage === 'string' && record.shortMessage) return record.shortMessage;
    if (typeof record.message === 'string' && record.message) return record.message.split('\n')[0];
  }
  return 'Transaction failed.';
}
