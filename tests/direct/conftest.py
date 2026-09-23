import hashlib
import json
import pytest

CONTRACT_PATH = "contracts/phage_sentinel.py"
PROMPT_PATTERN = r".*Security Triage Sentinel.*"
APPEAL_PROMPT_PATTERN = r".*Appeals Arbiter.*"

ATTO = 10**18
MIN_REPORTER_BOND = ATTO // 10
APPEAL_BOND = 2 * MIN_REPORTER_BOND
BASE_BOUNTY_REWARD = 1 * ATTO

# The category the general suite files under. The default transaction body served by
# these helpers carries a flash-loan borrow-and-repay, so it satisfies this category's
# mechanics check; tests of the other categories build their own evidence.
DEFAULT_CATEGORY = "FLASH_LOAN_DRAIN"
ERR_UNSUPPORTED_CATEGORY = (
    "ERR_UNSUPPORTED_EXPLOIT_CATEGORY: evidence does not support claimed exploit classification"
)

# Addresses that are never test accounts: a flash lender and a token contract.
LENDER = "0x" + "1a" * 20
TOKEN = "0x" + "70" * 20

# A rebuttal long enough to satisfy the contract's minimum justification length.
JUSTIFICATION = "Authorised treasury rebalance executed by the protocol's admin key."


def addr_hex(addr) -> str:
    """Hex form of a test address.

    The harness hands out raw 20-byte `bytes` when the SDK's `Address` type is not
    importable, and an `Address` when it is -- accept either, plus a hex string.
    """
    if isinstance(addr, str):
        return addr
    if isinstance(addr, (bytes, bytearray)):
        return "0x" + bytes(addr).hex()
    as_hex = getattr(addr, "as_hex", None)
    if isinstance(as_hex, str):
        return as_hex
    raw = getattr(addr, "address", None)
    if isinstance(raw, (bytes, bytearray)):
        return "0x" + bytes(raw).hex()
    return str(addr)


def tx_hash(seed: str) -> str:
    """A deterministic 32-byte transaction hash, for use as an EVM_TX trace."""
    return "0x" + hashlib.sha256(seed.encode()).hexdigest()


def token_transfer(src, dst, token=TOKEN, value="1000"):
    """One Blockscout `token_transfers` entry."""
    return {
        "token": {"address_hash": token, "symbol": "TKN"},
        "from": {"hash": addr_hex(src)},
        "to": {"hash": addr_hex(dst)},
        "total": {"value": value},
    }


def flash_loan_transfers(borrower):
    """A borrow from LENDER to `borrower` and its repayment, in one transaction."""
    return [token_transfer(LENDER, borrower), token_transfer(borrower, LENDER, value="1001")]


def tx_body(tx_hash_: str, from_addr=None, to_addr=None, created=None, status: str = "ok"):
    """A Blockscout-shaped transaction body, matching the real API's field names.

    Carries a flash-loan borrow-and-repay through the sender by default, so it meets the
    DEFAULT_CATEGORY mechanics check.
    """
    node = lambda a: {"hash": addr_hex(a)} if a is not None else None
    borrower = from_addr if from_addr is not None else OTHER_PARTY
    return {
        "hash": tx_hash_,
        "status": status,
        "result": "success" if status == "ok" else "failure",
        "from": node(from_addr),
        "to": node(to_addr),
        "created_contract": node(created),
        "value": "0",
        "decoded_input": None,
        "raw_input": "0x",
        "token_transfers": flash_loan_transfers(borrower),
    }


def _reset_web_mocks(direct_vm) -> None:
    """Drop previously registered web mocks.

    Every telemetry mock in this suite uses the catch-all pattern, and the harness
    resolves mocks first-match-wins, so without this a second mock is unreachable and
    the test silently reads the previous response. Registering a mock means "this is
    what the next call sees" -- so make that true.
    """
    direct_vm._web_mocks.clear()
    direct_vm._web_mocks_hit.clear()
    direct_vm._live_web_handler = None


def serve_incident(
    direct_vm, target, role: str = "from", status: str = "ok", extra=None, internal_calls=None,
    transfer_page=None,
):
    """Serve a bound incident for *whatever* transaction hash is requested.

    The contract requires the telemetry to echo the cited hash and to name the target as
    a party, so a fixed body cannot serve several reports or an appeal at once. This
    installs the harness's fallback web handler, which reads the hash from the URL and
    answers with a Blockscout-shaped transaction in which `target` plays `role`
    ("from", "to" or "created_contract"). `extra` fields are merged into the body.

    A request for the transaction's `/internal-transactions` page is answered with
    `internal_calls` -- `(from, to)` pairs in execution order -- and a request for its
    `/token-transfers` page with `transfer_page` (a list of `token_transfer` entries).
    Returns the list of URLs requested, so a test can assert exactly which evidence the
    contract fetched.
    """
    _reset_web_mocks(direct_vm)
    target_hex = addr_hex(target)
    requested_urls = []

    def respond(body):
        return {"ok": {"response": {
            "status": 200,
            "headers": {},
            "body": json.dumps(body).encode("utf-8"),
        }}}

    def handler(data):
        url = str(data.get("url", "")).rstrip("/")
        requested_urls.append(url)
        if url.endswith("/internal-transactions"):
            return respond({"items": [
                {"index": i, "type": "call", "success": True,
                 "from": {"hash": addr_hex(src)}, "to": {"hash": addr_hex(dst)}}
                for i, (src, dst) in enumerate(internal_calls or [])
            ], "next_page_params": None})
        if url.endswith("/token-transfers"):
            return respond({"items": [
                dict(t, log_index=i) for i, t in enumerate(transfer_page or [])
            ], "next_page_params": None})
        requested = url.rsplit("/", 1)[-1]
        body = tx_body(
            requested,
            from_addr=target_hex if role == "from" else OTHER_PARTY,
            to_addr=target_hex if role == "to" else None,
            created=target_hex if role == "created_contract" else None,
            status=status,
        )
        body.update(extra or {})
        return respond(body)

    direct_vm._live_web_handler = handler
    return requested_urls


# An address that is never a test account, used as the non-target party of a transaction.
OTHER_PARTY = "0x" + "0e" * 20


def mock_telemetry_success(direct_vm, body_dict: dict, target_hex=None):
    """Serve `body_dict`'s indicator fields inside a transaction bound to `target_hex`.

    Without `target_hex` the body is served verbatim, which is not a transaction naming
    the cited hash -- i.e. generic metadata that must fail the binding check.
    """
    if target_hex is not None:
        serve_incident(direct_vm, target_hex, extra=body_dict)
        return
    _reset_web_mocks(direct_vm)
    direct_vm.mock_web(
        r".*",
        {
            "status": 200,
            "body": json.dumps(body_dict),
        },
    )


def mock_tx_telemetry(direct_vm, body_dict: dict):
    """Serve a transaction payload verbatim (no target echo is injected)."""
    _reset_web_mocks(direct_vm)
    direct_vm.mock_web(
        r".*",
        {
            "status": 200,
            "body": json.dumps(body_dict),
        },
    )


def mock_telemetry_status(direct_vm, status: int, body: str = ""):
    _reset_web_mocks(direct_vm)
    direct_vm.mock_web(
        r".*",
        {
            "status": status,
            "body": body,
        },
    )


def _replace_llm_mock(direct_vm, pattern: str, response: str) -> None:
    """Register an LLM mock, dropping any earlier one for the same prompt pattern.

    LLM mocks are first-match-wins like web mocks, so without this a test that stubs a
    second verdict (e.g. an appeal after an earlier appeal) silently gets the first.
    """
    direct_vm._llm_mocks[:] = [m for m in direct_vm._llm_mocks if m[0].pattern != pattern]
    direct_vm._llm_mocks_hit.clear()
    direct_vm.mock_llm(pattern, response)


def mock_pathogen_verdict(
    direct_vm,
    tier: str = "TIER_PATHOGEN_CRITICAL",
    category_supported: bool = True,
    rationale: str = "Active exploit confirmed from forensic logs.",
):
    _replace_llm_mock(
        direct_vm,
        PROMPT_PATTERN,
        # Double-encode: exec_prompt(response_format="json") needs a JSON *string*.
        # The direct harness deserializes one layer, so double-dumps yields text.
        json.dumps(json.dumps({
            "tier": tier,
            "category_supported": category_supported,
            "rationale": rationale,
        })),
    )


def mock_appeal_verdict(
    direct_vm,
    tier: str = "TIER_BENIGN_NOISE",
    rebuts_original: bool = True,
    rationale: str = "The flagged transaction was authorised protocol execution.",
):
    _replace_llm_mock(
        direct_vm,
        APPEAL_PROMPT_PATTERN,
        # Double-encode: exec_prompt(response_format="json") needs a JSON *string*.
        # The direct harness deserializes one layer, so double-dumps yields text.
        json.dumps(json.dumps({
            "tier": tier,
            "rebuts_original": rebuts_original,
            "rationale": rationale,
        })),
    )
