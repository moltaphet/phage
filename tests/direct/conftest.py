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


def tx_body(tx_hash_: str, from_addr=None, to_addr=None, created=None, status: str = "ok"):
    """A Blockscout-shaped transaction body, matching the real API's field names."""
    node = lambda a: {"hash": addr_hex(a)} if a is not None else None
    return {
        "hash": tx_hash_,
        "status": status,
        "result": "success" if status == "ok" else "failure",
        "from": node(from_addr),
        "to": node(to_addr),
        "created_contract": node(created),
        "value": "0",
        "decoded_input": None,
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


def serve_incident(direct_vm, target, role: str = "from", status: str = "ok", extra=None):
    """Serve a bound incident for *whatever* transaction hash is requested.

    The contract requires the telemetry to echo the cited hash and to name the target as
    a party, so a fixed body cannot serve several reports or an appeal at once. This
    installs the harness's fallback web handler, which reads the hash from the URL and
    answers with a Blockscout-shaped transaction in which `target` plays `role`
    ("from", "to" or "created_contract"). `extra` fields are merged into the body.
    """
    _reset_web_mocks(direct_vm)
    target_hex = addr_hex(target)

    def handler(data):
        requested = str(data.get("url", "")).rstrip("/").rsplit("/", 1)[-1]
        body = tx_body(
            requested,
            from_addr=target_hex if role == "from" else OTHER_PARTY,
            to_addr=target_hex if role == "to" else None,
            created=target_hex if role == "created_contract" else None,
            status=status,
        )
        body.update(extra or {})
        return {"ok": {"response": {
            "status": 200,
            "headers": {},
            "body": json.dumps(body).encode("utf-8"),
        }}}

    direct_vm._live_web_handler = handler


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
    pathogen_type: str = "PROMPT_INJECTION",
    rationale: str = "Active exploit confirmed from forensic logs.",
):
    _replace_llm_mock(
        direct_vm,
        PROMPT_PATTERN,
        # Double-encode: exec_prompt(response_format="json") needs a JSON *string*.
        # The direct harness deserializes one layer, so double-dumps yields text.
        json.dumps(json.dumps({
            "tier": tier,
            "pathogen_type": pathogen_type,
            "rationale": rationale,
        })),
    )


def mock_appeal_verdict(
    direct_vm,
    tier: str = "TIER_BENIGN_NOISE",
    rationale: str = "Target proof verifies completely benign operation.",
):
    _replace_llm_mock(
        direct_vm,
        APPEAL_PROMPT_PATTERN,
        # Double-encode: exec_prompt(response_format="json") needs a JSON *string*.
        # The direct harness deserializes one layer, so double-dumps yields text.
        json.dumps(json.dumps({
            "tier": tier,
            "rationale": rationale,
        })),
    )
