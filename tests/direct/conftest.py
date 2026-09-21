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


def mock_telemetry_success(direct_vm, body_dict: dict, target_hex=None):
    """Serve `body_dict` as the telemetry response.

    Pass `target_hex` to make the payload a valid bound record for an EVM_ADDRESS
    report: the contract requires the response to echo the reported target, so an
    address report whose telemetry does not name the target is rejected as unbound.
    """
    payload = dict(body_dict)
    if target_hex is not None:
        payload["hash"] = addr_hex(target_hex)
    _reset_web_mocks(direct_vm)
    direct_vm.mock_web(
        r".*",
        {
            "status": 200,
            "body": json.dumps(payload),
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


def mock_pathogen_verdict(
    direct_vm,
    tier: str = "TIER_PATHOGEN_CRITICAL",
    pathogen_type: str = "PROMPT_INJECTION",
    rationale: str = "Active exploit confirmed from forensic logs.",
):
    direct_vm.mock_llm(
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
    direct_vm.mock_llm(
        APPEAL_PROMPT_PATTERN,
        # Double-encode: exec_prompt(response_format="json") needs a JSON *string*.
        # The direct harness deserializes one layer, so double-dumps yields text.
        json.dumps(json.dumps({
            "tier": tier,
            "rationale": rationale,
        })),
    )
