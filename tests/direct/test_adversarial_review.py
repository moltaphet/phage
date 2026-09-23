"""Adversarial tests for the steward review of evidence, appeals, antibodies and payouts.

Each section attacks one requested property:

  1. a report cannot claim an exploit category its evidence does not exhibit;
  2. an appeal cannot overturn a report with some other, benign transaction;
  3. an antibody label cannot be persisted without validator agreement on it;
  4. a payout cannot be claimed early, and pays exactly what was escrowed;
  5. an incident whose clock runs out closes deterministically with its bonds settled.
"""

import datetime
import json

import pytest
from conftest import (
    CONTRACT_PATH,
    ATTO,
    MIN_REPORTER_BOND,
    APPEAL_BOND,
    BASE_BOUNTY_REWARD,
    JUSTIFICATION,
    APPEAL_PROMPT_PATTERN,
    ERR_UNSUPPORTED_CATEGORY,
    LENDER,
    TOKEN,
    addr_hex,
    tx_hash,
    token_transfer,
    serve_incident,
    mock_pathogen_verdict,
    mock_appeal_verdict,
    _replace_llm_mock,
)

VICTIM = "0x" + "5c" * 20
POOL = "0x" + "b1" * 20
ROUTER = "0x" + "4e" * 20
OTHER_TOKEN = "0x" + "71" * 20

ERR_NOT_BOUND = "ERR_APPEAL_NOT_BOUND_TO_REPORT"
ERR_LABEL = "ERR_ANTIBODY_LABEL_UNAGREED"
ERR_WINDOW = "ERR_CHALLENGE_WINDOW_ACTIVE"
ERR_NOT_EXPIRED = "ERR_INCIDENT_NOT_EXPIRED"
ERR_PAYOUT_LOCKED = "ERR_PAYOUT_LOCKED"


# ---------------------------------------------------------------------------
# Evidence builders: one transaction that exhibits each category's mechanics, and one
# that is merely *about* the target without exhibiting them.
# ---------------------------------------------------------------------------
def _word(hex_body: str = "") -> str:
    return hex_body.rjust(64, "0")


def _evidence(category: str, attacker) -> dict:
    """`serve_incident` kwargs for a transaction exhibiting `category`, sent by `attacker`."""
    a = addr_hex(attacker)
    if category == "REENTRANCY":
        # attacker -> victim; victim pays attacker; attacker calls back into victim.
        return {"extra": {"to": {"hash": VICTIM}}, "internal_calls": [(VICTIM, a), (a, VICTIM)]}
    if category == "FLASH_LOAN_DRAIN":
        return {}  # the default body borrows from LENDER and repays it
    if category == "ORACLE_MANIPULATION":
        # Pump (X in, Y out) then dump (Y in, X out) against the same pool.
        return {"extra": {"token_transfers": [
            token_transfer(a, POOL, token=TOKEN),
            token_transfer(POOL, a, token=OTHER_TOKEN),
            token_transfer(a, POOL, token=OTHER_TOKEN),
            token_transfer(POOL, a, token=TOKEN),
        ]}}
    if category == "ACCESS_CONTROL":
        return {"extra": {"to": {"hash": VICTIM}, "raw_input": "0xf2fde38b" + _word(a[2:])}}
    if category == "ARBITRARY_EXTERNAL_CALL":
        # execute(address target, bytes data) whose data is transferFrom(victim, attacker, amt)
        data = "23b872dd" + _word(VICTIM[2:]) + _word(a[2:]) + _word("ff")
        raw = "0x1cff79cd" + _word(VICTIM[2:]) + _word("40") + _word(hex(len(data) // 2)[2:]) + data
        return {"extra": {"to": {"hash": VICTIM}, "raw_input": raw}}
    raise AssertionError(category)


def _generic_evidence(category: str) -> dict:
    """A transaction the target is a party to that lacks `category`'s mechanics."""
    if category == "REENTRANCY":
        # A router calling the victim twice in sequence is not re-entry: the second call
        # comes from the router, not from anything the victim called.
        return {"extra": {"to": {"hash": ROUTER}},
                "internal_calls": [(ROUTER, VICTIM), (VICTIM, TOKEN), (ROUTER, VICTIM)]}
    if category == "FLASH_LOAN_DRAIN":
        return {"extra": {"token_transfers": [token_transfer(LENDER, VICTIM)]}}  # no repayment
    if category == "ORACLE_MANIPULATION":
        return {}  # one token borrowed and repaid: no two-way swap through a pool
    if category == "ACCESS_CONTROL":
        return {"extra": {"raw_input": "0xa9059cbb" + _word("01") + _word("02")}}  # transfer()
    if category == "ARBITRARY_EXTERNAL_CALL":
        # transferFrom as the *top-level* call is an ordinary transfer, not a forwarded one.
        return {"extra": {"raw_input": "0x23b872dd" + _word("01") + _word("02") + _word("03")}}
    raise AssertionError(category)


CATEGORIES = [
    "REENTRANCY",
    "FLASH_LOAN_DRAIN",
    "ORACLE_MANIPULATION",
    "ACCESS_CONTROL",
    "ARBITRARY_EXTERNAL_CALL",
]


def _warp_hours(direct_vm, hours: float) -> None:
    future = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    ).isoformat().replace("+00:00", "Z")
    direct_vm.warp(future)


def _file_report(contract, direct_vm, reporter, target, report_id, category="FLASH_LOAN_DRAIN",
                 evidence=None, bond=MIN_REPORTER_BOND):
    serve_incident(direct_vm, target, **(evidence if evidence is not None else _evidence(category, target)))
    direct_vm.sender = reporter
    direct_vm.value = bond
    trace = tx_hash(f"{report_id}|{addr_hex(target)}")
    contract.report_pathogen(report_id, target, "EVM_TX", trace, category)
    direct_vm.value = 0
    return trace


def _critical(contract, direct_vm, reporter, target, report_id, category="FLASH_LOAN_DRAIN", pool=10 * ATTO):
    if pool:
        direct_vm.sender = reporter
        direct_vm.value = pool
        contract.fund_bounty_pool()
    trace = _file_report(contract, direct_vm, reporter, target, report_id, category)
    mock_pathogen_verdict(direct_vm, tier="TIER_PATHOGEN_CRITICAL")
    contract.evaluate_pathogen(report_id)
    return trace


def _appeal(contract, direct_vm, appellant, report_id, trace, kind="AUTHORIZED_ADMIN_ACTION",
            bond=APPEAL_BOND):
    direct_vm.sender = appellant
    direct_vm.value = bond
    contract.file_appeal(report_id, trace, kind, JUSTIFICATION)
    direct_vm.value = 0
    return contract.get_escrow(report_id)["active_appeal_id"]


def _overview(contract) -> dict:
    return {k: (int(v) if isinstance(v, str) and v.isdigit() else v)
            for k, v in contract.get_registry_overview().items()}


def _assert_solvent(contract, *accounts, pending_report_bonds=0):
    ov = _overview(contract)
    held = sum(int(contract.get_claimable_balance(a)) for a in accounts)
    assert ov["total_deposited_atto"] == (
        ov["bounty_pool_atto"] + ov["protocol_reserves_atto"] + ov["total_claimed_atto"]
        + ov["locked_escrow_atto"] + ov["pending_appeal_bonds_atto"] + held + pending_report_bonds
    )


# ---------------------------------------------------------------------------
# 1. Evidence-backed exploit classification
# ---------------------------------------------------------------------------
def test_exploit_category_mismatch_fails(direct_vm, direct_deploy, direct_alice, direct_bob):
    """Claiming REENTRANCY on a transaction whose call trace shows no re-entry reverts
    with ERR_UNSUPPORTED_EXPLOIT_CATEGORY before any bond is taken or report recorded."""
    contract = direct_deploy(CONTRACT_PATH)

    with pytest.raises(Exception) as exc:
        _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-mis", "REENTRANCY",
                     evidence=_generic_evidence("REENTRANCY"))
    assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)
    assert "no contract re-entered" in str(exc.value)

    ov = _overview(contract)
    assert ov["total_reports"] == 0 and ov["total_deposited_atto"] == 0

    # The same transaction with a real callback into the victim is accepted, and the
    # mechanics agreed under consensus are committed to the report.
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-mis", "REENTRANCY")
    rep = contract.get_report("rep-mis")
    assert rep["exploit_category"] == "REENTRANCY"
    assert rep["antibody_label"] == f"REENTRANCY|sel=0x|reentered={VICTIM}<-{addr_hex(direct_bob).lower()}"


@pytest.mark.parametrize("category", CATEGORIES)
def test_every_category_requires_its_own_mechanics(
    direct_vm, direct_deploy, direct_alice, direct_bob, category
):
    contract = direct_deploy(CONTRACT_PATH)

    with pytest.raises(Exception) as exc:
        _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-c", category,
                     evidence=_generic_evidence(category))
    assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)
    assert _overview(contract)["total_reports"] == 0

    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-c", category)
    assert contract.get_report("rep-c")["antibody_label"].startswith(f"{category}|sel=")


@pytest.mark.parametrize("case", ["flash_loan_callback", "mint_then_burn"])
def test_look_alike_mechanics_are_not_accepted(
    direct_vm, direct_deploy, direct_alice, direct_bob, case
):
    """Patterns that share a category's shape without being it: a lender calling back
    into the borrower's own contract is how flash loans work, not re-entry of a victim;
    and a token minted then burned is accounting, not a loan between two parties."""
    contract = direct_deploy(CONTRACT_PATH)
    b = addr_hex(direct_bob)
    zero = "0x" + "00" * 20
    if case == "flash_loan_callback":
        # bob -> borrower B; B -> pool.flashLoan; pool -> B.executeOperation
        borrower = "0x" + "bb" * 20
        category, evidence = "REENTRANCY", {
            "extra": {"to": {"hash": borrower}},
            "internal_calls": [(borrower, POOL), (POOL, borrower)],
        }
    else:
        category, evidence = "FLASH_LOAN_DRAIN", {"extra": {"token_transfers": [
            token_transfer(zero, b), token_transfer(b, zero),
        ]}}
    with pytest.raises(Exception) as exc:
        _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-look", category, evidence=evidence)
    assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)


def test_truncated_transfer_list_fetches_the_full_page(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The explorer's transaction record lists only the first transfers. When it says
    the list is truncated, validators fetch the full page -- so a repayment that falls
    past the cut still counts, and one that does not exist is not assumed."""
    contract = direct_deploy(CONTRACT_PATH)
    b = addr_hex(direct_bob)
    borrow = token_transfer(LENDER, b)
    head = {"token_transfers": [borrow], "token_transfers_overflow": True}

    with pytest.raises(Exception) as exc:
        _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-trunc", "FLASH_LOAN_DRAIN",
                     evidence={"extra": head, "transfer_page": [borrow]})
    assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)

    requested = serve_incident(direct_vm, direct_bob, extra=head,
                               transfer_page=[borrow, token_transfer(b, LENDER, value="1001")])
    direct_vm.sender = direct_alice
    direct_vm.value = MIN_REPORTER_BOND
    contract.report_pathogen("rep-trunc", direct_bob, "EVM_TX", tx_hash("trunc"), "FLASH_LOAN_DRAIN")
    assert any(u.endswith("/token-transfers") for u in requested)
    assert contract.get_report("rep-trunc")["antibody_label"].endswith(f"{LENDER}->{b.lower()}->{LENDER}")


EULER_TX = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
EULER_EXPLOITER = "0x5F259D0b76665c337c6104145894F4D1D2758B8c"


def _serve_fixture(direct_vm):
    """Serve the verbatim Blockscout responses recorded for the Euler exploit tx."""
    import os
    here = os.path.join(os.path.dirname(__file__), "fixtures")
    files = {
        "": "euler_tx.json",
        "/internal-transactions": "euler_internal_transactions.json",
        "/token-transfers": "euler_token_transfers.json",
    }
    direct_vm._web_mocks.clear()
    direct_vm._llm_mocks_hit.clear()

    def handler(data):
        url = str(data.get("url", "")).rstrip("/")
        for suffix, name in sorted(files.items(), key=lambda kv: -len(kv[0])):
            if url.endswith(EULER_TX + suffix):
                with open(os.path.join(here, name), "rb") as fh:
                    return {"ok": {"response": {"status": 200, "headers": {}, "body": fh.read()}}}
        return {"ok": {"response": {"status": 404, "headers": {}, "body": b"{}"}}}

    direct_vm._live_web_handler = handler


@pytest.mark.parametrize("category,supported", [
    ("FLASH_LOAN_DRAIN", True),
    ("ORACLE_MANIPULATION", False),
    ("ACCESS_CONTROL", False),
    ("ARBITRARY_EXTERNAL_CALL", False),
])
def test_real_euler_exploit_is_classified_on_its_mechanics(
    direct_vm, direct_deploy, direct_alice, category, supported
):
    """Against the recorded explorer data of the 2023 Euler exploit: the Aave DAI flash
    loan (borrowed from aDAI, repaid in the 20th transfer, past the record's cut) is
    found; categories the transaction does not exhibit are refused."""
    contract = direct_deploy(CONTRACT_PATH)
    _serve_fixture(direct_vm)
    direct_vm.sender = direct_alice
    direct_vm.value = MIN_REPORTER_BOND
    if supported:
        contract.report_pathogen("rep-euler", EULER_EXPLOITER, "EVM_TX", EULER_TX, category)
        label = contract.get_report("rep-euler")["antibody_label"]
        dai, adai = "0x6b175474e89094c44da98b954eedeac495271d0f", "0x028171bca77440897b824ca71d1c56cac55b68a3"
        assert label.startswith("FLASH_LOAN_DRAIN|sel=0x863df8af|flash=" + dai + ":" + adai + "->")
        assert direct_vm.run_validator() is True
    else:
        with pytest.raises(Exception) as exc:
            contract.report_pathogen("rep-euler", EULER_EXPLOITER, "EVM_TX", EULER_TX, category)
        assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)


@pytest.mark.parametrize("claimed", ["GENERIC_EXPLOIT", "reentrancy", "", "PROMPT_INJECTION"])
def test_unknown_category_rejected_before_fetch(
    direct_vm, direct_deploy, direct_alice, direct_bob, claimed
):
    """Only the enum is accepted -- free-text or mis-cased categories are refused before
    the explorer is even contacted."""
    contract = direct_deploy(CONTRACT_PATH)
    requested = serve_incident(direct_vm, direct_bob)
    direct_vm.sender = direct_alice
    direct_vm.value = MIN_REPORTER_BOND
    with pytest.raises(Exception) as exc:
        contract.report_pathogen("rep-u", direct_bob, "EVM_TX", tx_hash("u"), claimed)
    assert ERR_UNSUPPORTED_CATEGORY in str(exc.value)
    assert requested == []


def test_mechanics_present_but_model_rejects_category_fabricates(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """Mechanics are necessary, not sufficient. If consensus finds the transaction is
    not an instance of the claimed category (e.g. a benign flash-loan arbitrage), an
    escalating verdict cannot stand: the report is fabricated and the bond slashed."""
    contract = direct_deploy(CONTRACT_PATH)
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-arb")
    mock_pathogen_verdict(direct_vm, tier="TIER_PATHOGEN_CRITICAL", category_supported=False)
    contract.evaluate_pathogen("rep-arb")

    rep = contract.get_report("rep-arb")
    assert rep["tier"] == "TIER_FABRICATED_ATTACK"
    assert rep["antibody_hash"] == ""
    assert contract.is_quarantined(direct_bob) is False
    assert _overview(contract)["total_antibodies"] == 0
    assert _overview(contract)["protocol_reserves_atto"] == MIN_REPORTER_BOND


def test_evaluation_rechecks_mechanics_on_served_bytes(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If the evidence served at evaluation no longer shows the mechanics, the model is
    never asked and the report resolves fabricated."""
    contract = direct_deploy(CONTRACT_PATH)
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-gone", "REENTRANCY")
    serve_incident(direct_vm, direct_bob, **_generic_evidence("REENTRANCY"))
    mock_pathogen_verdict(direct_vm, tier="TIER_PATHOGEN_CRITICAL")
    contract.evaluate_pathogen("rep-gone")
    assert contract.get_report("rep-gone")["tier"] == "TIER_FABRICATED_ATTACK"
    assert contract.is_quarantined(direct_bob) is False


# ---------------------------------------------------------------------------
# 2. Direct rebuttal appeals
# ---------------------------------------------------------------------------
def test_cannot_overturn_with_unrelated_benign_tx(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """The target cannot dismiss a report by citing some other, benign transaction it
    was a party to. Filing such an appeal reverts with no bond taken; a valid appeal is
    judged on the original trace only, under the stated rebuttal."""
    contract = direct_deploy(CONTRACT_PATH)
    trace = _critical(contract, direct_vm, direct_alice, direct_bob, "rep-orig")
    deposited = _overview(contract)["total_deposited_atto"]

    benign = tx_hash("bob-harmless-transfer")
    serve_incident(direct_vm, direct_bob)  # bob *is* a party to the benign tx
    for kind in ("AUTHORIZED_ADMIN_ACTION", "MISCLASSIFIED_MECHANICS"):
        direct_vm.sender = direct_bob
        direct_vm.value = APPEAL_BOND
        with pytest.raises(Exception) as exc:
            contract.file_appeal("rep-orig", benign, kind, JUSTIFICATION)
        assert ERR_NOT_BOUND in str(exc.value)
        assert trace in str(exc.value)

    esc = contract.get_escrow("rep-orig")
    assert esc["status"] == "LOCKED" and esc["active_appeal_id"] == ""
    assert _overview(contract)["total_deposited_atto"] == deposited
    assert _overview(contract)["pending_appeal_bonds_atto"] == 0

    # A proper rebuttal of the original: the arbiter re-fetches only the flagged
    # transaction and sees the appellant's justification.
    appeal_id = _appeal(contract, direct_vm, direct_bob, "rep-orig", trace)
    appeal = contract.get_appeal(appeal_id)
    assert appeal["rebutted_trace_id"] == trace
    assert appeal["rebuttal_kind"] == "AUTHORIZED_ADMIN_ACTION"
    assert appeal["justification"] == JUSTIFICATION

    requested = serve_incident(direct_vm, direct_bob)
    _replace_llm_mock(
        direct_vm,
        APPEAL_PROMPT_PATTERN,
        json.dumps(json.dumps({"tier": "TIER_BENIGN_NOISE", "rebuts_original": True, "rationale": "ok"})),
    )
    # Narrow the arbiter mock to prompts that carry the original trace and the rebuttal,
    # and never the benign transaction.
    direct_vm._llm_mocks[:] = [m for m in direct_vm._llm_mocks if m[0].pattern != APPEAL_PROMPT_PATTERN]
    direct_vm.mock_llm(
        rf"(?s)^(?!.*{benign[2:]}).*Appeals Arbiter.*Flagged Transaction: <untrusted_input>{trace}"
        rf".*Rebuttal Kind: AUTHORIZED_ADMIN_ACTION.*{JUSTIFICATION}",
        json.dumps(json.dumps({"tier": "TIER_BENIGN_NOISE", "rebuts_original": True, "rationale": "ok"})),
    )
    contract.resolve_appeal(appeal_id)
    assert requested and all(u.endswith(trace) for u in requested)
    assert contract.get_appeal(appeal_id)["status"] == "UPHELD"


def test_benign_verdict_without_rebuttal_does_not_overturn(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """A 'looks benign' verdict is not enough: the arbiter must find that the rebuttal
    explains the flagged transaction, otherwise the appeal is rejected and slashed."""
    contract = direct_deploy(CONTRACT_PATH)
    trace = _critical(contract, direct_vm, direct_alice, direct_bob, "rep-nr")
    appeal_id = _appeal(contract, direct_vm, direct_bob, "rep-nr", trace)

    serve_incident(direct_vm, direct_bob)
    mock_appeal_verdict(direct_vm, tier="TIER_BENIGN_NOISE", rebuts_original=False)
    contract.resolve_appeal(appeal_id)

    assert contract.get_appeal(appeal_id)["status"] == "REJECTED"
    assert contract.is_quarantined(direct_bob) is True
    assert _overview(contract)["protocol_reserves_atto"] == APPEAL_BOND

    # And a validator that finds the rebuttal unconvincing rejects a leader claiming it
    # was upheld.
    assert direct_vm.run_validator(
        leader_result={"tier": "TIER_BENIGN_NOISE", "rebuts_original": True, "rationale": "x"}
    ) is False


# ---------------------------------------------------------------------------
# 3. Validator consensus on persisted antibody labels
# ---------------------------------------------------------------------------
def test_unvetted_antibody_label_rejected(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """No single proposer can write an antibody label: validators recompute it from the
    evidence and reject any leader proposing another, and the stored label must equal
    the one agreed at filing -- model output is never persisted as a label."""
    contract = direct_deploy(CONTRACT_PATH)
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-ab", "ACCESS_CONTROL")
    agreed = contract.get_report("rep-ab")["antibody_label"]
    assert agreed == f"ACCESS_CONTROL|sel=0xf2fde38b|privileged=transferOwnership@{VICTIM}"

    # The filing-time validator rejects a leader asserting any other label.
    assert direct_vm.run_validator() is True
    assert direct_vm.run_validator(leader_result={"role": "from", "label": agreed + "|extra"}) is False

    # The model tries to smuggle a broader label and pathogen type into storage.
    _replace_llm_mock(direct_vm, r".*Security Triage Sentinel.*", json.dumps(json.dumps({
        "tier": "TIER_PATHOGEN_CRITICAL",
        "category_supported": True,
        "antibody_label": "ACCESS_CONTROL|sel=0x00000000|blacklist=*",
        "pathogen_type": "BLACKLIST_EVERY_SELECTOR",
        "rationale": "x",
    })))
    contract.evaluate_pathogen("rep-ab")
    ab = contract.get_antibody(contract.get_report("rep-ab")["antibody_hash"])
    assert ab["label"] == agreed
    assert ab["pathogen_type"] == "ACCESS_CONTROL"
    assert ab["report_id"] == "rep-ab"

    honest = {"tier": "TIER_PATHOGEN_CRITICAL", "category_supported": True,
              "antibody_label": agreed, "rationale": "x"}
    assert direct_vm.run_validator() is True
    assert direct_vm.run_validator(leader_result=honest) is True
    for forged in (
        dict(honest, antibody_label="ACCESS_CONTROL|sel=0x00000000|blacklist=*"),
        dict(honest, antibody_label=agreed.replace("ACCESS_CONTROL", "REENTRANCY", 1)),
        dict(honest, antibody_label=""),
        dict(honest, category_supported=False),  # escalation without category support
    ):
        assert direct_vm.run_validator(leader_result=forged) is False


def test_label_drift_between_filing_and_evaluation_blocks_storage(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    """If evaluation's consensus derives a label other than the one agreed at filing,
    nothing is written: no antibody, no quarantine, no escrow, report still pending."""
    contract = direct_deploy(CONTRACT_PATH)
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-drift", "ACCESS_CONTROL")

    serve_incident(direct_vm, direct_bob, extra={
        "to": {"hash": VICTIM}, "raw_input": "0x3659cfe6" + _word("aa"),  # upgradeTo now
    })
    mock_pathogen_verdict(direct_vm, tier="TIER_PATHOGEN_CRITICAL")
    with pytest.raises(Exception) as exc:
        contract.evaluate_pathogen("rep-drift")
    assert ERR_LABEL in str(exc.value)

    ov = _overview(contract)
    assert ov["total_antibodies"] == 0 and ov["total_escrows"] == 0
    assert contract.get_report("rep-drift")["status"] == "PENDING"
    assert contract.is_quarantined(direct_bob) is False


# ---------------------------------------------------------------------------
# 4. Payout workflow
# ---------------------------------------------------------------------------
def test_claim_payout_lifecycle(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    """Premature payout fails with ERR_CHALLENGE_WINDOW_ACTIVE, payout during an appeal
    fails with ERR_PAYOUT_LOCKED, and after the deadline the reporter receives exactly
    bond + escrowed bounty -- once."""
    contract = direct_deploy(CONTRACT_PATH)
    trace = _critical(contract, direct_vm, direct_alice, direct_bob, "rep-pay")
    owed = MIN_REPORTER_BOND + BASE_BOUNTY_REWARD

    esc = contract.get_escrow("rep-pay")
    assert esc["challenge_deadline_utc"] == esc["locked_until_utc"] > 0
    assert int(esc["bond_atto"]) + int(esc["payout_atto"]) == owed
    assert _overview(contract)["bounty_pool_atto"] == 9 * ATTO

    direct_vm.sender = direct_charlie
    with pytest.raises(Exception) as early:
        contract.claim_payout("rep-pay")
    assert ERR_WINDOW in str(early.value)

    appeal_id = _appeal(contract, direct_vm, direct_bob, "rep-pay", trace)
    _warp_hours(direct_vm, 24 * 8)
    with pytest.raises(Exception) as locked:
        contract.claim_payout("rep-pay")
    assert ERR_PAYOUT_LOCKED in str(locked.value)

    serve_incident(direct_vm, direct_bob)
    mock_appeal_verdict(direct_vm, tier="TIER_PATHOGEN_CRITICAL", rebuts_original=False)
    contract.resolve_appeal(appeal_id)

    # A rejected appeal keeps the window open for the grace period.
    with pytest.raises(Exception) as grace:
        contract.claim_payout("rep-pay")
    assert ERR_WINDOW in str(grace.value)

    _warp_hours(direct_vm, 24 * 8 + 25)
    before = _overview(contract)
    contract.claim_payout("rep-pay")  # permissionless: charlie triggers, alice is paid
    after = _overview(contract)

    assert int(contract.get_claimable_balance(direct_alice)) == owed
    assert contract.get_claimable_balance(direct_charlie) == "0"
    assert before["locked_escrow_atto"] - after["locked_escrow_atto"] == owed
    assert after["bounty_pool_atto"] == 9 * ATTO
    assert after["protocol_reserves_atto"] == APPEAL_BOND
    assert contract.get_escrow("rep-pay")["status"] == "RELEASED"
    _assert_solvent(contract, direct_alice, direct_bob, direct_charlie)

    with pytest.raises(Exception) as twice:
        contract.claim_payout("rep-pay")
    assert "already settled" in str(twice.value)

    direct_vm.sender = direct_alice
    contract.withdraw()
    assert _overview(contract)["total_claimed_atto"] == owed
    _assert_solvent(contract, direct_alice, direct_bob, direct_charlie)


def test_claim_payout_refuses_non_confirmed_incidents(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-benign")
    mock_pathogen_verdict(direct_vm, tier="TIER_BENIGN_NOISE")
    contract.evaluate_pathogen("rep-benign")
    with pytest.raises(Exception) as exc:
        contract.claim_payout("rep-benign")
    assert "no escrow exists" in str(exc.value)

    trace = _critical(contract, direct_vm, direct_alice, direct_bob, "rep-over", pool=0)
    appeal_id = _appeal(contract, direct_vm, direct_bob, "rep-over", trace)
    serve_incident(direct_vm, direct_bob)
    mock_appeal_verdict(direct_vm)
    contract.resolve_appeal(appeal_id)
    _warp_hours(direct_vm, 24 * 30)
    with pytest.raises(Exception) as exc2:
        contract.claim_payout("rep-over")
    assert "already settled" in str(exc2.value)
    # Alice holds only the bond refunded by her benign report -- nothing from escrow.
    assert int(contract.get_claimable_balance(direct_alice)) == MIN_REPORTER_BOND


# ---------------------------------------------------------------------------
# 5. Expiry workflow
# ---------------------------------------------------------------------------
def test_expire_incident_workflow(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    """An inconclusive (never-evaluated) incident expires permissionlessly after its
    deadline: the reporter's bond is refunded and the replay digest freed. A rebutted
    incident closes with its bonds already settled by the appeal."""
    contract = direct_deploy(CONTRACT_PATH)

    # -- Inconclusive: never evaluated --------------------------------------------
    trace = _file_report(contract, direct_vm, direct_alice, direct_bob, "rep-idle")
    direct_vm.sender = direct_charlie
    with pytest.raises(Exception) as early:
        contract.expire_incident("rep-idle")
    assert ERR_NOT_EXPIRED in str(early.value)
    _assert_solvent(contract, direct_alice, pending_report_bonds=MIN_REPORTER_BOND)

    _warp_hours(direct_vm, 24 * 7 + 1)
    contract.expire_incident("rep-idle")  # a third party closes it
    assert contract.get_report("rep-idle")["status"] == "EXPIRED"
    assert int(contract.get_claimable_balance(direct_alice)) == MIN_REPORTER_BOND
    assert contract.get_claimable_balance(direct_charlie) == "0"
    _assert_solvent(contract, direct_alice, direct_charlie)

    with pytest.raises(Exception) as again:
        contract.expire_incident("rep-idle")
    assert "already terminal" in str(again.value)

    # The digest is free: the same incident can be filed again.
    serve_incident(direct_vm, direct_bob)
    direct_vm.sender = direct_alice
    direct_vm.value = MIN_REPORTER_BOND
    contract.report_pathogen("rep-idle-2", direct_bob, "EVM_TX", trace, "FLASH_LOAN_DRAIN")
    direct_vm.value = 0
    assert contract.get_report("rep-idle-2")["status"] == "PENDING"

    # -- Rebutted: appeal upheld, then closed -------------------------------------
    target = direct_charlie
    trace2 = _critical(contract, direct_vm, direct_alice, target, "rep-rebut")
    appeal_id = _appeal(contract, direct_vm, target, "rep-rebut", trace2)
    serve_incident(direct_vm, target)
    mock_appeal_verdict(direct_vm)
    contract.resolve_appeal(appeal_id)
    assert contract.get_report("rep-rebut")["status"] == "OVERTURNED"

    contract.expire_incident("rep-rebut")
    assert contract.get_report("rep-rebut")["status"] == "CLOSED"
    assert contract.is_quarantined(target) is False
    assert int(contract.get_claimable_balance(target)) == APPEAL_BOND  # appellant refunded
    ov = _overview(contract)
    assert ov["bounty_pool_atto"] == 10 * ATTO  # escrowed bounty returned
    assert ov["protocol_reserves_atto"] == MIN_REPORTER_BOND  # false reporter slashed
    _assert_solvent(contract, direct_alice, target, pending_report_bonds=MIN_REPORTER_BOND)


def test_expire_incident_settles_inconclusive_appeal_then_closes_confirmed(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    """An appeal consensus never resolves: expiry refunds the appellant and lets the
    verdict stand; a second expiry then releases the matured escrow, lifts the lapsed
    quarantine and closes the incident."""
    contract = direct_deploy(CONTRACT_PATH)
    trace = _critical(contract, direct_vm, direct_alice, direct_bob, "rep-stall")
    appeal_id = _appeal(contract, direct_vm, direct_bob, "rep-stall", trace)

    direct_vm.sender = direct_charlie
    with pytest.raises(Exception) as early:
        contract.expire_incident("rep-stall")
    assert ERR_NOT_EXPIRED in str(early.value)

    _warp_hours(direct_vm, 24 * 7 + 1)
    contract.expire_incident("rep-stall")
    assert contract.get_appeal(appeal_id)["status"] == "EXPIRED"
    assert contract.get_report("rep-stall")["status"] == "RESOLVED"
    assert int(contract.get_claimable_balance(direct_bob)) == APPEAL_BOND

    contract.expire_incident("rep-stall")
    assert contract.get_report("rep-stall")["status"] == "CLOSED"
    assert contract.get_escrow("rep-stall")["status"] == "RELEASED"
    assert contract.get_quarantine_info(direct_bob)["is_active"] is False
    assert int(contract.get_claimable_balance(direct_alice)) == MIN_REPORTER_BOND + BASE_BOUNTY_REWARD
    _assert_solvent(contract, direct_alice, direct_bob, direct_charlie)


def test_expire_incident_refuses_open_challenge_window(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy(CONTRACT_PATH)
    _critical(contract, direct_vm, direct_alice, direct_bob, "rep-open")
    with pytest.raises(Exception) as exc:
        contract.expire_incident("rep-open")
    assert ERR_WINDOW in str(exc.value)
    assert contract.get_escrow("rep-open")["status"] == "LOCKED"
    assert contract.get_report("rep-open")["status"] == "RESOLVED"
    with pytest.raises(Exception) as missing:
        contract.expire_incident("no-such-report")
    assert "not found" in str(missing.value)
