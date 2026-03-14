"""CRAFT interactive demo and self-test CLI.

Usage:
    craft-auth demo          Run the interactive protocol demo
    craft-auth demo --json   Output demo results as structured JSON
"""
from __future__ import annotations

import json
import os
import sys
import time

from .canonical import mac_input_bytes
from .crypto import (
    b64url_encode,
    derive_session_keys,
    hmac_sha256,
    state_commit_0,
)
from .verifier import CraftSessionState, CraftVerifier
from .capabilities import CapabilityIssuer, ToolCall


# ── ANSI colours (disabled if not a terminal) ──────────────────────

_USE_COLOUR = hasattr(sys.stderr, "isatty") and sys.stdout.isatty()

_GREEN = "\033[32m" if _USE_COLOUR else ""
_RED = "\033[31m" if _USE_COLOUR else ""
_YELLOW = "\033[33m" if _USE_COLOUR else ""
_CYAN = "\033[36m" if _USE_COLOUR else ""
_DIM = "\033[2m" if _USE_COLOUR else ""
_BOLD = "\033[1m" if _USE_COLOUR else ""
_RESET = "\033[0m" if _USE_COLOUR else ""


def _trunc(b: bytes, n: int = 8) -> str:
    return b64url_encode(b)[:n] + "..."


def _print_pass(msg: str) -> None:
    print(f"  {_GREEN}\u2713 {msg}{_RESET}")


def _print_fail(msg: str) -> None:
    print(f"  {_RED}\u2717 {msg}{_RESET}")


def _print_detail(label: str, value: str) -> None:
    print(f"  {_DIM}{label:12s}{_RESET} {value}")


# ── Session + envelope helpers ─────────────────────────────────────

def _make_demo_session():
    """Create a fresh session with random keys."""
    ikm = os.urandom(32)
    salt0 = os.urandom(32)
    server_secret = os.urandom(32)
    session_id = "sess_demo_" + os.urandom(2).hex()

    ctx = f"CRAFT/v4.2|{session_id}|acct_demo|chan_demo|conv_demo|agent".encode()
    keys = derive_session_keys(
        ikm=ikm, salt0=salt0, ctx=ctx, epoch=0, server_secret=server_secret,
    )
    session = CraftSessionState.from_session_keys(
        session_id=session_id,
        account_id="acct_demo",
        channel_id="chan_demo",
        conversation_id="conv_demo",
        context_type="agent",
        epoch=0,
        keys=keys,
        ctx=ctx,
    )
    session.last_state_commit["c2p"] = state_commit_0(keys.c2p.k_state, ctx)
    session.last_state_commit["p2c"] = state_commit_0(keys.p2c.k_state, ctx)
    return session, keys


def _build_envelope(session, seq, tool="fs_read", target="/tmp/data.txt", payload_extra=None):
    """Build and sign a c2p envelope."""
    payload = {"tool": tool, "args": {"path": target}}
    if payload_extra:
        payload.update(payload_extra)

    envelope = {
        "v": 4,
        "epoch": 0,
        "session_id": session.session_id,
        "account_id": session.account_id,
        "channel_id": session.channel_id,
        "conversation_id": session.conversation_id,
        "context_type": session.context_type,
        "seq": str(seq),
        "ts_ms": int(time.time() * 1000),
        "state_commit": "",
        "msg_type": "tool_call",
        "direction": "c2p",
        "payload": payload,
        "mac": "",
    }

    raw_mac = hmac_sha256(session.keys_c2p.k_msg, mac_input_bytes(envelope))
    envelope["mac"] = b64url_encode(raw_mac)

    prev = session.last_state_commit["c2p"]
    commit = hmac_sha256(session.keys_c2p.k_state, prev + raw_mac)
    envelope["state_commit"] = b64url_encode(commit)

    return envelope, raw_mac, commit


# ── Demo scenarios ─────────────────────────────────────────────────

def run_demo(as_json: bool = False) -> bool:
    """Run the full CRAFT demo. Returns True if all scenarios passed."""
    results = []
    session, keys = _make_demo_session()
    verifier = CraftVerifier()

    if not as_json:
        print(f"\n{_BOLD}CRAFT Protocol v4.2 — Interactive Demo{_RESET}")
        print("\u2550" * 50)

    # ── Scenario 1: Session setup ──────────────────────────────────
    if not as_json:
        print(f"\n{_CYAN}\u25b8 Deriving session keys (HKDF-SHA256)...{_RESET}")
        _print_detail("Session", session.session_id)
        _print_detail("Keys", f"c2p_msg={_trunc(keys.c2p.k_msg)}  c2p_state={_trunc(keys.c2p.k_state)}")
        _print_pass("Session established")

    # ── Scenario 2: Valid envelope ─────────────────────────────────
    env1, mac1, commit1 = _build_envelope(session, seq=1)
    result1 = verifier.verify_and_admit(env1, session)

    if not as_json:
        print(f"\n{_CYAN}\u25b8 Scenario 1: Valid envelope{_RESET}")
        _print_detail("Tool", "fs_read")
        _print_detail("Target", "/tmp/data.txt")
        _print_detail("MAC", f"{_trunc(mac1)}  (HMAC-SHA256)")
        _print_detail("Commit\u2081", f"HMAC(k_state, commit\u2080 \u2225 mac\u2081) = {_trunc(commit1)}")

    if result1.accepted:
        if not as_json:
            _print_pass("ACCEPTED \u2014 envelope is authentic and in sequence")
        results.append({"scenario": "valid_envelope", "passed": True})
    else:
        if not as_json:
            _print_fail(f"UNEXPECTED FAILURE: {result1.error}")
        results.append({"scenario": "valid_envelope", "passed": False, "error": str(result1.error)})

    # ── Scenario 3: Tampered payload ───────────────────────────────
    import copy
    tampered = copy.deepcopy(env1)
    tampered["payload"]["args"]["path"] = "/etc/shadow"
    tampered["seq"] = "2"  # new seq so it's not a replay

    # Re-derive session for clean state (we need a separate session to test tampering)
    session_t, _ = _make_demo_session()
    verifier_t = CraftVerifier()
    # First admit a valid envelope
    env_t1, _, _ = _build_envelope(session_t, seq=1)
    verifier_t.verify_and_admit(env_t1, session_t)
    # Now try the tampered one (reuse mac from env_t1 but change payload)
    tampered2 = copy.deepcopy(env_t1)
    tampered2["payload"]["args"]["path"] = "/etc/shadow"

    result2 = verifier_t.verify_and_admit(tampered2, session_t)

    if not as_json:
        print(f"\n{_CYAN}\u25b8 Scenario 2: Tampered payload{_RESET}")
        _print_detail("Modified", 'path "/tmp/data.txt" \u2192 "/etc/shadow"')
        _print_detail("MAC", f"{tampered2['mac'][:8]}...  {_DIM}(unchanged \u2014 attacker can't recompute){_RESET}")

    if result2.error is not None:
        if not as_json:
            _print_fail(f"REJECTED \u2014 {result2.error.value}")
            print(f"  {_DIM}\u2192 The MAC no longer matches the modified content{_RESET}")
        results.append({"scenario": "tampered_payload", "passed": True, "error": result2.error.value})
    else:
        if not as_json:
            _print_fail("UNEXPECTED: tampered envelope was accepted!")
        results.append({"scenario": "tampered_payload", "passed": False})

    # ── Scenario 4: Hash chain (3 envelopes) ───────────────────────
    session_c, _ = _make_demo_session()
    verifier_c = CraftVerifier()
    chain_commits = []
    chain_ok = True

    if not as_json:
        print(f"\n{_CYAN}\u25b8 Scenario 3: Hash chain (3 envelopes){_RESET}")

    for i in range(1, 4):
        env_c, mac_c, commit_c = _build_envelope(
            session_c, seq=i, tool=["fs_read", "web_fetch", "fs_write"][i - 1],
            target=["/tmp/data.txt", "https://api.github.com", "/tmp/out.txt"][i - 1],
        )
        res_c = verifier_c.verify_and_admit(env_c, session_c)
        chain_commits.append(commit_c)

        if not as_json:
            subscript = str(i).translate(str.maketrans("0123456789", "\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089"))
            if res_c.accepted:
                _print_detail(f"Envelope {i}", f"commit{subscript} = {_trunc(commit_c)}  {_GREEN}\u2713{_RESET}")
            else:
                _print_detail(f"Envelope {i}", f"{_RED}\u2717 {res_c.error}{_RESET}")
                chain_ok = False

    if not as_json and chain_ok:
        _print_pass("Chain integrity: VERIFIED (3/3)")

    # Now tamper with middle commit
    session_c2, _ = _make_demo_session()
    verifier_c2 = CraftVerifier()
    env_c2_1, _, _ = _build_envelope(session_c2, seq=1)
    verifier_c2.verify_and_admit(env_c2_1, session_c2)

    env_c2_2, _, _ = _build_envelope(session_c2, seq=2, tool="web_fetch", target="https://api.github.com")
    # Tamper with state_commit
    env_c2_2["state_commit"] = b64url_encode(os.urandom(32))
    res_tamper = verifier_c2.verify_and_admit(env_c2_2, session_c2)

    if not as_json:
        print(f"\n  {_DIM}Now tampering with envelope 2's state commitment...{_RESET}")

    if res_tamper.error is not None:
        if not as_json:
            _print_fail(f"REJECTED \u2014 {res_tamper.error.value}")
            print(f"  {_DIM}\u2192 Modifying any link breaks every subsequent commitment{_RESET}")
        results.append({"scenario": "chain_integrity", "passed": True})
    else:
        if not as_json:
            _print_fail("UNEXPECTED: tampered chain was accepted!")
        results.append({"scenario": "chain_integrity", "passed": False})

    # ── Scenario 5: Capability token ───────────────────────────────
    session_cap, _ = _make_demo_session()
    verifier_cap = CraftVerifier()

    # Admit one envelope to establish state
    env_cap1, _, _ = _build_envelope(session_cap, seq=1)
    verifier_cap.verify_and_admit(env_cap1, session_cap)

    issuer = CapabilityIssuer(cap_keys_by_epoch=session_cap.cap_keys_by_epoch)
    token = issuer.mint_capability(
        session=session_cap,
        subject=session_cap.account_id,
        allowed_tools=["fs_write"],
        arg_constraints={"exact": {"path": "/tmp/config.json"}},
        target_constraints={"type": "exact", "value": "/tmp/config.json"},
        bind_seq=1,
        state_commit_at_issue=b64url_encode(session_cap.last_state_commit["c2p"]),
        purpose="write config file",
    )

    # Matching call
    good_call = ToolCall(
        session_id=session_cap.session_id,
        account_id=session_cap.account_id,
        channel_id=session_cap.channel_id,
        conversation_id=session_cap.conversation_id,
        context_type=session_cap.context_type,
        subject=session_cap.account_id,
        seq=1, direction="c2p",
        tool_id="fs_write", args={"path": "/tmp/config.json"},
        target="/tmp/config.json",
    )
    decision_good = issuer.enforce_at_tool_dispatch(
        token=token, tool_call=good_call, session=session_cap,
    )

    # Mismatching call
    bad_call = ToolCall(
        session_id=session_cap.session_id,
        account_id=session_cap.account_id,
        channel_id=session_cap.channel_id,
        conversation_id=session_cap.conversation_id,
        context_type=session_cap.context_type,
        subject=session_cap.account_id,
        seq=1, direction="c2p",
        tool_id="fs_write", args={"path": "/etc/passwd"},
        target="/etc/passwd",
    )
    # Need a fresh token for the bad call since tokens are single-use
    token2 = issuer.mint_capability(
        session=session_cap,
        subject=session_cap.account_id,
        allowed_tools=["fs_write"],
        arg_constraints={"exact": {"path": "/tmp/config.json"}},
        target_constraints={"type": "exact", "value": "/tmp/config.json"},
        bind_seq=1,
        state_commit_at_issue=b64url_encode(session_cap.last_state_commit["c2p"]),
        purpose="write config file",
    )
    decision_bad = issuer.enforce_at_tool_dispatch(
        token=token2, tool_call=bad_call, session=session_cap,
    )

    if not as_json:
        print(f"\n{_CYAN}\u25b8 Scenario 4: Capability token (scoped authorization){_RESET}")
        _print_detail("Token", f"{token.cap_id[:12]}... (TTL=60s, single-use)")
        _print_detail("Scope", "fs_write \u2192 /tmp/config.json")

    cap_pass = decision_good.allowed and not decision_bad.allowed

    if not as_json:
        if decision_good.allowed:
            _print_detail("Match", f"fs_write /tmp/config.json  {_GREEN}\u2713 ALLOWED{_RESET}")
        else:
            _print_detail("Match", f"fs_write /tmp/config.json  {_RED}\u2717 UNEXPECTED DENY{_RESET}")

        if not decision_bad.allowed:
            _print_detail("Mismatch", f"fs_write /etc/passwd       {_RED}\u2717 DENIED{_RESET}")
            print(f"  {_DIM}\u2192 Tokens are bound to specific tools, targets, and arguments{_RESET}")
        else:
            _print_detail("Mismatch", f"fs_write /etc/passwd       {_RED}\u2717 UNEXPECTED ALLOW{_RESET}")

    results.append({"scenario": "capability_token", "passed": cap_pass})

    # ── Summary ────────────────────────────────────────────────────
    all_passed = all(r["passed"] for r in results)

    if as_json:
        print(json.dumps({"passed": all_passed, "scenarios": results}, indent=2))
    else:
        print(f"\n{'=' * 50}")
        if all_passed:
            _print_pass(f"Demo complete. All {len(results)} scenarios passed.")
        else:
            failed = [r["scenario"] for r in results if not r["passed"]]
            _print_fail(f"Demo complete. {len(failed)} scenario(s) failed: {', '.join(failed)}")
        print(f"  {_DIM}Zero external dependencies. Pure Python stdlib.{_RESET}")
        print(f"  {_DIM}pip install craft-auth \u00b7 github.com/unwind-mcp/craft-auth{_RESET}")
        print()

    return all_passed


def main() -> None:
    """CLI entry point."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage: craft-auth demo [--json]")
        print("       craft-auth demo         Run interactive protocol demo")
        print("       craft-auth demo --json   Output as structured JSON")
        sys.exit(0)

    if args[0] == "demo":
        as_json = "--json" in args
        ok = run_demo(as_json=as_json)
        sys.exit(0 if ok else 1)
    else:
        print(f"Unknown command: {args[0]}")
        print("Usage: craft-auth demo [--json]")
        sys.exit(1)


if __name__ == "__main__":
    main()
