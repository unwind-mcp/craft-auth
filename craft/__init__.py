"""CRAFT — Cryptographic Relay Authentication for Faithful Transmission.

Transport-layer command provenance and anti-spoofing for AI agents.
Zero external dependencies. Pure Python stdlib.

https://github.com/unwind-mcp/craft-auth
"""

from .canonical import canonicalize_for_mac, mac_input_bytes
from .crypto import (
    DirectionalKeys,
    SessionKeys,
    hmac_sha256,
    hkdf_extract,
    hkdf_expand,
    derive_session_keys,
    derive_keys_from_prk,
    derive_rekey_prk,
    state_commit_0,
    b64url_encode,
    b64url_decode,
)
from .verifier import (
    CraftSessionState,
    CraftVerifier,
    VerifyResult,
    VerifyError,
)
from .capabilities import (
    CapabilityIssuer,
    CapabilityToken,
    CapabilityDecision,
    CapabilityError,
    CapabilitySubcode,
    ToolCall,
    StepUpChallenge,
)
from .lifecycle import (
    CraftLifecycleManager,
    RekeyPrepare,
    ResyncChallenge,
    ResyncResult,
    ResyncError,
)
from .persistence import CraftStateStore

__all__ = [
    "canonicalize_for_mac",
    "mac_input_bytes",
    "DirectionalKeys",
    "SessionKeys",
    "hmac_sha256",
    "hkdf_extract",
    "hkdf_expand",
    "derive_session_keys",
    "derive_keys_from_prk",
    "derive_rekey_prk",
    "state_commit_0",
    "b64url_encode",
    "b64url_decode",
    "CraftSessionState",
    "CraftVerifier",
    "VerifyResult",
    "VerifyError",
    "CapabilityIssuer",
    "CapabilityToken",
    "CapabilityDecision",
    "CapabilityError",
    "CapabilitySubcode",
    "ToolCall",
    "StepUpChallenge",
    "CraftLifecycleManager",
    "RekeyPrepare",
    "ResyncChallenge",
    "ResyncResult",
    "ResyncError",
    "CraftStateStore",
]
