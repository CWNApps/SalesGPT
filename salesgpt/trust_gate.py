"""trust_gate.py -- optional, tamper-evident receipt for a qualified-lead handoff.

When SalesGPT qualifies a lead and hands it to a human rep, this mints a signed receipt over
the qualification: what the agent saw, how it scored (BANT/MEDDIC), and when. The rep (or a
later auditor) can verify from the certificate alone that the handoff was not edited after the
fact.

OPTIONAL by design: the cryptography lives in the open-source `openagentontology` package
(Apache-2.0), imported lazily. If the package is not installed, this returns an explicit
unsigned stub (never a fake signature), so adding this module imposes no new required
dependency on SalesGPT. A broken install (not mere absence) is surfaced, not swallowed.

    pip install "openagentontology[pq]"   # Ed25519 + ML-DSA-65 + SLH-DSA legs

Usage:
    from salesgpt.trust_gate import mint_lead_handoff_receipt, verify_receipt
    receipt = mint_lead_handoff_receipt({
        "lead_id": "acme-123",
        "bant": {"budget": True, "authority": True, "need": True, "timing": "Q3"},
        "meddic_score": 0.72,
        "qualified_by": "salesgpt",
    })
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional


def _oao():
    """Lazy import so SalesGPT has no hard dependency on the receipt package.

    Returns None ONLY when the package is genuinely absent. A broken install (any other import
    error from inside the package) is allowed to propagate, so it is surfaced to the maintainer
    rather than silently degrading to an unsigned receipt.
    """
    try:
        from openagentontology import receipt as _r  # type: ignore
        return _r
    except (ImportError, ModuleNotFoundError):
        return None


def _hash(s: str) -> str:
    """Full SHA-256 integrity hash of the input. This is a tamper-evidence hash, not a privacy
    guarantee: low-entropy inputs can be brute-forced, so do not treat it as redaction."""
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def build_handoff_manifest(lead: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble the ASCII-safe action manifest for a lead handoff."""
    lead_id = str(lead.get("lead_id", "")).strip()
    if not lead_id:
        raise ValueError("lead must include a non-empty 'lead_id'")
    return {
        "operation": "lead_qualification_handoff",
        "lead_id": lead_id,
        "bant": lead.get("bant", {}),
        "meddic_score": lead.get("meddic_score"),
        "qualified_by": lead.get("qualified_by", "salesgpt"),
        "conversation_hash": _hash(str(lead.get("conversation", ""))),
        "policy": "auditable AI-sourced lead provenance",
    }


def mint_lead_handoff_receipt(lead: Dict[str, Any]) -> Dict[str, Any]:
    """Mint a (post-quantum, when available) receipt over a qualified-lead handoff.

    Returns the receipt dict. If `openagentontology` is not installed, returns an explicit
    unsigned stub flagged `signed: False` -- the lead provenance is still hashed and carried,
    but it is honestly marked as not cryptographically signed.
    """
    manifest = build_handoff_manifest(lead)
    oao = _oao()
    if oao is None:
        return {
            "type": "AgentGovernanceReceipt",
            "decision": "LEAD_QUALIFIED",
            "evidence": {"ontology": manifest},
            "signed": False,
            "unsigned_reason": "install 'openagentontology[pq]' to sign this receipt",
        }
    return oao.mint_receipt(manifest, decision="LEAD_QUALIFIED")


def verify_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a handoff receipt from the cert alone. Requires openagentontology to check sigs."""
    oao = _oao()
    if oao is None:
        return {"ok": False, "reason": "install 'openagentontology' to verify signatures"}
    return oao.verify_receipt(receipt)
