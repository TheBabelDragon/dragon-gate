"""Node identity and signed records."""

from dragon_gate.core.identity import generate_identity, verify_signed_identity


def test_generate_and_sign():
    ident = generate_identity()
    assert ident.node_id.startswith("dg-")
    signed = ident.signed_identity()
    assert verify_signed_identity(signed)


def test_tampered_signature_rejected():
    ident = generate_identity()
    signed = ident.signed_identity()
    signed["node_id"] = "tampered"
    assert not verify_signed_identity(signed)


def test_missing_signature_rejected():
    ident = generate_identity()
    record = ident.identity_record()
    assert not verify_signed_identity(record)
