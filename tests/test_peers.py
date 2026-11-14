"""Peer enrollment and authentication failure."""

import pytest

from dragon_gate.core.identity import generate_identity
from dragon_gate.network.peers import PeerRegistry, TrustState


def test_authenticated_enrollment():
    ident = generate_identity()
    reg = PeerRegistry()
    peer = reg.enroll(ident.signed_identity())
    assert peer.trust == TrustState.AUTHENTICATED
    assert peer.node_id == ident.node_id


def test_unauthenticated_rejected():
    reg = PeerRegistry()
    with pytest.raises(ValueError, match="authentication failure"):
        reg.enroll({"node_id": "fake", "public_key": "x"})


def test_discover_does_not_authenticate():
    reg = PeerRegistry()
    peer = reg.discover("dg-unknown")
    assert peer.trust == TrustState.DISCOVERED
