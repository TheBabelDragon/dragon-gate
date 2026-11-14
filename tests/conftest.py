"""Shared fixtures."""

import pytest

from dragon_gate.core.identity import generate_identity


@pytest.fixture
def identity():
    return generate_identity(metadata={"test": True})
