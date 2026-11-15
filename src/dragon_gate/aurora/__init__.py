"""gate-aurora: destination resolver adapter and gateway integration contracts."""

from .adapter import AuroraAdapter, AuroraRouteDiagnosis, NullAuroraAdapter

__all__ = ["AuroraAdapter", "AuroraRouteDiagnosis", "NullAuroraAdapter"]
