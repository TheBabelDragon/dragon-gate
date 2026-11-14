"""TLS Laboratory — certificate chain, SANs, validity, hostname verification."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    san: list[str] = field(default_factory=list)
    serial: str | None = None
    fingerprint_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TLSResult:
    host: str
    port: int = 443
    connected: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    hostname_ok: bool | None = None
    chain: list[CertInfo] = field(default_factory=list)
    expires_in_days: float | None = None
    error: str | None = None
    timing_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "connected": self.connected,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "hostname_ok": self.hostname_ok,
            "chain": [c.to_dict() for c in self.chain],
            "expires_in_days": self.expires_in_days,
            "error": self.error,
            "timing_ms": self.timing_ms,
        }


def _cert_to_info(cert: x509.Certificate) -> CertInfo:
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n) for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        san=sans,
        serial=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(cert.signature_hash_algorithm).hex()
        if cert.signature_hash_algorithm
        else None,
    )


class TLSLaboratory:
    def __init__(self, timeout_s: float = 10.0) -> None:
        self.timeout_s = timeout_s

    def inspect(self, host: str, port: int = 443) -> TLSResult:
        result = TLSResult(host=host, port=port)
        t0 = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            # Never disable verification as a convenience feature
            with socket.create_connection((host, port), timeout=self.timeout_s) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result.connected = True
                    result.tls_version = ssock.version()
                    cipher = ssock.cipher()
                    result.cipher = cipher[0] if cipher else None
                    result.hostname_ok = True  # wrap_socket would have raised

                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        info = _cert_to_info(cert)
                        result.chain.append(info)
                        now = datetime.now(timezone.utc)
                        delta = cert.not_valid_after_utc - now
                        result.expires_in_days = delta.total_seconds() / 86400.0

        except ssl.SSLCertVerificationError as e:
            result.error = f"certificate verification failed: {e}"
            result.hostname_ok = False
        except ssl.SSLError as e:
            result.error = f"TLS error: {e}"
        except socket.timeout:
            result.error = "timeout"
        except OSError as e:
            result.error = f"connection error: {e}"
        except Exception as e:
            result.error = str(e)

        result.timing_ms = (time.monotonic() - t0) * 1000
        return result
