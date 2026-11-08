from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from backend.app.models.artefact import Artefact, ArtefactType, Location
from backend.app.scanners.base import BaseScanner, register_scanner
from backend.app.services.catalogue_service import catalogue_service

logger = logging.getLogger(__name__)

SKIP_DIRECTORIES: Set[str] = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "ENV",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


@register_scanner("certificate_scanner")
class CertificateScanner(BaseScanner):
    """
    Scanner for finding and parsing X.509 digital certificates.
    Inspects .pem, .crt, .cer, .der, .p12 files to evaluate key algorithms,
    signature hashes, expiration horizons, and self-signed status.
    """

    name: str = "certificate_scanner"
    description: str = "X.509 Certificate discovery and security analyzer"
    supported_extensions: List[str] = [".pem", ".crt", ".cer", ".der", ".p12", ".pfx"]

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        files_to_scan: List[Path] = []
        if target.is_file():
            files_to_scan.append(target)
        else:
            for item in target.rglob("*"):
                if any(part in SKIP_DIRECTORIES for part in item.parts):
                    continue
                if item.is_file() and (self.can_handle(item) or item.suffix.lower() in self.supported_extensions):
                    files_to_scan.append(item)

        artefacts: List[Artefact] = []
        for file_path in files_to_scan:
            try:
                found = self._scan_cert_file(file_path)
                artefacts.extend(found)
            except Exception as e:
                logger.warning(f"Error parsing certificate in {file_path}: {e}")

        return artefacts

    def _scan_cert_file(self, file_path: Path) -> List[Artefact]:
        ext = file_path.suffix.lower()
        data = file_path.read_bytes()

        certs: List[Tuple[x509.Certificate, int]] = []

        # Try parsing PEM certificates first
        if b"-----BEGIN CERTIFICATE-----" in data:
            try:
                # Find line number where certificate begins
                lines = data.decode("utf-8", errors="ignore").splitlines()
                start_lines = [i + 1 for i, l in enumerate(lines) if "-----BEGIN CERTIFICATE-----" in l]
                loaded = x509.load_pem_x509_certificates(data)
                for idx, cert in enumerate(loaded):
                    line_no = start_lines[idx] if idx < len(start_lines) else 1
                    certs.append((cert, line_no))
            except Exception as e:
                logger.debug(f"Failed loading PEM certs from {file_path}: {e}")

        # Try parsing DER if PEM didn't yield or for .der/.cer
        if not certs and ext in {".der", ".cer"}:
            try:
                cert = x509.load_der_x509_certificate(data)
                certs.append((cert, 1))
            except Exception as e:
                logger.debug(f"Failed loading DER cert from {file_path}: {e}")

        results: List[Artefact] = []
        now = datetime.now(timezone.utc)

        for cert, line_no in certs:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            self_signed = (cert.subject == cert.issuer)

            # Public key extraction
            pub_key = cert.public_key()
            algo_name = "Unknown"
            key_size: Optional[int] = None
            curve_name: Optional[str] = None

            if isinstance(pub_key, rsa.RSAPublicKey):
                algo_name = "RSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                algo_name = "ECDSA"
                key_size = pub_key.key_size
                curve_name = pub_key.curve.name
            elif isinstance(pub_key, dsa.DSAPublicKey):
                algo_name = "DSA"
                key_size = pub_key.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                algo_name = "Ed25519"
                key_size = 256

            # Signature algorithm
            sig_algo = getattr(cert.signature_algorithm_oid, "_name", "Unknown")

            # Validity dates
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                # Compatibility with older cryptography versions
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_until_expiry = (not_after - now).days
            version_name = f"v{cert.version.value + 1}" if hasattr(cert.version, "value") else str(cert.version)

            evidence_summary = (
                f"Subject: {subject} | Issuer: {issuer} | Algorithm: {algo_name}-{key_size} | "
                f"Sig: {sig_algo} | Expires: {not_after.strftime('%Y-%m-%d')} ({days_until_expiry}d)"
            )

            metadata: Dict[str, Any] = {
                "subject": subject,
                "issuer": issuer,
                "self_signed": self_signed,
                "public_key_algorithm": algo_name,
                "public_key_size": key_size,
                "signature_algorithm": sig_algo,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_until_expiry": days_until_expiry,
                "serial_number": str(cert.serial_number),
            }
            if curve_name:
                metadata["curve"] = curve_name

            artefact = Artefact(
                type=ArtefactType.CERTIFICATE,
                name=algo_name,
                version=version_name,
                key_size=key_size,
                location=Location(file=str(file_path), line=line_no),
                detection_method="x509_parser",
                evidence=evidence_summary,
                confidence=1.0,
                metadata=metadata,
            )

            # Enrich with quantum status from catalogue
            enriched = catalogue_service.enrich_artefact(artefact)
            results.append(enriched)

        return results
