from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
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

# Regex patterns for infrastructure and server configuration files
CONFIG_PATTERNS = [
    # 1. Nginx / Apache TLS Protocols
    {
        "id": "tls_protocols_directive",
        "pattern": re.compile(r"(?i)\b(?:ssl_protocols|SSLProtocol)\s+([^;\n]+)"),
        "type": "protocol",
        "handler": "tls_protocol_tokens",
    },
    # 2. Nginx / Apache Cipher Suites
    {
        "id": "ssl_ciphers_directive",
        "pattern": re.compile(r"(?i)\b(?:ssl_ciphers|SSLCipherSuite)\s+[\"']?([^;\"'\n]+)[\"']?"),
        "type": "algorithm",
        "handler": "cipher_suite_tokens",
    },
    # 3. SSH Configuration (Kex, HostKey, Ciphers, MACs)
    {
        "id": "ssh_algorithm_directive",
        "pattern": re.compile(r"(?i)\b(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs)\s+([^\n#]+)"),
        "type": "protocol",
        "handler": "ssh_tokens",
    },
    # 4. OpenSSL Configuration MinProtocol
    {
        "id": "openssl_min_protocol",
        "pattern": re.compile(r"(?i)\b(?:MinProtocol|MaxProtocol)\s*=\s*(TLSv?1(?:\.[0-3])?|SSLv[23])\b"),
        "type": "protocol",
        "handler": "direct_token",
    },
    # 5. Environment variable crypto settings
    {
        "id": "env_crypto_setting",
        "pattern": re.compile(r"(?i)\b(SSL_VERSION|TLS_MIN_VERSION|CIPHER|CIPHER_SUITE|JWT_ALGORITHM|ENCRYPTION_ALGORITHM)\s*=\s*[\"']?([^\"'\n\r#\s]+)[\"']?"),
        "type": "algorithm",
        "handler": "env_tokens",
    },
]

WEAK_CIPHER_KEYWORDS = {
    "RC4": "RC4",
    "3DES": "3DES",
    "DES": "DES",
    "DES-CBC3": "3DES",
    "MD5": "MD5",
    "EXPORT": "DES",
    "NULL": "NULL",
    "AES128-SHA": "AES-128",
    "AES256-SHA": "AES-256",
}


@register_scanner("config_scanner")
class ConfigScanner(BaseScanner):
    """
    Scanner for infrastructure and application configurations:
    - Nginx / Apache configs (*.conf, httpd.conf)
    - OpenSSH configs (sshd_config, ssh_config)
    - OpenSSL configuration (openssl.cnf)
    - Environment configs (.env, *.yaml, *.yml)
    Evaluates TLS minimum protocols, cipher suites, and SSH cryptographic primitives.
    """

    name: str = "config_scanner"
    description: str = "Infrastructure configuration and TLS/SSH cryptographic profile scanner"
    supported_extensions: List[str] = [
        ".conf",
        ".cnf",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".env",
        "",
    ]

    CONFIG_FILENAMES = {
        "sshd_config",
        "ssh_config",
        "nginx.conf",
        "httpd.conf",
        "openssl.cnf",
        ".env",
    }

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        files_to_scan: List[Path] = []
        if target.is_file():
            if self._is_config_file(target):
                files_to_scan.append(target)
        else:
            for item in target.rglob("*"):
                if any(part in SKIP_DIRECTORIES for part in item.parts):
                    continue
                if item.is_file() and self._is_config_file(item):
                    files_to_scan.append(item)

        artefacts: List[Artefact] = []
        for file_path in files_to_scan:
            try:
                found = self._scan_file(file_path)
                artefacts.extend(found)
            except Exception as e:
                logger.warning(f"Error scanning config file {file_path}: {e}")

        return artefacts

    def _is_config_file(self, path: Path) -> bool:
        if path.name in self.CONFIG_FILENAMES or path.name.startswith(".env"):
            return True
        ext = path.suffix.lower()
        return ext in {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml"}

    def _scan_file(self, file_path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for rule in CONFIG_PATTERNS:
                match = rule["pattern"].search(stripped)
                if not match:
                    continue

                handler = rule["handler"]

                # 1. TLS Protocols
                if handler == "tls_protocol_tokens":
                    raw_tokens = match.group(1).split()
                    for token in raw_tokens:
                        clean_token = token.strip("+").strip()
                        if clean_token.startswith("-"):
                            continue  # Excluded protocol (e.g. -SSLv3)

                        norm_token = self._normalize_protocol_name(clean_token)
                        if norm_token:
                            artefact = Artefact(
                                type=ArtefactType.PROTOCOL,
                                name=norm_token,
                                location=Location(file=str(file_path), line=line_no),
                                detection_method="config_directive",
                                evidence=stripped,
                                confidence=0.98,
                                metadata={"directive": "ssl_protocols", "raw": clean_token},
                            )
                            results.append(catalogue_service.enrich_artefact(artefact))

                # 2. Cipher Suites
                elif handler == "cipher_suite_tokens":
                    raw_ciphers = match.group(1).replace(":", " ").replace("+", " ").split()
                    for token in raw_ciphers:
                        clean_token = token.strip("!").strip("-").strip()
                        if not clean_token or clean_token.startswith("!"):
                            continue

                        # Check known weak/classical cipher keywords
                        for kw, canonical in WEAK_CIPHER_KEYWORDS.items():
                            if kw in clean_token.upper():
                                artefact = Artefact(
                                    type=ArtefactType.ALGORITHM,
                                    name=canonical,
                                    location=Location(file=str(file_path), line=line_no),
                                    detection_method="config_directive",
                                    evidence=stripped,
                                    confidence=0.95,
                                    metadata={"directive": "ssl_ciphers", "cipher_spec": clean_token},
                                )
                                results.append(catalogue_service.enrich_artefact(artefact))
                                break

                # 3. SSH Algorithms
                elif handler == "ssh_tokens":
                    directive = match.group(1)
                    algo_list = [a.strip() for a in match.group(2).split(",") if a.strip()]

                    for algo in algo_list:
                        canonical_name, q_status, primitive = self._categorize_ssh_algorithm(algo)
                        artefact = Artefact(
                            type=ArtefactType.PROTOCOL if "diffie-hellman" in algo or "kex" in directive.lower() else ArtefactType.ALGORITHM,
                            name=canonical_name,
                            location=Location(file=str(file_path), line=line_no),
                            detection_method="sshd_config",
                            evidence=stripped,
                            confidence=0.98,
                            quantum_status=q_status,
                            metadata={"ssh_directive": directive, "raw_algorithm": algo, "primitive": primitive},
                        )
                        results.append(catalogue_service.enrich_artefact(artefact))

                # 4. Direct token (OpenSSL MinProtocol)
                elif handler == "direct_token":
                    proto = match.group(1)
                    norm_proto = self._normalize_protocol_name(proto)
                    artefact = Artefact(
                        type=ArtefactType.PROTOCOL,
                        name=norm_proto,
                        location=Location(file=str(file_path), line=line_no),
                        detection_method="openssl_cnf",
                        evidence=stripped,
                        confidence=0.95,
                        metadata={"raw": proto},
                    )
                    results.append(catalogue_service.enrich_artefact(artefact))

                # 5. Environment variable
                elif handler == "env_tokens":
                    var_name = match.group(1)
                    var_val = match.group(2)

                    norm_name = self._normalize_protocol_name(var_val) or var_val
                    artefact = Artefact(
                        type=ArtefactType.PROTOCOL if "TLS" in var_val.upper() or "SSL" in var_val.upper() else ArtefactType.ALGORITHM,
                        name=norm_name,
                        location=Location(file=str(file_path), line=line_no),
                        detection_method="env_variable",
                        evidence=stripped,
                        confidence=0.90,
                        metadata={"variable": var_name, "raw_value": var_val},
                    )
                    results.append(catalogue_service.enrich_artefact(artefact))

        return results

    def _normalize_protocol_name(self, token: str) -> str:
        t = token.upper().replace("V", " ").replace(".", " ").split()
        joined = "".join(t)
        if "SSL3" in joined or "SSLV3" in joined:
            return "SSLv3"
        elif "TLS10" in joined or "TLS1" in joined and "1" not in joined[4:]:
            return "TLS 1.0"
        elif "TLS11" in joined:
            return "TLS 1.1"
        elif "TLS12" in joined:
            return "TLS 1.2"
        elif "TLS13" in joined:
            return "TLS 1.3"
        return token

    def _categorize_ssh_algorithm(self, algo: str) -> Tuple[str, QuantumStatus, str]:
        a = algo.lower()
        if "diffie-hellman" in a or "kex" in a:
            return "DH", QuantumStatus.VULNERABLE_SHOR, "Key Exchange"
        elif "ssh-rsa" in a:
            return "RSA", QuantumStatus.VULNERABLE_SHOR, "Host Key"
        elif "ssh-dss" in a:
            return "DSA", QuantumStatus.VULNERABLE_SHOR, "Host Key"
        elif "ecdsa" in a:
            return "ECDSA", QuantumStatus.VULNERABLE_SHOR, "Host Key"
        elif "3des" in a:
            return "3DES", QuantumStatus.CLASSICALLY_BROKEN, "Symmetric Cipher"
        elif "arcfour" in a:
            return "RC4", QuantumStatus.CLASSICALLY_BROKEN, "Stream Cipher"
        elif "aes" in a:
            return "AES", QuantumStatus.QUANTUM_SAFE, "Symmetric Cipher"
        return algo, QuantumStatus.VULNERABLE_SHOR, "SSH Primitive"
