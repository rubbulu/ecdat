from __future__ import annotations

import logging
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.scanners.base import BaseScanner, register_scanner
from backend.app.services.catalogue_service import catalogue_service

logger = logging.getLogger(__name__)

# Try importing lief for deep ELF/PE/Mach-O symbol parsing
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    lief = None
    LIEF_AVAILABLE = False

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

# Cryptographic algorithm constants (byte signatures)
CRYPTO_CONSTANTS = [
    {
        "name": "SHA-256",
        "type": ArtefactType.ALGORITHM,
        "quantum_status": QuantumStatus.QUANTUM_SAFE,
        "description": "SHA-256 Initial Hash State Constants (H0..H3)",
        # Little-endian & Big-endian first 16 bytes of SHA-256 IV
        "patterns": [
            b"\x67\xe6\x09\x6a\x85\xae\x67\xbb\x72\xf3\x6e\x3c\x3a\xf5\x4f\xa5",
            b"\x6a\x09\xe6\x67\xbb\x67\xae\x85\x3c\x6e\xf3\x72\xa5\x4f\xf5\x3a",
        ],
    },
    {
        "name": "MD5",
        "type": ArtefactType.ALGORITHM,
        "quantum_status": QuantumStatus.CLASSICALLY_BROKEN,
        "description": "MD5 Initial State Constants (A, B, C, D)",
        # Little-endian & Big-endian MD5 IV
        "patterns": [
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
            b"\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76",
        ],
    },
    {
        "name": "AES",
        "type": ArtefactType.ALGORITHM,
        "quantum_status": QuantumStatus.QUANTUM_SAFE,
        "description": "AES Rijndael Forward S-box Table Signature",
        "patterns": [
            b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76",
        ],
    },
]

# Known crypto functions / symbols in compiled binaries
CRYPTO_SYMBOLS_PATTERNS = [
    (re.compile(r"\b(EVP_aes_128_[a-z]+)\b"), "AES-128", ArtefactType.ALGORITHM, 128),
    (re.compile(r"\b(EVP_aes_192_[a-z]+)\b"), "AES-192", ArtefactType.ALGORITHM, 192),
    (re.compile(r"\b(EVP_aes_256_[a-z]+)\b"), "AES-256", ArtefactType.ALGORITHM, 256),
    (re.compile(r"\b(EVP_des_ede3_[a-z]+)\b"), "3DES", ArtefactType.ALGORITHM, 168),
    (re.compile(r"\b(EVP_des_[a-z]+)\b"), "DES", ArtefactType.ALGORITHM, 56),
    (re.compile(r"\b(EVP_rc4)\b"), "RC4", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(RSA_generate_key|RSA_generate_key_ex|RSA_new|RSA_public_encrypt)\b"), "RSA", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(EC_KEY_new|ECDSA_do_sign|EC_KEY_generate_key)\b"), "ECDSA", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(DH_generate_parameters|DH_compute_key|DH_new)\b"), "DH", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(MD5_Init|MD5_Update|MD5_Final)\b"), "MD5", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(SHA1_Init|SHA1_Update|SHA1_Final)\b"), "SHA-1", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(SHA256_Init|SHA256_Update|SHA256_Final)\b"), "SHA-256", ArtefactType.ALGORITHM, None),
    (re.compile(r"\b(SHA384_Init|SHA512_Init)\b"), "SHA-512", ArtefactType.ALGORITHM, None),
]

# Shared library linkage regex
SHARED_LIB_PATTERN = re.compile(
    r"\b(libcrypto(?:\.so(?:\.\d+)*|\.dylib)?|libssl(?:\.so(?:\.\d+)*|\.dylib)?|crypt32\.dll|bcrypt\.dll|libsodium(?:\.so|\.dylib)?|libwolfssl(?:\.so|\.dylib)?)\b",
    re.IGNORECASE,
)

# OpenSSL version string regex
OPENSSL_VERSION_PATTERN = re.compile(
    r"\b(OpenSSL\s+(?:[0-9]+\.[0-9]+\.[0-9]+[a-z]?|[0-9]+\.[0-9]+\.[0-9]+))\b",
    re.IGNORECASE,
)


@register_scanner("binary_scanner")
class BinaryScanner(BaseScanner):
    """
    Static Binary & Shared Library Cryptographic Scanner.
    Extracts symbols, linked libraries, version banners, and cryptographic constants
    from ELF, PE, Mach-O binaries and shared libraries (.so, .dll, .dylib).
    Safety: Never executes target binaries; inspects headers, symbol tables, and bytes statically.
    """

    name: str = "binary_scanner"
    description: str = "ELF/PE/Mach-O binary symbol, library linkage, and constant analyzer"
    supported_extensions: List[str] = [
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".o",
        ".a",
        "",
    ]

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        files_to_scan: List[Path] = []
        if target.is_file():
            if self._is_binary_file(target):
                files_to_scan.append(target)
        else:
            for item in target.rglob("*"):
                if any(part in SKIP_DIRECTORIES for part in item.parts):
                    continue
                if item.is_file() and self._is_binary_file(item):
                    files_to_scan.append(item)

        artefacts: List[Artefact] = []
        for file_path in files_to_scan:
            try:
                found = self._scan_binary(file_path)
                artefacts.extend(found)
            except Exception as e:
                logger.warning(f"Error scanning binary {file_path}: {e}")

        return artefacts

    def _is_binary_file(self, path: Path) -> bool:
        ext = path.suffix.lower()
        if ext in {".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a"}:
            return True

        # Check binary magic signatures for extensionless executables
        try:
            with open(path, "rb") as f:
                header = f.read(4)
                if header.startswith(b"\x7fELF"):  # ELF
                    return True
                if header.startswith(b"MZ"):      # PE
                    return True
                if header in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:  # Mach-O
                    return True
        except Exception:
            pass

        return False

    def _extract_printable_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from raw binary bytes."""
        ascii_strings = re.findall(rb"[ -~]{" + str(min_length).encode() + rb",}", data)
        return [s.decode("ascii", errors="ignore") for s in ascii_strings]

    def _scan_binary(self, file_path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        raw_bytes = file_path.read_bytes()

        # 1. Detect Cryptographic Constants / Byte Signatures
        for const in CRYPTO_CONSTANTS:
            for pat in const["patterns"]:
                idx = raw_bytes.find(pat)
                if idx != -1:
                    art = Artefact(
                        type=const["type"],
                        name=const["name"],
                        location=Location(file=str(file_path), line=1),
                        detection_method="binary_constant_signature",
                        evidence=f"Byte offset 0x{idx:08x}: {const['description']}",
                        confidence=0.99,
                        quantum_status=const["quantum_status"],
                        metadata={"byte_offset": hex(idx), "constant_name": const["name"]},
                    )
                    results.append(catalogue_service.enrich_artefact(art))
                    break

        # 2. Extract Imported Libraries and Symbols via LIEF (if available)
        lief_symbols: Set[str] = set()
        lief_libraries: Set[str] = set()

        if LIEF_AVAILABLE:
            try:
                parsed = lief.parse(str(file_path))
                if parsed:
                    # Linked libraries
                    for lib in parsed.libraries:
                        lief_libraries.add(str(lib))

                    # Symbols / imported functions
                    if hasattr(parsed, "symbols"):
                        for sym in parsed.symbols:
                            lief_symbols.add(sym.name)
                    if hasattr(parsed, "imported_functions"):
                        for func in parsed.imported_functions:
                            lief_symbols.add(func)
            except Exception as e:
                logger.debug(f"LIEF parsing failed on {file_path}, falling back to pure strings: {e}")

        # 3. String extraction for fallback / supplementary detection
        strings = self._extract_printable_strings(raw_bytes)
        string_blob = "\n".join(strings)

        # A. Check library linkage (LIEF + String match)
        detected_libs = set(lief_libraries)
        for match in SHARED_LIB_PATTERN.finditer(string_blob):
            detected_libs.add(match.group(1))

        for lib_name in detected_libs:
            m = SHARED_LIB_PATTERN.search(lib_name)
            if m:
                clean_name = m.group(1)
                art = Artefact(
                    type=ArtefactType.LIBRARY,
                    name=clean_name,
                    location=Location(file=str(file_path), line=1),
                    detection_method="binary_linkage" if lib_name in lief_libraries else "binary_strings",
                    evidence=f"Linked cryptographic library: {lib_name}",
                    confidence=0.98 if lib_name in lief_libraries else 0.88,
                    quantum_status=QuantumStatus.VULNERABLE_SHOR,
                    metadata={"library": lib_name},
                )
                results.append(art)

        # B. Check OpenSSL version banner strings
        for match in OPENSSL_VERSION_PATTERN.finditer(string_blob):
            ver_str = match.group(1)
            q_status = QuantumStatus.VULNERABLE_SHOR
            is_eol = False

            if any(legacy in ver_str for legacy in ["0.9.", "1.0.", "1.1.0"]):
                q_status = QuantumStatus.CLASSICALLY_BROKEN
                is_eol = True

            art = Artefact(
                type=ArtefactType.LIBRARY,
                name="OpenSSL",
                version=ver_str,
                location=Location(file=str(file_path), line=1),
                detection_method="binary_version_banner",
                evidence=f"Embedded OpenSSL banner: {ver_str}",
                confidence=0.98,
                quantum_status=q_status,
                notes="End-of-Life / Insecure legacy OpenSSL version" if is_eol else "Vulnerable to Shor's algorithm for public-key operations",
                metadata={"version_banner": ver_str, "is_eol": is_eol},
            )
            results.append(art)

        # C. Check crypto function symbols / API calls (LIEF symbols + regex search)
        detected_symbols: Set[str] = set(lief_symbols)
        for regex, algo_name, art_type, key_size in CRYPTO_SYMBOLS_PATTERNS:
            found_symbol = None

            # Check LIEF symbols first
            for s in lief_symbols:
                if regex.search(s):
                    found_symbol = s
                    break

            # Fall back to extracted strings
            if not found_symbol:
                m = regex.search(string_blob)
                if m:
                    found_symbol = m.group(1)

            if found_symbol:
                art = Artefact(
                    type=art_type,
                    name=algo_name,
                    key_size=key_size,
                    location=Location(file=str(file_path), line=1),
                    detection_method="binary_symbol_table" if found_symbol in lief_symbols else "binary_strings",
                    evidence=f"Discovered cryptographic symbol: {found_symbol}",
                    confidence=0.95 if found_symbol in lief_symbols else 0.85,
                    metadata={"symbol": found_symbol},
                )
                results.append(catalogue_service.enrich_artefact(art))

        return results
