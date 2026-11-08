from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.scanners.base import BaseScanner, register_scanner

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

# Known cryptographic libraries catalog with deprecation & risk advisories
CRYPTO_LIBRARIES: Dict[str, Dict[str, Any]] = {
    # Python
    "pycrypto": {
        "canonical": "pycrypto",
        "ecosystem": "Python",
        "deprecated": True,
        "risk": "Critical: Unmaintained since 2013, known security vulnerabilities (CVE-2013-7459). Replace with pycryptodome or cryptography.",
        "quantum_status": QuantumStatus.CLASSICALLY_BROKEN,
    },
    "pycryptodome": {
        "canonical": "pycryptodome",
        "ecosystem": "Python",
        "deprecated": False,
        "risk": "Active library. Contains classical public-key primitives vulnerable to Shor's algorithm.",
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "pycryptodomex": {
        "canonical": "pycryptodome",
        "ecosystem": "Python",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "cryptography": {
        "canonical": "cryptography",
        "ecosystem": "Python",
        "deprecated": False,
        "risk": "Modern standard. Classical primitives require migration to PQC (ML-KEM/ML-DSA).",
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "pyopenssl": {
        "canonical": "pyOpenSSL",
        "ecosystem": "Python",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "bcrypt": {
        "canonical": "bcrypt",
        "ecosystem": "Multi",
        "deprecated": False,
        "quantum_status": QuantumStatus.QUANTUM_SAFE,
    },
    "pynacl": {
        "canonical": "pynacl",
        "ecosystem": "Python",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "rsa": {
        "canonical": "rsa",
        "ecosystem": "Python",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    # JavaScript / Node.js
    "crypto-js": {
        "canonical": "crypto-js",
        "ecosystem": "Node.js",
        "deprecated": True,
        "risk": "High: Weak PRNG and insecure PBKDF2 defaults in older versions (<4.2.0); unmaintained. Replace with Web Crypto API.",
        "quantum_status": QuantumStatus.CLASSICALLY_BROKEN,
    },
    "node-forge": {
        "canonical": "node-forge",
        "ecosystem": "Node.js",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "sjcl": {
        "canonical": "sjcl",
        "ecosystem": "Node.js",
        "deprecated": True,
        "risk": "High: Stanford Javascript Crypto Library is deprecated and unmaintained.",
        "quantum_status": QuantumStatus.CLASSICALLY_BROKEN,
    },
    "elliptic": {
        "canonical": "elliptic",
        "ecosystem": "Node.js",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "tweetnacl": {
        "canonical": "tweetnacl",
        "ecosystem": "Node.js",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "jsonwebtoken": {
        "canonical": "jsonwebtoken",
        "ecosystem": "Node.js",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    # Java
    "bouncycastle": {
        "canonical": "bouncycastle",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "bcprov-jdk15on": {
        "canonical": "bouncycastle",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "bcprov-jdk18on": {
        "canonical": "bouncycastle",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "bcpkix-jdk15on": {
        "canonical": "bouncycastle",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "commons-crypto": {
        "canonical": "commons-crypto",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.QUANTUM_SAFE,
    },
    "jasypt": {
        "canonical": "jasypt",
        "ecosystem": "Java",
        "deprecated": False,
        "quantum_status": QuantumStatus.CLASSICALLY_BROKEN,
    },
    # Go
    "golang.org/x/crypto": {
        "canonical": "golang.org/x/crypto",
        "ecosystem": "Go",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    # Ruby
    "openssl": {
        "canonical": "openssl",
        "ecosystem": "Ruby",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "jwt": {
        "canonical": "jwt",
        "ecosystem": "Ruby",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
    "rbnacl": {
        "canonical": "rbnacl",
        "ecosystem": "Ruby",
        "deprecated": False,
        "quantum_status": QuantumStatus.VULNERABLE_SHOR,
    },
}


@register_scanner("dependency_scanner")
class DependencyScanner(BaseScanner):
    """
    Scanner for package manifests across multiple package managers:
    - Python: requirements.txt, Pipfile, pyproject.toml
    - Node.js: package.json
    - Java: pom.xml
    - Go: go.mod
    - Ruby: Gemfile
    Flags cryptographic libraries, extracts versions, and tags deprecated/risky dependencies.
    """

    name: str = "dependency_scanner"
    description: str = "Package manifest and cryptographic library dependency analyzer"
    supported_extensions: List[str] = [".txt", ".json", ".xml", ".mod", ""]

    MANIFEST_NAMES = {
        "requirements.txt",
        "package.json",
        "pom.xml",
        "go.mod",
        "Gemfile",
        "Pipfile",
    }

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        manifests: List[Path] = []
        if target.is_file():
            if target.name in self.MANIFEST_NAMES:
                manifests.append(target)
        else:
            for item in target.rglob("*"):
                if any(part in SKIP_DIRECTORIES for part in item.parts):
                    continue
                if item.is_file() and item.name in self.MANIFEST_NAMES:
                    manifests.append(item)

        artefacts: List[Artefact] = []
        for mf in manifests:
            try:
                if mf.name == "requirements.txt":
                    artefacts.extend(self._scan_requirements_txt(mf))
                elif mf.name == "package.json":
                    artefacts.extend(self._scan_package_json(mf))
                elif mf.name == "pom.xml":
                    artefacts.extend(self._scan_pom_xml(mf))
                elif mf.name == "go.mod":
                    artefacts.extend(self._scan_go_mod(mf))
                elif mf.name == "Gemfile":
                    artefacts.extend(self._scan_gemfile(mf))
            except Exception as e:
                logger.warning(f"Error parsing manifest {mf}: {e}")

        return artefacts

    def _match_crypto_lib(self, raw_name: str) -> Optional[Dict[str, Any]]:
        norm = raw_name.strip().lower()
        if norm in CRYPTO_LIBRARIES:
            return CRYPTO_LIBRARIES[norm]

        for k, v in CRYPTO_LIBRARIES.items():
            if norm == k or norm.startswith(f"{k}-") or norm.endswith(f"-{k}"):
                return v

        return None

    def _scan_requirements_txt(self, path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

        for line_no, line in enumerate(lines, start=1):
            cleaned = line.split("#")[0].strip()
            if not cleaned:
                continue

            # Parse package name and version
            m = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:(==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z\.\-]+))?", cleaned)
            if not m:
                continue

            pkg_name = m.group(1)
            version = m.group(3)

            lib_info = self._match_crypto_lib(pkg_name)
            if lib_info:
                results.append(self._create_artefact(path, line_no, pkg_name, version, line.strip(), lib_info))

        return results

    def _scan_package_json(self, path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        try:
            data = json.loads(content)
        except Exception:
            return []

        all_deps: Dict[str, str] = {}
        if "dependencies" in data and isinstance(data["dependencies"], dict):
            all_deps.update(data["dependencies"])
        if "devDependencies" in data and isinstance(data["devDependencies"], dict):
            all_deps.update(data["devDependencies"])

        for pkg_name, version in all_deps.items():
            lib_info = self._match_crypto_lib(pkg_name)
            if lib_info:
                # Find line number in file
                line_no = 1
                for i, l in enumerate(lines, start=1):
                    if f'"{pkg_name}"' in l:
                        line_no = i
                        break

                evidence = f'"{pkg_name}": "{version}"'
                results.append(self._create_artefact(path, line_no, pkg_name, str(version), evidence, lib_info))

        return results

    def _scan_pom_xml(self, path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        try:
            # Strip namespaces for simple parsing
            xml_text = re.sub(r'\sxmlns="[^"]+"', "", content, count=1)
            root = ET.fromstring(xml_text)
        except Exception:
            return []

        for dep in root.findall(".//dependency"):
            group_el = dep.find("groupId")
            artifact_el = dep.find("artifactId")
            version_el = dep.find("version")

            group_id = group_el.text.strip() if group_el is not None and group_el.text else ""
            artifact_id = artifact_el.text.strip() if artifact_el is not None and artifact_el.text else ""
            version = version_el.text.strip() if version_el is not None and version_el.text else ""

            # Check both artifactId and groupId
            lib_info = self._match_crypto_lib(artifact_id) or self._match_crypto_lib(group_id)
            if lib_info:
                line_no = 1
                for i, l in enumerate(lines, start=1):
                    if artifact_id and artifact_id in l:
                        line_no = i
                        break

                evidence = f"<dependency><groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId><version>{version}</version></dependency>"
                results.append(self._create_artefact(path, line_no, artifact_id or group_id, version, evidence, lib_info))

        return results

    def _scan_go_mod(self, path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

        for line_no, line in enumerate(lines, start=1):
            cleaned = line.strip()
            # Match: require golang.org/x/crypto v0.14.0 or inside require block: golang.org/x/crypto v0.14.0
            m = re.match(r"^(?:require\s+)?([a-zA-Z0-9_\-\./]+)\s+([v0-9a-zA-Z\.\-]+)", cleaned)
            if not m:
                continue

            mod_name = m.group(1)
            version = m.group(2)

            lib_info = self._match_crypto_lib(mod_name)
            if lib_info:
                results.append(self._create_artefact(path, line_no, mod_name, version, line.strip(), lib_info))

        return results

    def _scan_gemfile(self, path: Path) -> List[Artefact]:
        results: List[Artefact] = []
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

        for line_no, line in enumerate(lines, start=1):
            cleaned = line.strip()
            m = re.match(r"^gem\s+['\"]([a-zA-Z0-9_\-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", cleaned)
            if not m:
                continue

            gem_name = m.group(1)
            version = m.group(2) or ""

            lib_info = self._match_crypto_lib(gem_name)
            if lib_info:
                results.append(self._create_artefact(path, line_no, gem_name, version, line.strip(), lib_info))

        return results

    def _create_artefact(
        self,
        file_path: Path,
        line_no: int,
        pkg_name: str,
        version: Optional[str],
        evidence: str,
        lib_info: Dict[str, Any],
    ) -> Artefact:
        canonical = lib_info.get("canonical", pkg_name)
        is_deprecated = lib_info.get("deprecated", False)
        risk = lib_info.get("risk", "")
        quantum_status = lib_info.get("quantum_status")

        metadata = {
            "manifest": file_path.name,
            "ecosystem": lib_info.get("ecosystem", "Unknown"),
            "canonical_name": canonical,
            "is_deprecated": is_deprecated,
            "risk_advisory": risk,
        }

        # Notes for human analysis
        notes = f"Ecosystem: {lib_info.get('ecosystem')}. "
        if is_deprecated:
            notes += f"[DEPRECATED/INSECURE] {risk}"
        elif risk:
            notes += risk

        return Artefact(
            type=ArtefactType.LIBRARY,
            name=canonical,
            version=version,
            location=Location(file=str(file_path), line=line_no),
            detection_method="dependency_manifest",
            evidence=evidence,
            confidence=1.0,
            quantum_status=quantum_status,
            notes=notes,
            metadata=metadata,
        )
