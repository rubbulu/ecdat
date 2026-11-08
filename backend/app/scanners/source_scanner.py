from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import yaml

from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.scanners.base import BaseScanner, register_scanner
from backend.app.services.catalogue_service import catalogue_service

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "rules.yaml"

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
    ".egg-info",
    ".idea",
    ".vscode",
}

MODE_PATTERN = re.compile(r"\b(GCM|CBC|ECB|CTR|CFB|OFB|CCM|XTS)\b", re.IGNORECASE)
KEY_SIZE_PATTERN = re.compile(r"\b(128|192|256|512|1024|2048|3072|4096)\b")


class PythonCryptoASTVisitor(ast.NodeVisitor):
    """
    AST visitor for Python files to accurately extract algorithm, key size,
    curve names, and cipher modes without regex fragility.
    """

    def __init__(self, filename: str, lines: List[str]):
        self.filename = filename
        self.lines = lines
        self.artefacts: List[Artefact] = []

    def _get_evidence(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        # 1. hashlib.md5(...), hashlib.sha1(...), hashlib.new("md5")
        if isinstance(node.func, ast.Attribute):
            # Check hashlib.<algo>(...)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                algo_name = node.func.attr
                if algo_name == "new" and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        algo_name = first_arg.value

                self.artefacts.append(
                    Artefact(
                        type=ArtefactType.ALGORITHM,
                        name=algo_name.upper(),
                        location=Location(file=self.filename, line=node.lineno),
                        detection_method="ast_parser",
                        evidence=self._get_evidence(node),
                        confidence=0.98,
                    )
                )

            # 2. rsa.generate_private_key(public_exponent=..., key_size=2048)
            elif node.func.attr == "generate_private_key":
                is_rsa = False
                key_size = None

                # Check if rsa module
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "rsa":
                    is_rsa = True

                for kw in node.keywords:
                    if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                        key_size = int(kw.value.value)
                        is_rsa = True

                if is_rsa:
                    self.artefacts.append(
                        Artefact(
                            type=ArtefactType.ALGORITHM,
                            name="RSA",
                            key_size=key_size,
                            location=Location(file=self.filename, line=node.lineno),
                            detection_method="ast_parser",
                            evidence=self._get_evidence(node),
                            confidence=0.99,
                        )
                    )

                # 3. ec.generate_private_key(curve=ec.SECP256R1())
                is_ec = False
                curve_name = None
                curve_key_size = None

                if isinstance(node.func.value, ast.Name) and node.func.value.id == "ec":
                    is_ec = True

                for arg in node.args:
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                        curve_name = arg.func.attr
                        is_ec = True
                    elif isinstance(arg, ast.Attribute):
                        curve_name = arg.attr
                        is_ec = True

                for kw in node.keywords:
                    if kw.arg == "curve":
                        if isinstance(kw.value, ast.Call) and isinstance(kw.value.func, ast.Attribute):
                            curve_name = kw.value.func.attr
                            is_ec = True

                if is_ec:
                    if curve_name:
                        if "256" in curve_name or "P256" in curve_name:
                            curve_key_size = 256
                        elif "384" in curve_name or "P384" in curve_name:
                            curve_key_size = 384
                        elif "521" in curve_name or "P521" in curve_name:
                            curve_key_size = 521

                    self.artefacts.append(
                        Artefact(
                            type=ArtefactType.ALGORITHM,
                            name="ECDSA",
                            version=curve_name,
                            key_size=curve_key_size,
                            location=Location(file=self.filename, line=node.lineno),
                            detection_method="ast_parser",
                            evidence=self._get_evidence(node),
                            confidence=0.99,
                            metadata={"curve": curve_name} if curve_name else {},
                        )
                    )

            # 4. Crypto.Cipher.AES.new(key, AES.MODE_CBC)
            elif node.func.attr == "new":
                cipher_name = None
                mode = None

                if isinstance(node.func.value, ast.Name):
                    cipher_name = node.func.value.id
                elif isinstance(node.func.value, ast.Attribute):
                    cipher_name = node.func.value.attr

                if cipher_name in {"AES", "DES", "DES3", "ARC4", "Blowfish", "ChaCha20"}:
                    # Look for mode in args/kwargs
                    for arg in node.args:
                        if isinstance(arg, ast.Attribute) and "MODE_" in arg.attr:
                            mode = arg.attr.replace("MODE_", "")
                    for kw in node.keywords:
                        if isinstance(kw.value, ast.Attribute) and "MODE_" in kw.value.attr:
                            mode = kw.value.attr.replace("MODE_", "")

                    self.artefacts.append(
                        Artefact(
                            type=ArtefactType.ALGORITHM,
                            name=cipher_name,
                            mode=mode,
                            location=Location(file=self.filename, line=node.lineno),
                            detection_method="ast_parser",
                            evidence=self._get_evidence(node),
                            confidence=0.98,
                        )
                    )

            # 5. jwt.encode(payload, secret, algorithm="RS256")
            elif node.func.attr in {"encode", "decode"}:
                is_jwt = False
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "jwt":
                    is_jwt = True

                if is_jwt:
                    algo = None
                    for kw in node.keywords:
                        if kw.arg == "algorithm" and isinstance(kw.value, ast.Constant):
                            algo = str(kw.value.value)
                    if algo:
                        self.artefacts.append(
                            Artefact(
                                type=ArtefactType.ALGORITHM,
                                name=algo,
                                location=Location(file=self.filename, line=node.lineno),
                                detection_method="ast_parser",
                                evidence=self._get_evidence(node),
                                confidence=0.95,
                            )
                        )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_SSLv23, etc.
        if isinstance(node.value, ast.Name) and node.value.id == "ssl":
            if node.attr.startswith("PROTOCOL_"):
                proto_name = node.attr.replace("PROTOCOL_", "").replace("_", ".")
                self.artefacts.append(
                    Artefact(
                        type=ArtefactType.PROTOCOL,
                        name=proto_name,
                        location=Location(file=self.filename, line=node.lineno),
                        detection_method="ast_parser",
                        evidence=self._get_evidence(node),
                        confidence=0.96,
                    )
                )
        self.generic_visit(node)


@register_scanner("source_scanner")
class SourceScanner(BaseScanner):
    """
    Multi-language cryptographic discovery scanner.
    Combines rule-based regex detection and Python AST parsing to identify
    cryptographic primitives, protocols, libraries, and hardcoded keys.
    """

    name: str = "source_scanner"
    description: str = "Multi-language source code cryptographic scanner"
    supported_extensions: List[str] = [
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".java",
        ".kt",
        ".go",
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".conf",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".json",
    ]

    def __init__(self, config: Optional[Dict] = None, rules_path: Optional[Path] = None):
        super().__init__(config=config)
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            logger.warning(f"Rules YAML file not found at {self.rules_path}")
            return

        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_rules = data.get("rules", [])
        self.rules = []
        for r in raw_rules:
            try:
                compiled = re.compile(r["pattern"])
                self.rules.append({**r, "_regex": compiled})
            except re.error as e:
                logger.error(f"Failed to compile regex rule {r.get('id')}: {e}")

        logger.info(f"Loaded {len(self.rules)} source scanning rules from {self.rules_path}")

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        files_to_scan: List[Path] = []
        if target.is_file():
            files_to_scan.append(target)
        else:
            for item in target.rglob("*"):
                # Skip excluded directories
                if any(part in SKIP_DIRECTORIES for part in item.parts):
                    continue
                if item.is_file() and self.can_handle(item):
                    files_to_scan.append(item)

        results: List[Artefact] = []
        for file_path in files_to_scan:
            try:
                artefacts = self._scan_file(file_path)
                results.extend(artefacts)
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")

        return results

    def _scan_file(self, file_path: Path) -> List[Artefact]:
        artefacts: List[Artefact] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()
        ext = file_path.suffix.lower()

        # 1. If Python, run AST parser first
        ast_hits: Set[Tuple[int, str]] = set()
        if ext == ".py":
            try:
                tree = ast.parse(content, filename=str(file_path))
                visitor = PythonCryptoASTVisitor(filename=str(file_path), lines=lines)
                visitor.visit(tree)
                for a in visitor.artefacts:
                    enriched = catalogue_service.enrich_artefact(a)
                    artefacts.append(enriched)
                    ast_hits.add((a.location.line, a.name.upper()))
            except SyntaxError:
                # Fall back to regex if file has Python syntax error
                pass

        # 2. Run regex rules against each line
        for line_num, line_text in enumerate(lines, start=1):
            for rule in self.rules:
                rule_exts = rule.get("extensions", [])
                if rule_exts and ext not in [e.lower() for e in rule_exts]:
                    continue

                regex: re.Pattern = rule["_regex"]
                match = regex.search(line_text)
                if not match:
                    continue

                # Determine algorithm/primitive name
                algo_name = rule.get("name")
                algo_grp = rule.get("algorithm_group")
                if algo_grp is not None and algo_grp <= len(match.groups()):
                    captured = match.group(algo_grp)
                    if captured:
                        algo_name = captured.strip()

                if not algo_name:
                    algo_name = rule.get("id", "Unknown")

                # Handle PEM private key naming
                if rule.get("id") == "secret_pem_private_key":
                    if "RSA" in algo_name.upper():
                        algo_name = "RSA"
                    elif "DSA" in algo_name.upper():
                        algo_name = "DSA"
                    elif "EC" in algo_name.upper():
                        algo_name = "ECDSA"
                    else:
                        algo_name = "Hardcoded PEM Private Key"

                # Check if algo_name contains mode/ciphersuite (e.g. aes-128-cbc)
                cipher_match = re.match(r"(?i)^(aes-\d+|aes|des|3des|des3|rc4)[-_/]([a-z0-9]+)", algo_name)
                if cipher_match:
                    base_algo = cipher_match.group(1)
                    sub_mode = cipher_match.group(2).upper()
                    if sub_mode in {"CBC", "GCM", "ECB", "CTR", "CFB", "OFB"}:
                        mode = sub_mode
                        algo_name = base_algo

                # Normalize algorithm name (e.g. 'md5' -> 'MD5')
                algo_name_upper = algo_name.upper()

                # If this line was already accurately parsed by Python AST for the same algorithm, skip duplicate
                if (line_num, algo_name_upper) in ast_hits:
                    continue

                # Mode extraction
                mode = None
                mode_grp = rule.get("mode_group")
                if mode_grp is not None and mode_grp <= len(match.groups()):
                    mode = match.group(mode_grp)
                if not mode:
                    mode_m = MODE_PATTERN.search(line_text)
                    if mode_m:
                        mode = mode_m.group(1).upper()

                # Key size extraction
                key_size = rule.get("default_key_size")
                key_grp = rule.get("key_size_group")
                if key_grp is not None and key_grp <= len(match.groups()):
                    val = match.group(key_grp)
                    if val and val.isdigit():
                        key_size = int(val)
                if key_size is None:
                    # Check context (subsequent 6 lines) for modulusLength or key_size
                    context_window = "\n".join(lines[line_num - 1 : min(line_num + 6, len(lines))])
                    mod_match = re.search(r'(?:modulusLength|key_size|initialize)\s*[:=\(]\s*([0-9]{3,5})', context_window)
                    if mod_match:
                        key_size = int(mod_match.group(1))

                if key_size is None:
                    # Check if algorithm itself contains key size (e.g. AES-128)
                    size_m = KEY_SIZE_PATTERN.search(algo_name)
                    if size_m:
                        key_size = int(size_m.group(1))

                # Artefact type
                type_str = rule.get("type", "algorithm")
                try:
                    art_type = ArtefactType(type_str)
                except ValueError:
                    art_type = ArtefactType.ALGORITHM

                artefact = Artefact(
                    type=art_type,
                    name=algo_name,
                    mode=mode,
                    key_size=key_size,
                    location=Location(file=str(file_path), line=line_num),
                    detection_method=rule.get("detection_method", "regex_rule"),
                    evidence=line_text.strip(),
                    confidence=rule.get("confidence", 0.90),
                    metadata={"rule_id": rule.get("id")},
                )

                # Enrich with central catalogue
                enriched = catalogue_service.enrich_artefact(artefact)
                artefacts.append(enriched)

        return artefacts
