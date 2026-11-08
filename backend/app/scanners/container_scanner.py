from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from backend.app.models.artefact import Artefact, Location
from backend.app.scanners.base import BaseScanner, register_scanner
from backend.app.scanners.binary_scanner import BinaryScanner
from backend.app.scanners.certificate_scanner import CertificateScanner
from backend.app.scanners.config_scanner import ConfigScanner
from backend.app.scanners.dependency_scanner import DependencyScanner
from backend.app.scanners.source_scanner import SourceScanner

logger = logging.getLogger(__name__)


@register_scanner("container_scanner")
class ContainerScanner(BaseScanner):
    """
    Static Container Image Cryptographic Discovery Scanner.
    Accepts a Docker image tarball (from 'docker save') or a Docker image name.
    Unpacks image layers, reconstructs the layered container filesystem, and runs
    certificate, dependency, config, binary, and source scanners over the filesystem.
    Records the specific layer ID where each cryptographic artefact originated.
    Safety: Never executes containers or files; purely static tarball analysis.
    """

    name: str = "container_scanner"
    description: str = "Docker image tarball layer unpacker and multi-layer cryptographic scanner"
    supported_extensions: List[str] = [".tar", ".tar.gz", ".tgz", ".tar.xz"]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config=config)
        self.sub_scanners = [
            CertificateScanner(),
            DependencyScanner(),
            ConfigScanner(),
            BinaryScanner(),
            SourceScanner(),
        ]

    def can_handle(self, path: Union[str, Path]) -> bool:
        """Only handle file paths matching tarball extensions or image names."""
        p = Path(path)
        if p.is_file():
            return any(str(p).lower().endswith(ext) for ext in self.supported_extensions)
        # If it's a directory, container scanner does not scan it as an image
        if p.is_dir():
            return False
        # If path doesn't exist on disk, could be image name (e.g. 'ubuntu:latest')
        return True

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        target_str = str(target_path).strip()
        target_path_obj = Path(target_str)

        # 1. Determine if target is an existing tarball file or an image name
        is_tarball = target_path_obj.is_file() and any(
            target_str.lower().endswith(ext) for ext in [".tar", ".tar.gz", ".tgz", ".tar.xz"]
        )

        tmp_dir = tempfile.mkdtemp(prefix="ecdat_container_")
        tmp_tar_path: Optional[Path] = None

        try:
            if is_tarball:
                tar_file = target_path_obj
                image_name = target_path_obj.name
            else:
                # Target is an image name (e.g. 'alpine:latest' or 'my-image')
                image_name = target_str
                docker_cli = shutil.which("docker")
                if not docker_cli:
                    raise RuntimeError(
                        f"Docker CLI is not available on this system to save image '{image_name}'. "
                        "Please export the container image using 'docker save -o <file.tar> <image>' "
                        "and provide the tarball path instead."
                    )

                tmp_tar_path = Path(tmp_dir) / "image_export.tar"
                logger.info(f"Exporting Docker image '{image_name}' to {tmp_tar_path}...")
                proc = subprocess.run(
                    [docker_cli, "save", "-o", str(tmp_tar_path), image_name],
                    capture_output=True,
                    text=True,
                )
                if proc.returncode != 0:
                    raise RuntimeError(
                        f"Failed to export Docker image '{image_name}' via docker save: {proc.stderr.strip()}"
                    )
                tar_file = tmp_tar_path

            return self._scan_tarball(tar_file, image_name, Path(tmp_dir))

        finally:
            # Clean up temporary directory and extracted layers
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception as e:
                logger.debug(f"Failed to clean up temp container dir {tmp_dir}: {e}")

    def _scan_tarball(self, tar_path: Path, image_name: str, work_dir: Path) -> List[Artefact]:
        extract_dir = work_dir / "extracted_tar"
        merged_fs = work_dir / "merged_fs"
        extract_dir.mkdir(parents=True, exist_ok=True)
        merged_fs.mkdir(parents=True, exist_ok=True)

        # 1. Extract outer image tarball
        with tarfile.open(tar_path, "r:*") as tar:
            tar.extractall(path=extract_dir)

        # 2. Parse manifest.json
        manifest_file = extract_dir / "manifest.json"
        layer_paths: List[str] = []
        repo_tags: List[str] = []

        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
                    if isinstance(manifest, list) and len(manifest) > 0:
                        first_entry = manifest[0]
                        layer_paths = first_entry.get("Layers", [])
                        repo_tags = first_entry.get("RepoTags", [])
            except Exception as e:
                logger.warning(f"Error reading manifest.json: {e}")

        # Fallback: find all layer.tar files if manifest was missing
        if not layer_paths:
            layer_paths = [str(p.relative_to(extract_dir)) for p in extract_dir.glob("*/layer.tar")]

        # Map of relative file paths in merged_fs -> layer_id
        file_to_layer_map: Dict[str, str] = {}

        # 3. Unpack each layer sequentially into merged filesystem
        for layer_rel in layer_paths:
            layer_tar_file = extract_dir / layer_rel
            if not layer_tar_file.exists():
                continue

            # Layer identifier (e.g. hash or folder name)
            layer_id = Path(layer_rel).parent.name or layer_rel

            try:
                with tarfile.open(layer_tar_file, "r:*") as layer_tar:
                    for member in layer_tar.getmembers():
                        # Handle whiteouts (.wh.<filename>)
                        member_path = Path(member.name)
                        if member_path.name.startswith(".wh."):
                            real_name = member_path.name[4:]
                            deleted_target = merged_fs / member_path.parent / real_name
                            if deleted_target.exists():
                                if deleted_target.is_dir():
                                    shutil.rmtree(deleted_target, ignore_errors=True)
                                else:
                                    deleted_target.unlink(missing_ok=True)
                            continue

                        # Extract member safely
                        layer_tar.extract(member, path=merged_fs)
                        norm_rel = str(Path(member.name)).replace("\\", "/")
                        file_to_layer_map[norm_rel] = layer_id
            except Exception as e:
                logger.warning(f"Failed extracting container layer {layer_rel}: {e}")

        # 4. Run sub-scanners across the merged filesystem
        all_artefacts: List[Artefact] = []
        image_label = repo_tags[0] if repo_tags else image_name

        for scanner in self.sub_scanners:
            try:
                found = scanner.scan(merged_fs)
                for art in found:
                    # Relativize file location to container root
                    try:
                        rel_path = Path(art.location.file).relative_to(merged_fs)
                        clean_rel_str = "/" + str(rel_path).replace("\\", "/")
                    except ValueError:
                        clean_rel_str = art.location.file

                    norm_lookup = str(Path(art.location.file).relative_to(merged_fs)).replace("\\", "/")
                    origin_layer = file_to_layer_map.get(norm_lookup, "base_or_unknown")

                    art.location = Location(
                        file=clean_rel_str,
                        line=art.location.line,
                        column=art.location.column,
                    )
                    art.metadata["container_image"] = image_label
                    art.metadata["container_layer"] = origin_layer
                    all_artefacts.append(art)
            except Exception as e:
                logger.warning(f"Sub-scanner {scanner.name} error on container fs: {e}")

        return all_artefacts
