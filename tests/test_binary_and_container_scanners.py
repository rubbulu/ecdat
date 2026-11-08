import io
import json
import tarfile
from pathlib import Path
import pytest

from backend.app.models.artefact import ArtefactType, QuantumStatus
from backend.app.scanners.binary_scanner import BinaryScanner
from backend.app.scanners.container_scanner import ContainerScanner


def test_binary_scanner_constants_and_strings(tmp_path):
    scanner = BinaryScanner()
    dummy_bin = tmp_path / "libcrypto_test.so"

    # Construct mock binary payload with ELF header, SHA-256 constants, AES S-box, and symbols
    elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00"
    sha256_h_const = b"\x67\xe6\x09\x6a\x85\xae\x67\xbb\x72\xf3\x6e\x3c\x3a\xf5\x4f\xa5"
    aes_sbox = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
    strings_section = (
        b"\x00libcrypto.so.1.1\x00"
        b"\x00OpenSSL 1.1.1t  7 Feb 2023\x00"
        b"\x00RSA_generate_key_ex\x00"
        b"\x00EVP_aes_128_cbc\x00"
        b"\x00MD5_Init\x00"
    )

    dummy_bin.write_bytes(elf_header + b"\x90" * 32 + sha256_h_const + b"\x90" * 16 + aes_sbox + strings_section)

    artefacts = scanner.scan(dummy_bin)
    assert len(artefacts) >= 5

    names = {a.name for a in artefacts}
    assert "SHA-256" in names
    assert any("AES" in name for name in names)
    assert "RSA" in names
    assert "OpenSSL" in names
    assert any("libcrypto" in name.lower() for name in names) or "MD5" in names

    # Check constant signature detection method
    sha_hit = next(a for a in artefacts if a.name == "SHA-256")
    assert sha_hit.detection_method == "binary_constant_signature"
    assert sha_hit.quantum_status == QuantumStatus.QUANTUM_SAFE

    # Check OpenSSL version banner
    openssl_hit = next(a for a in artefacts if a.name == "OpenSSL")
    assert "1.1.1" in openssl_hit.version


def test_container_scanner_with_mock_docker_tarball(tmp_path):
    scanner = ContainerScanner()
    image_tar_path = tmp_path / "mock_app_image.tar"

    # Layer 1 tarball: contains /etc/nginx/nginx.conf
    layer1_tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=layer1_tar_bytes, mode="w") as l1_tar:
        nginx_conf = b"server {\n    ssl_protocols TLSv1 TLSv1.1;\n    ssl_ciphers RC4:3DES;\n}\n"
        ti = tarfile.TarInfo(name="etc/nginx/nginx.conf")
        ti.size = len(nginx_conf)
        l1_tar.addfile(ti, io.BytesIO(nginx_conf))
    layer1_tar_data = layer1_tar_bytes.getvalue()

    # Layer 2 tarball: contains /app/requirements.txt
    layer2_tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=layer2_tar_bytes, mode="w") as l2_tar:
        req_txt = b"pycrypto==2.6.1\ncryptography==41.0.3\n"
        ti = tarfile.TarInfo(name="app/requirements.txt")
        ti.size = len(req_txt)
        l2_tar.addfile(ti, io.BytesIO(req_txt))
    layer2_tar_data = layer2_tar_bytes.getvalue()

    # Build the outer docker save tarball with manifest.json
    manifest_data = json.dumps([
        {
            "Config": "dummy_config.json",
            "RepoTags": ["enterprise/vulnerable-app:2026"],
            "Layers": [
                "layer_01_nginx/layer.tar",
                "layer_02_python/layer.tar",
            ],
        }
    ]).encode("utf-8")

    with tarfile.open(image_tar_path, mode="w") as outer_tar:
        # Add manifest.json
        ti = tarfile.TarInfo(name="manifest.json")
        ti.size = len(manifest_data)
        outer_tar.addfile(ti, io.BytesIO(manifest_data))

        # Add Layer 1
        ti1 = tarfile.TarInfo(name="layer_01_nginx/layer.tar")
        ti1.size = len(layer1_tar_data)
        outer_tar.addfile(ti1, io.BytesIO(layer1_tar_data))

        # Add Layer 2
        ti2 = tarfile.TarInfo(name="layer_02_python/layer.tar")
        ti2.size = len(layer2_tar_data)
        outer_tar.addfile(ti2, io.BytesIO(layer2_tar_data))

    # Scan mock image tarball
    artefacts = scanner.scan(image_tar_path)
    assert len(artefacts) >= 4

    names = {a.name for a in artefacts}
    assert "TLS 1.0" in names
    assert "pycrypto" in names
    assert "cryptography" in names

    # Verify layer tracking
    pycrypto_hit = next(a for a in artefacts if a.name == "pycrypto")
    assert pycrypto_hit.metadata.get("container_layer") == "layer_02_python"
    assert pycrypto_hit.metadata.get("container_image") == "enterprise/vulnerable-app:2026"
    assert "/app/requirements.txt" in pycrypto_hit.location.file

    tls_hit = next(a for a in artefacts if a.name == "TLS 1.0")
    assert tls_hit.metadata.get("container_layer") == "layer_01_nginx"
    assert "/etc/nginx/nginx.conf" in tls_hit.location.file


def test_container_scanner_docker_missing_error():
    scanner = ContainerScanner()
    # If scanning an image name when docker CLI is absent or image non-existent
    # Expect clear descriptive RuntimeError
    with pytest.raises(RuntimeError) as exc_info:
        scanner.scan("nonexistent-image-registry.internal/fake-image:1.0")

    err_msg = str(exc_info.value)
    assert "docker" in err_msg.lower()
