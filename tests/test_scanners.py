from pathlib import Path
from typing import List, Union
import pytest
from backend.app.models.artefact import Artefact, ArtefactType
from backend.app.scanners.base import (
    BaseScanner,
    ScannerRegistry,
    register_scanner,
)


@pytest.fixture(autouse=True)
def clean_registry():
    # Save original registry state, clear, and restore after test
    orig_scanners = dict(ScannerRegistry._scanners)
    orig_instances = dict(ScannerRegistry._instances)
    ScannerRegistry.clear()
    yield
    ScannerRegistry._scanners = orig_scanners
    ScannerRegistry._instances = orig_instances


class DummyPythonScanner(BaseScanner):
    name = "dummy_python"
    description = "Test python crypto scanner"
    supported_extensions = [".py"]

    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        return [
            Artefact(
                type=ArtefactType.ALGORITHM,
                name="RSA",
                location=f"{target_path}:10",
                detection_method="dummy_scanner",
                evidence="import rsa",
            )
        ]


def test_register_and_get_scanner():
    ScannerRegistry.register(DummyPythonScanner)
    assert "dummy_python" in ScannerRegistry.list_scanners()

    scanner = ScannerRegistry.get("dummy_python")
    assert scanner is not None
    assert scanner.name == "dummy_python"


def test_register_scanner_decorator():
    @register_scanner("annotated_scanner")
    class AnnotatedScanner(BaseScanner):
        name = "annotated_scanner"
        description = "Annotated scanner"

        def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
            return []

    assert "annotated_scanner" in ScannerRegistry.list_scanners()
    inst = ScannerRegistry.get("annotated_scanner")
    assert inst is not None


def test_scanner_can_handle_extension():
    scanner = DummyPythonScanner()
    assert scanner.can_handle("test.py") is True
    assert scanner.can_handle("test.PY") is True
    assert scanner.can_handle("test.js") is False


def test_scanner_registry_scan_all():
    ScannerRegistry.register(DummyPythonScanner)
    artefacts = ScannerRegistry.scan_all("sample.py")
    assert len(artefacts) == 1
    assert artefacts[0].name == "RSA"
    assert artefacts[0].detection_method == "dummy_scanner"
