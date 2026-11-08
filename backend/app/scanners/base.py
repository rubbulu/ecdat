from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Dict, List, Optional, Type, Union

from backend.app.models.artefact import Artefact

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract Base Class for all ECDAT cryptographic discovery scanners.
    Plugin-style architecture allowing source, binary, container, and network scanners.
    """
    name: str = "base_scanner"
    description: str = "Base cryptographic scanner"
    supported_extensions: List[str] = []

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    @abstractmethod
    def scan(self, target_path: Union[str, Path]) -> List[Artefact]:
        """
        Execute scan against the given target file or directory.
        Returns a list of discovered Artefact objects.
        """
        pass

    def can_handle(self, path: Union[str, Path]) -> bool:
        """
        Check if this scanner can process the given file/directory.
        If supported_extensions is empty, it handles any path by default.
        """
        if not self.supported_extensions:
            return True
        p = Path(path)
        if p.is_dir():
            return True
        return p.suffix.lower() in [ext.lower() for ext in self.supported_extensions]


class ScannerRegistry:
    """
    Central registry for discovering, registering, and orchestrating scanners.
    """
    _scanners: Dict[str, Type[BaseScanner]] = {}
    _instances: Dict[str, BaseScanner] = {}

    @classmethod
    def register(cls, scanner_cls: Type[BaseScanner], name: Optional[str] = None) -> Type[BaseScanner]:
        scanner_name = name or getattr(scanner_cls, "name", scanner_cls.__name__)
        cls._scanners[scanner_name] = scanner_cls
        # Invalidate cached instance if replacing
        cls._instances.pop(scanner_name, None)
        logger.debug(f"Registered scanner: {scanner_name}")
        return scanner_cls

    @classmethod
    def get(cls, name: str, config: Optional[Dict] = None) -> Optional[BaseScanner]:
        if name in cls._instances and not config:
            return cls._instances[name]
        if name in cls._scanners:
            instance = cls._scanners[name](config=config)
            if not config:
                cls._instances[name] = instance
            return instance
        return None

    @classmethod
    def list_scanners(cls) -> List[str]:
        return sorted(list(cls._scanners.keys()))

    @classmethod
    def get_all(cls, config: Optional[Dict] = None) -> List[BaseScanner]:
        scanners = []
        for name in cls.list_scanners():
            scanner = cls.get(name, config=config)
            if scanner:
                scanners.append(scanner)
        return scanners

    @classmethod
    def scan_all(cls, target_path: Union[str, Path], config: Optional[Dict] = None) -> List[Artefact]:
        """
        Run all registered scanners sequentially on the target path and aggregate results.
        """
        target = Path(target_path)
        all_artefacts: List[Artefact] = []
        for scanner in cls.get_all(config=config):
            if scanner.can_handle(target):
                try:
                    found = scanner.scan(target)
                    all_artefacts.extend(found)
                except Exception as e:
                    logger.error(f"Scanner '{scanner.name}' failed on {target}: {e}", exc_info=True)
        return all_artefacts

    @classmethod
    def clear(cls) -> None:
        """Clear registry (used for test isolation)."""
        cls._scanners.clear()
        cls._instances.clear()


def register_scanner(name: Optional[str] = None) -> Callable[[Type[BaseScanner]], Type[BaseScanner]]:
    """
    Decorator to register a Scanner class into ScannerRegistry.
    Usage:
        @register_scanner("python_ast")
        class PythonAstScanner(BaseScanner):
            ...
    """
    def decorator(cls: Type[BaseScanner]) -> Type[BaseScanner]:
        ScannerRegistry.register(cls, name=name)
        return cls
    return decorator
