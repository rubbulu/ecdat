# Contributing to ECDAT

Thank you for your interest in contributing to **ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)**! We welcome contributions from cybersecurity researchers, cryptographers, software engineers, and post-quantum enthusiasts.

---

## 🏛️ Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Please be respectful, constructive, and collaborative in all communications.

---

## 🚀 Development Workflow

### 1. Prerequisites
- **Python 3.11+**
- **Node.js 18+ & npm**
- **Git**
- **Docker & Docker Compose** (optional, for containerized workflows)

### 2. Fork & Clone Repository
```bash
git clone https://github.com/rubbulu/ecdat.git
cd ecdat
```

### 3. Setup Python Backend Environment
```bash
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

pip install -r backend/requirements.txt
```

### 4. Setup Node.js Frontend Environment
```bash
cd frontend
npm install --legacy-peer-deps
cd ..
```

---

## 🧪 Testing Guidelines

Before submitting a Pull Request, verify that all test suites pass:

```bash
# Set PYTHONPATH to repository root
export PYTHONPATH=$(pwd) # Linux/macOS
$env:PYTHONPATH = (Get-Location).Path # Windows PowerShell

# Run full pytest test suite
pytest tests/ -v

# Run evaluation benchmark
python tests/evaluation/run_evaluation_suite.py

# Verify frontend build
cd frontend && npm run build && cd ..
```

All 74+ tests must pass with zero regressions.

---

## 🧩 Adding a New Cryptographic Scanner

ECDAT uses a plugin-style scanner architecture. To add a new scanner:
1. Subclass `BaseScanner` in `backend/app/scanners/`:
   ```python
   from backend.app.scanners.base import BaseScanner, register_scanner
   from backend.app.models.artefact import Artefact

   @register_scanner("my_scanner")
   class MyScanner(BaseScanner):
       name = "my_scanner"
       description = "Discovers custom cryptographic patterns"
       supported_extensions = [".ext"]

       def scan(self, target_path) -> list[Artefact]:
           ...
   ```
2. Register the scanner in `backend/app/scanners/__init__.py`.
3. Add unit tests in `tests/test_scanners.py`.

---

## 📚 Adding or Updating Cryptographic Primitives

The central cryptographic catalogue is located at [`backend/data/crypto_catalogue.json`](backend/data/crypto_catalogue.json). Each algorithm entry requires:
- `family`: Category (e.g., `Asymmetric / Key Exchange`, `Post-Quantum Cryptography / KEM`)
- `primitive`: Cryptographic primitive type
- `quantum_status`: `vulnerable_shor`, `weakened_grover`, `classically_broken`, or `quantum_safe`
- `nist_replacement`: NIST standardized replacement (e.g., `ML-KEM-768`, `ML-DSA-65`, `AES-256`)
- `notes`: Cryptanalytic justification and Shor/Grover asymptotic complexity notes
- `aliases`: Lowercase alternate names, identifiers, and RFC aliases

---

## 📬 Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-new-capability`.
2. Commit with conventional commit messages (e.g., `feat(scanner): add Rust ring crypto discovery`).
3. Push to your branch and open a Pull Request against `main`.
4. Ensure CI/CD tests pass cleanly.
