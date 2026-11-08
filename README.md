# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/Frontend-React%2018-61DAFB.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/UI-Tailwind%20CSS-38B2AC.svg)](https://tailwindcss.com/)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-orange.svg)](https://cyclonedx.org/)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-purple.svg)](https://csrc.nist.gov/pqc)
[![Tests: 74 Passed](https://img.shields.io/badge/Tests-74%20Passed-brightgreen.svg)](tests/)

> **Threws Odyssey 2026 Hackathon — Cybersecurity Track**  
> An automated enterprise platform to discover cryptographic assets, generate standardized **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)**, quantify quantum vulnerability using **Mosca's Inequality ($X + Y > Z$)**, and formulate actionable **NIST Post-Quantum Cryptography (PQC)** migration roadmaps.

---

## 📌 The Problem: The Post-Quantum Cryptographic Crisis

Organizations worldwide face an existential cryptographic inflection point: the imminent arrival of **Cryptanalytically Relevant Quantum Computers (CRQCs)**.

1. **Shor's Algorithm** runs in polynomial time on quantum hardware, rendering all classical asymmetric public-key cryptography (**RSA, DSA, Diffie-Hellman, ECDH, ECDSA, Ed25519**) mathematically obsolete.
2. **Grover's Algorithm** provides a quadratic speedup against symmetric ciphers and hashing functions, halving the effective security margin of **AES-128** (reducing it to 64 bits of security) and **SHA-256** (reducing collision resistance to 128 bits).
3. **"Harvest Now, Decrypt Later" (HNDL)**: Adversaries and state actors are actively intercepting, harvesting, and storing encrypted enterprise intellectual property, financial communications, and classified records today. Once a CRQC is operational, this harvested data will be decrypted retrospectively.

### Why It Matters Now
Federal mandates and global standards bodies have declared immediate preparation mandatory:
- **White House OMB Memorandum M-23-02 & National Security Memorandum 10 (NSM-10)**: Mandates that all federal agencies maintain a continuous, comprehensive inventory of all cryptographic systems vulnerable to CRQCs.
- **NIST Post-Quantum Cryptography Standards (August 2024)**: Released official standardized post-quantum algorithms:
  - **FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, derived from CRYSTALS-Kyber)
  - **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm, derived from CRYSTALS-Dilithium)
  - **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm, derived from SPHINCS+)
- **NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)**: Timelines require software and firmware upgrades to PQC algorithms to begin immediately, concluding between 2030 and 2033.

### The Enterprise Bottlenecks
Enterprises cannot migrate what they cannot see. Organizations struggle with:
- **Cryptographic Blindness**: Cryptographic calls are buried across heterogeneous source repositories (Python, JS, Java, Go, C/C++), container images, compiled binary libraries, TLS certificates, and infrastructure configuration files.
- **Standardized Inventory Deficit**: Inability to generate machine-readable **Cryptographic Bills of Materials (CBOM)** formatted to open industry standards.
- **Risk Prioritization Paralysis**: Inability to mathematically determine which assets are in imminent danger versus which can wait.

**ECDAT** solves these challenges with end-to-end multi-vector discovery, native CycloneDX 1.6 CBOM generation, live Mosca inequality simulation, and automated PQC migration recommendations.

---

## 🚀 Key Capabilities & Features

### 1. Multi-Vector Cryptographic Discovery
- **Source Code Static Analysis**:
  - Python AST parsing for `hashlib`, `cryptography` key generation (extracting modulus sizes and elliptic curves like `SECP256R1`), `Crypto.Cipher`, `ssl.PROTOCOL_*`, and JWT configurations.
  - Regex & heuristic context scanning for JavaScript/TypeScript, Java, Go, C/C++, and Ruby.
  - Hardcoded secret detection: Private key PEM headers (`-----BEGIN RSA PRIVATE KEY-----`) and high-entropy secret tokens.
- **X.509 Certificate Scanner**:
  - Parses `.pem`, `.crt`, `.cer`, `.der`, and `.p12` files using `cryptography.x509`.
  - Extracts Subject, Issuer, Public Key Algorithm, Key Size (bits), Signature Algorithm (e.g. `sha256WithRSAEncryption`), Validity Horizon, Days to Expiry, and Self-Signed indicators.
- **Software Dependency Scanner**:
  - Scans package manifests: `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, and `Gemfile`.
  - Detects cryptographic providers (`cryptography`, `pycryptodome`, `node-forge`, `crypto-js`, `bouncycastle`, `golang.org/x/crypto`).
  - Flags known deprecated/risky libraries (e.g. `pycrypto`, legacy unmaintained `crypto-js`).
- **Infrastructure & Configuration Scanner**:
  - Analyzes Nginx, Apache (`httpd.conf`), OpenSSH (`sshd_config`), OpenSSL (`openssl.cnf`), and `.env` files.
  - Detects deprecated TLS versions (`TLSv1.0`, `TLSv1.1`), weak cipher suites (`RC4`, `3DES`), and legacy SSH key exchange (`diffie-hellman-group1-sha1`).
- **Compiled Binary Scanner**:
  - Inspects ELF (Linux), PE (Windows), and Mach-O (macOS) executables and shared libraries (`.so`, `.dll`, `.dylib`).
  - Uses `lief` to inspect symbol tables and dynamically linked libraries (`libssl`, `libcrypto`).
  - Pure Python fallback for printable string extraction and cryptographic constant byte-signatures (e.g., SHA-256 initialization constants, AES S-box permutations).
- **Container Image Layer Scanner**:
  - Ingests Docker image tarballs (`docker save` output) or image names.
  - Unpacks layered OCI tar files, handles whiteout markers (`.wh.*`), and records originating layer hashes for every discovered cryptographic asset.

### 2. Native CycloneDX 1.6 CBOM Generation
- Native generator produces compliant **CycloneDX 1.6 JSON Cryptographic Bill of Materials (CBOM)**.
- Formats cryptographic assets as `cryptographic-asset` components with full `cryptoProperties`:
  - `assetType`: `algorithm`, `certificate`, `protocol`, or `related-crypto-material`
  - `algorithmProperties`: parameter sets, key length, execution mode (CBC, GCM, ECB), and NIST quantum status
  - `certificateProperties`: subject, issuer, signature algorithm, expiry
  - `protocolProperties`: protocol type, minimum version, cipher suite specification

### 3. Mathematical Quantum Risk Modeling: Mosca's Inequality
- Implements Michele Mosca's inequality:
  $$\text{At Risk If: } X + Y > Z$$
- **Configurable Parameters**:
  - $X$: Data confidentiality shelf-life (years)
  - $Y$: System migration timeline to deploy PQC (years, default 3.0)
  - $Z$: Years until CRQC collapses classical public-key cryptography (years, default 12.0)
- **Composite Risk Score (0-100)** combining quantum vulnerability classification, Mosca margin, business criticality, and key length.
- **Plain-English Explanations** per asset (e.g., *"RSA-2048 protects 15-year data; 15 + 3 > 12, so this is at risk from Shor's algorithm."*).

### 4. NIST PQC & Hybrid Migration Advisory Engine
- Maps vulnerable algorithms to NIST FIPS standardized quantum-resistant replacements:
  - RSA / DH / ECDH Key Exchange $\rightarrow$ **ML-KEM-768** (or hybrid **X25519MLKEM768** for TLS)
  - RSA / ECDSA / DSA Signatures $\rightarrow$ **ML-DSA-65** (or **SLH-DSA** for long-lived signing keys)
  - AES-128 $\rightarrow$ **AES-256**
  - SHA-1 / MD5 $\rightarrow$ **SHA-256** or **SHA-3**
  - 3DES / DES / RC4 $\rightarrow$ **AES-256-GCM**
  - TLS $< 1.3 \rightarrow$ **TLS 1.3** with hybrid PQC cipher groups
- Provides estimated migration effort, public key and signature size impact (e.g. ML-KEM-768 1,184-byte public key vs X25519 32 bytes), library suggestions (`liboqs`, `OpenSSL 3.5`, `BoringSSL`, `Bouncy Castle`), and transitional hybrid guidance.

### 5. Interactive Dark-Mode React GUI
- **Executive Dashboard**: Quantum readiness gauge, Recharts donut chart of risk levels, primitive frequency bar chart, and top risk preview.
- **Live Mosca Simulator**: Interactive sliders for $X, Y, Z$ with instant live risk recalculation.
- **Artefact Explorer**: Sortable, filterable table with search, pagination, and expandable row drill-down displaying exact code evidence and NIST recommendations.
- **Dependency & Location Risk Map**: Recharts Treemap heatmap visualizing file-level risk density.
- **Before vs. After Scan Comparison**: Side-by-side migration benchmarking to prove risk reduction over time.

### 6. Multi-Format Compliance Exports
- **CycloneDX 1.6 CBOM JSON** for machine-to-machine compliance tooling.
- **Executive PDF Report** with scorecards, charts, and audit summaries.
- **Printable HTML Scorecard** with embedded styles and charts.
- **Audit CSV Spreadsheet** for compliance spreadsheets and ticketing systems.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph INGESTION["Target Discovery Inputs"]
        T1["Source Repositories (Py, JS, Java, Go, C/C++)"]
        T2["Compiled Binaries & Shared Libraries (ELF, PE, DLL, SO)"]
        T3["Container Images (Docker Tarball Layers)"]
        T4["Certificates & Configs (X.509, Nginx, SSH, .env)"]
    end

    subgraph BACKEND["ECDAT Core Engine (Python 3.11 + FastAPI)"]
        direction TB
        REGISTRY["Scanner Registry\n(Plugin Architecture)"]
        CATALOGUE["Central Cryptographic Catalogue\n(31+ Classical & PQC Algorithms)"]
        CLASSIFIER["Asset Classifier\n(Lifetime & Business Criticality)"]
        MOSCA["Mosca's Inequality Engine\n(X + Y > Z Simulator)"]
        PQC_REC["NIST PQC Migration Advisory\n(FIPS 203/204/205 Mapping)"]
        CBOM_BUILDER["CycloneDX 1.6 CBOM Builder\n(cyclonedx-bom Engine)"]
        STORAGE[("SQLite Persistence\n(WAL Mode, Cascade Foreign Keys)")]
        API["FastAPI REST Endpoints\n(/api/scans, /api/artefacts, /api/export)"]

        REGISTRY --> CATALOGUE
        CATALOGUE --> CLASSIFIER
        CLASSIFIER --> MOSCA
        MOSCA --> PQC_REC
        PQC_REC --> CBOM_BUILDER
        CBOM_BUILDER --> STORAGE
        STORAGE <--> API
    end

    subgraph FRONTEND["Analyst Console (React 18 + Vite + Tailwind + Recharts)"]
        DASH["Executive Dashboard\n& Quantum Readiness Score"]
        CBOM_VIEW["Artefact Explorer\n& Code Evidence Viewer"]
        HEATMAP["Risk Treemap\n& Dependency Map"]
        COMPARE["Scan Comparison\n(Pre vs Post Migration)"]
        UPLOAD["Drag-and-Drop Ingestion\n(Zip, Git URL, Docker)"]

        API <--> DASH
        API <--> CBOM_VIEW
        API <--> HEATMAP
        API <--> COMPARE
        API <--> UPLOAD
    end

    INGESTION --> REGISTRY
```

---

## 🖼️ User Interface Walkthrough

```text
+----------------------------------------------------------------------------------------------------+
|  Ψ ECDAT  [PQC 1.0]     [Dashboard]  [Artefacts]  [Risk Map]  [Compare Scans]  [+ New Scan]     🔍 |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Quantum Readiness: 78% ]  [ Assets: 44 ]  [ At Risk (Mosca): 18 ]  [ Quantum Vulnerable: 68% ]  |
|                                                                                                    |
|  +---------------------------------------+   +--------------------------------------------------+  |
|  |       Risk Severity Distribution      |   |       Top Cryptographic Primitives Discovered    |  |
|  |           [ DONUT CHART ]             |   |                  [ BAR CHART ]                   |  |
|  |      Critical: 12  |  High: 8         |   |    RSA: 14   AES: 10   SHA-1: 6   MD5: 5        |  |
|  |      Medium: 14    |  Low: 10         |   |                                                  |  |
|  +---------------------------------------+   +--------------------------------------------------+  |
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  |  ⏱️ Mosca's Inequality Live Simulator: X (Shelf-Life) + Y (Migration) > Z (CRQC Horizon)       |  |
|  |  [X: 5.0 yrs ===o=====]   [Y: 3.0 yrs ==o======]   [Z: 12.0 yrs ========o===]  [Recalculate] |  |
|  |  STATUS: Within Safety Margin (X + Y = 8.0 yrs vs Z = 12.0 yrs | 4.0 yr safety window)       |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  Export Audit Packages: [📥 CBOM 1.6 JSON]  [📄 Executive PDF]  [📊 HTML Report]  [📑 CSV Export]  |
+----------------------------------------------------------------------------------------------------+
```

---

## ⚡ Quick Start

### Option 1: Docker Compose (Recommended — One Command)
Run the entire platform (backend API + frontend UI + Nginx reverse proxy):

```bash
docker compose up --build
```
- **Web Console**: [http://localhost:5173](http://localhost:5173) (or [http://localhost:3000](http://localhost:3000))
- **Interactive API Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option 2: Local Development Setup

#### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

#### 1. Start Backend Server
```powershell
# Windows PowerShell
.\start_backend.ps1

# Linux / macOS
export PYTHONPATH=$(pwd)
python3 -m uvicorn backend.main:app --reload --port 8000
```
API docs live at: [http://localhost:8000/docs](http://localhost:8000/docs)

#### 2. Start Frontend Server
```powershell
# Windows PowerShell
.\start_frontend.ps1

# Linux / macOS
cd frontend
npm install --legacy-peer-deps
npm run dev
```
Web console live at: [http://localhost:5173](http://localhost:5173)

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status and version |
| `POST` | `/api/scans` | Start a new scan (accepts zip upload, git repo URL, or local path) |
| `GET` | `/api/scans` | List all historical scans |
| `GET` | `/api/scans/{id}` | Get status and progress of a scan |
| `DELETE` | `/api/scans/{id}` | Delete a scan and cascade-delete its discovered artefacts |
| `GET` | `/api/scans/{id}/artefacts` | Query artefacts (filters: `type`, `risk_level`, `quantum_status`, `is_at_risk`, `scanner`; pagination) |
| `GET` | `/api/scans/{id}/summary` | Comprehensive risk posture scorecard, top 10 riskiest items, and Mosca parameters |
| `PUT` | `/api/artefacts/{id}/override` | Override lifetime, business criticality, or confidentiality shelf life ($X$) |
| `PUT` | `/api/scans/{id}/mosca` | Dynamically update scan Mosca parameters ($X, Y, Z$) and recalculate risk |
| `GET` | `/api/scans/{id}/export?format={cbom\|pdf\|html\|csv}` | Export results as CycloneDX 1.6 CBOM JSON, printable PDF, HTML scorecard, or CSV |
| `GET` | `/api/catalogue` | List all cryptographic algorithms and NIST PQC replacements from the catalogue |

### Example cURL Commands

#### 1. Initiate a Scan on a Local Directory
```bash
curl -X POST "http://localhost:8000/api/scans" \
     -H "Content-Type: application/json" \
     -d '{"local_path": "sample_targets/vulnerable_app"}'
```

#### 2. Upload a Zipped Repository
```bash
curl -X POST "http://localhost:8000/api/scans" \
     -F "file=@my_application.zip"
```

#### 3. Clone and Scan a Remote Git Repository
```bash
curl -X POST "http://localhost:8000/api/scans" \
     -H "Content-Type: application/json" \
     -d '{"git_url": "https://github.com/org/crypto-service.git"}'
```

#### 4. Query Discovered Artefacts with Filters
```bash
curl -X GET "http://localhost:8000/api/scans/<SCAN_ID>/artefacts?risk_level=critical&limit=10"
```

#### 5. Download CycloneDX 1.6 CBOM JSON
```bash
curl -X GET "http://localhost:8000/api/scans/<SCAN_ID>/export?format=cbom" -o cbom.json
```

#### 6. Download Executive PDF Audit Report
```bash
curl -X GET "http://localhost:8000/api/scans/<SCAN_ID>/export?format=pdf" -o report.pdf
```

#### 7. Update Mosca Parameters ($X, Y, Z$) Live
```bash
curl -X PUT "http://localhost:8000/api/scans/<SCAN_ID>/mosca" \
     -H "Content-Type: application/json" \
     -d '{"y": 4.0, "z": 10.0}'
```

---

## 🧮 Mosca's Inequality In Practice

Michele Mosca's theorem provides a mathematical formula for cryptographic migration urgency:
$$\text{At Risk If: } X + Y > Z$$

### Worked Real-World Examples

#### Scenario 1: Healthcare Patient Medical Records (Long-Lived Confidentiality)
- **Data**: Electronic Health Records (EHR) protected by RSA-2048 encryption.
- **Shelf-Life ($X$)**: 25 years (HIPAA requirements).
- **Migration Timeline ($Y$)**: 4 years to re-encrypt archived databases.
- **Quantum Arrival ($Z$)**: 12 years (consensus estimate ~2036).
- **Calculation**: $25 + 4 = 29 > 12$ $\rightarrow$ **VULNERABLE (Deficit of 17 years)**.
- **Verdict**: Critical urgency. Attackers harvesting encrypted records today can decrypt them well before the 25-year privacy mandate expires.

#### Scenario 2: Operational Web TLS Session (Short-Lived Confidentiality)
- **Data**: HTTPS banking session protected by ephemeral ECDHE.
- **Shelf-Life ($X$)**: 1 day ($X \approx 0.003$ years).
- **Migration Timeline ($Y$)**: 2 years to upgrade enterprise load balancers to hybrid PQC groups.
- **Quantum Arrival ($Z$)**: 12 years.
- **Calculation**: $0.003 + 2 = 2.003 < 12$ $\rightarrow$ **WITHIN SAFETY MARGIN (10-year safety window)**.
- **Verdict**: Low urgency for session secrecy, though long-term digital signatures must still transition.

---

## 📊 Evaluation & Benchmarks

Full empirical evaluation results are documented in [**`docs/EVALUATION.md`**](docs/EVALUATION.md).

### Ground Truth Accuracy ([`sample_targets/vulnerable_app`](sample_targets/vulnerable_app))
- **Recall (Sensitivity)**: **100.0%** (32 / 32 planted vulnerabilities discovered, zero false negatives).
- **Precision**: **84.21%**
- **F1 Score**: **91.43%**

### Performance & Memory Overhead
- **Scanning Speed**: **148 to 387 files/second** (~5,800 to 7,300 lines of code/second).
- **Peak Memory Usage**: **0.24 MB to 1.46 MB peak memory** via `tracemalloc`.
- **Open-Source Corpus**: Successfully scanned 10 public open-source repositories spanning C, Go, Python, and JavaScript.

---

## ⚠️ Limitations

1. **Static Analysis Exclusivity**: ECDAT performs static discovery and does not monitor live, runtime network traffic in real time. (See Future Work for eBPF integration).
2. **Dynamic Key Derivation**: Cryptographic keys derived entirely in memory at runtime without static code or configuration references require runtime instrumentation.
3. **Physical Hardware HSM Probing**: Hardware Security Modules (HSMs) requiring physical smartcard PINs or PKCS#11 hardware authentication are outside the scope of static discovery.

---

## 🔮 Future Roadmap

- [ ] **Runtime eBPF Cryptographic Probe**: Real-time Linux kernel eBPF probe to detect dynamic OpenSSL, BoringSSL, and GnuTLS socket handshakes.
- [ ] **Automated Git Remediation Bot**: Automatic generation of GitHub Pull Requests replacing deprecated algorithms with NIST PQC wrappers (e.g. migrating `hashlib.sha1()` to `hashlib.sha256()`).
- [ ] **Hardware Security Module (HSM) PKCS#11 Connector**: Auditing keys and algorithms active inside AWS CloudHSM, Azure Dedicated HSM, and YubiKeys.
- [ ] **Continuous CI/CD Quality Gate**: Pre-receive Git hook and GitHub Action to block commits introducing Shor-vulnerable public keys.

---

## 📦 Third-Party Libraries & Licences

ECDAT is built upon open-source technologies:

| Library | License | Role in ECDAT |
|---|---|---|
| **FastAPI** | MIT | High-performance asynchronous REST API framework |
| **Pydantic v2** | MIT | Cryptographic asset data modeling and strict input validation |
| **Cryptography** | Apache-2.0 / BSD | X.509 certificate parsing and cryptographic primitives |
| **LIEF** | Apache-2.0 | Executable binary (ELF, PE, Mach-O) symbol and header analysis |
| **ReportLab** | BSD | Enterprise PDF audit report generation engine |
| **Jinja2** | BSD | Printable HTML executive report templating engine |
| **React** | MIT | Frontend interactive user interface framework |
| **Vite** | MIT | High-speed frontend build tooling and HMR dev server |
| **Tailwind CSS** | MIT | Responsive utility-first dark-mode styling system |
| **Recharts** | MIT | Composable data visualization charts (Pie, Bar, Treemap) |
| **Lucide React** | ISC | Modern UI icon library |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
