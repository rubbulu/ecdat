# ECDAT System Architecture & Technical Design

> **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**  
> **Threws Odyssey 2026 Hackathon — Cybersecurity Track**

---

## 🏛️ Executive Architectural Overview

ECDAT is engineered as a high-throughput, multi-modal cryptographic discovery and quantum risk evaluation platform. It systematically ingests source code repositories, compiled binaries, container layers, X.509 certificates, package manifests, and server configurations to generate **CycloneDX v1.6 Cryptographic Bill of Materials (CBOM)** and compute enterprise quantum exposure using **Mosca's Inequality**.

```mermaid
flowchart TD
    subgraph INGESTION["Multi-Vector Discovery Targets"]
        T_SRC["Source Code\n(Python, JS/TS, Java, Go, C/C++)"]
        T_BIN["Compiled Binaries\n(PE, ELF, DLL, SO)"]
        T_CTR["Container Images\n(Docker Tarball Layers)"]
        T_CRT["X.509 Certificates\n(.pem, .crt, .cer, .der, .p12)"]
        T_DEP["Package Manifests\n(pip, npm, maven, go.mod)"]
        T_CFG["Server Configs\n(nginx, apache, sshd, .env)"]
    end

    subgraph ENGINE["ECDAT Core Engine (Python 3.11 + FastAPI)"]
        direction TB
        REGISTRY["Plugin Scanner Registry\n(ScannerRegistry)"]
        CATALOGUE["Central PQC & Classical Catalogue\n(crypto_catalogue.json)"]
        CLASSIFIER["Asset Classifier\n(Lifetime & Business Criticality)"]
        MOSCA["Mosca's Inequality Engine\n(X + Y > Z Simulation)"]
        PQC_REC["NIST PQC Migration Advisory\n(FIPS 203 / 204 / 205 Mapping)"]
        CBOM_BUILDER["CycloneDX 1.6 CBOM Builder\n(cyclonedx-bom serializer)"]
        STORAGE[("SQLite Persistence\n(WAL Mode, Cascade Foreign Keys)")]

        REGISTRY --> CATALOGUE
        CATALOGUE --> CLASSIFIER
        CLASSIFIER --> MOSCA
        MOSCA --> PQC_REC
        PQC_REC --> CBOM_BUILDER
        CBOM_BUILDER --> STORAGE
    end

    subgraph PRESENTATION["Presentation & Integration Layer"]
        API["FastAPI REST Endpoints\n(Upload, Scans, Artefacts, Overrides, Exports)"]
        GUI["React 18 + Vite + Tailwind Console\n(Dashboard, Recharts, Risk Map, Compare)"]
        EXPORTS["Audit Deliverables\n(CycloneDX 1.6 CBOM, PDF, HTML, CSV)"]

        STORAGE <--> API
        API <--> GUI
        API --> EXPORTS
    end

    INGESTION --> REGISTRY
```

---

## 🔄 Scan Execution Lifecycle

The scan execution lifecycle is fully asynchronous, decoupling target upload and validation from CPU-intensive cryptographic static inspection.

```mermaid
sequenceDiagram
    autonumber
    actor User as Enterprise Security Auditor
    participant UI as React GUI / Client
    participant API as FastAPI Backend (main.py)
    participant Worker as Background Scanning Worker
    participant Registry as ScannerRegistry (base.py)
    participant Cat as CatalogueService
    participant Mosca as MoscaEngine & RiskEngine
    participant DB as SQLite Storage (db.py)

    User->>UI: Submit Target (Zip, Git URL, or Local Path)
    UI->>API: POST /api/scans
    API->>API: Enforce Zip-Slip & File Size (<=50MB) Validation
    API->>DB: create_scan(status="pending")
    API-->>UI: 202 Accepted (scan_id, status="pending")
    
    API->>Worker: Enqueue _run_scan_job(scan_id, target_path)
    Worker->>DB: update_scan_status("running")
    Worker->>Registry: scan_all(target_path)
    
    loop For each registered scanner
        Registry->>Registry: Execute Scanner (Source, Cert, Dep, Config, Binary)
        Registry->>Cat: enrich_artefact(artefact)
    end
    
    Registry-->>Worker: List[Artefact]
    Worker->>DB: save_artefacts(scan_id, artefacts)
    Worker->>Mosca: assess_scan_risk(artefacts, y=3.0, z=12.0)
    Mosca-->>Worker: RiskSummary (scores, exposures, top risks)
    Worker->>DB: update_scan_status("completed", total_artefacts, summary)
    Worker->>Worker: Cleanup temporary sandbox folders (finally block)

    UI->>API: GET /api/scans/{id}/summary (polling)
    API->>DB: get_scan(scan_id) & get_artefacts(scan_id)
    API-->>UI: RiskSummary JSON
    UI-->>User: Render Dashboard, Charts, and CBOM Inventory
```

---

## 🔍 Discovery Vector Implementation Details

### 1. Multi-Language Source Code AST & Regex Scanner
- **Python**: Uses Python's native `ast` parser to traverse `Call` nodes (`hashlib.md5()`, `rsa.generate_private_key()`, `ec.generate_private_key()`, `Cipher.new()`), extracting key lengths, curves (e.g., `SECP256R1`), and modes.
- **JavaScript / TypeScript, Java, Go, C/C++**: Declarative regex rules loaded from [`backend/data/rules.yaml`](../backend/data/rules.yaml), inspecting multi-line context windows to extract modulus lengths, padding modes, and cipher suites.
- **Hardcoded Secrets**: Detects PEM private key headers (`-----BEGIN RSA PRIVATE KEY-----`) and high-entropy API key assignments.

### 2. X.509 Certificate Scanner
- Recursively inspects `.pem`, `.crt`, `.cer`, `.der`, and `.p12` certificates.
- Uses `cryptography.x509` to parse Subject, Issuer, Public Key Algorithm, Key Size (bits), Signature Algorithm (e.g., `sha256WithRSAEncryption`), Validity Horizon, Days to Expiry, and Self-Signed indicators.

### 3. Software Dependency Manifest Scanner
- Parses `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, and `Gemfile`.
- Detects crypto providers (`cryptography`, `pycryptodome`, `node-forge`, `crypto-js`, `bouncycastle`, `golang.org/x/crypto`).
- Flags deprecated or insecure libraries (e.g. `pycrypto`, legacy unmaintained `crypto-js`).

### 4. Infrastructure & Server Configuration Scanner
- Inspects `nginx.conf`, Apache `httpd.conf`, OpenSSH `sshd_config`, `openssl.cnf`, and `.env` files.
- Analyzes TLS protocol minimums (`TLSv1.0`, `TLSv1.1`), SSH key exchange (`diffie-hellman-group1-sha1`), host key algorithms (`ssh-rsa`), and weak cipher suite directives (`RC4`, `3DES`).

### 5. Compiled Binary Scanner
- Targets ELF (Linux), PE (Windows), and Mach-O (macOS) executables and shared libraries (`.so`, `.dll`, `.dylib`).
- Uses `lief` to inspect symbol tables and dynamically linked libraries (`libssl.so`, `libcrypto.so`).
- Pure Python fallback for static string extraction and cryptographic constant byte-signatures (e.g., SHA-256 initialization constants, AES S-box permutations).

### 6. Container Image Layer Scanner
- Ingests Docker image tarballs (`docker save` output) or image names.
- Unpacks layered OCI tar files, handles whiteout markers (`.wh.*`), and aggregates findings while tracking the originating layer hash for every discovered cryptographic asset.

---

## 🧮 Mathematical Risk Modeling: Mosca's Inequality

ECDAT calculates quantum urgency using Michele Mosca's theorem:
$$\text{At Risk If: } X + Y > Z$$

Where:
- **$X$ (Confidentiality Shelf-Life)**: How long encrypted data must remain protected (years).
  - Short ($<2$y): Session tokens, ephemeral keys ($X = 1$).
  - Medium ($2\text{--}10$y): Operational certificates, commercial contracts ($X = 5$).
  - Long ($>10$y): Medical records, government secrets, root CA certs ($X = 15$).
- **$Y$ (Migration Timeline)**: Time needed to upgrade systems, re-encrypt databases, and deploy post-quantum standards (default $Y = 3.0$).
- **$Z$ (CRQC Arrival Horizon)**: Estimated years until a Cryptanalytically Relevant Quantum Computer collapses RSA and ECC via Shor's algorithm (default $Z = 12.0$).

### Composite Risk Scoring Formula (0-100)
$$\text{Risk Score} = w_{\text{quantum}} \cdot S_{\text{quantum}} + w_{\text{mosca}} \cdot S_{\text{mosca}} + w_{\text{crit}} \cdot S_{\text{crit}} + w_{\text{key}} \cdot S_{\text{key}}$$

- **Quantum Status Weight ($45\%$)**: Shor-vulnerable asymmetric crypto scores 100; classically broken ciphers score 90; Grover-weakened ciphers score 50; Quantum-safe ciphers score 0.
- **Mosca Exposure Weight ($25\%$)**: $100$ if $X + Y > Z$; scaled proportionally by margin if within safety window.
- **Business Criticality Weight ($20\%$)**: Critical ($100$), High ($75$), Medium ($50$), Low ($25$).
- **Key Length Penalty ($10\%$)**: Penalizes sub-standard key sizes (e.g. RSA-1024 or DES).

---

## 🛡️ Security Architecture

1. **Strict Zip-Slip Traversal Protection**: Every file entry within uploaded zip archives is resolved against the target destination folder. If any entry attempts directory traversal (`..`, leading `/`, or unresolved paths outside destination), the entire archive is rejected with HTTP 400.
2. **Safe Isolated Workspaces**: Container unpacking, git cloning, and archive decompression occur within randomized ephemeral directories created via `tempfile.mkdtemp()`. Guaranteed deletion is enforced in `finally` execution blocks.
3. **No Execution Guarantee**: ECDAT performs **static inspection exclusively**. Scanned binaries, scripts, or container payloads are never executed.
4. **Input Sanitization**: Remote Git URLs are strictly sanitized against shell metacharacters (`;&|$\`<>`), preventing command injection.

---

## 💾 Persistence & Storage Design

ECDAT utilizes SQLite with:
- **Write-Ahead Logging (WAL)**: Ensures high-concurrency read/write transactions without database locking.
- **Foreign Key Cascades**: Scans maintain an `ON DELETE CASCADE` relationship with discovered artefacts; removing a scan automatically purges all child artefacts.
- **JSON Metadata Columns**: Enables extensible, non-breaking storage of scanner-specific context, user risk overrides, and Mosca parameter simulations.
