# Competitive Analysis & Comparison

> **How ECDAT Compares with Existing Cryptographic Discovery & SAST Tools**  
> **Threws Odyssey 2026 Hackathon — Cybersecurity Track**

---

## 📌 Executive Comparison Matrix

The table below contrasts **ECDAT** with prominent industry and research tools:
- **IBM CBOMkit** (IBM Research Cryptographic Bill of Materials generator)
- **SonarQube Crypto Rules** (General Static Application Security Testing)
- **CryptoGuard / CryptoScan** (Academic static analysis for cryptographic API misuse)
- **GitHub CodeQL Cryptographic Queries** (Semantic code search)

| Capability / Feature | **ECDAT** | **IBM CBOMkit** | **SonarQube Crypto** | **CryptoGuard** | **GitHub CodeQL** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Standard CycloneDX 1.6 CBOM Output** | **Yes (Full Spec)** | Yes | No | No | No |
| **Mosca's Inequality Risk Engine ($X+Y>Z$)** | **Yes (Live Sim)** | No | No | No | No |
| **NIST PQC Replacement Advisory** *(FIPS 203/204/205)* | **Yes (Automated)** | Partial | No | No | No |
| **Hybrid Transitional Schemes** *(e.g. X25519+ML-KEM)* | **Yes** | No | No | No | No |
| **Multi-Language Source AST & Heuristics** | **Yes (6+ Langs)** | Yes (Java/Py) | Yes | Java Only | Yes |
| **X.509 Certificate Parsing** *(Key sizes, expiry, SANs)*| **Yes** | Partial | No | No | No |
| **Server & Infrastructure Configs** *(Nginx, SSH, .env)* | **Yes** | No | Partial | No | No |
| **Compiled Binaries** *(ELF, PE, Mach-O via LIEF)* | **Yes** | No | No | No | No |
| **Container Image Layer Unpacking** *(Docker Tarballs)* | **Yes** | No | No | No | No |
| **Scan Comparison / Delta Benchmarking** | **Yes** | No | Partial | No | No |
| **Executive PDF, HTML & CSV Reporting** | **Yes** | No | Plugin Only | No | No |
| **Interactive Dark-Mode React GUI** | **Yes** | No (CLI only) | Yes (Generic) | No (CLI only) | Cloud Web UI |
| **Deployment Model** | **Docker / Local** | Python CLI | Server / Cloud | Java CLI | Cloud / CLI |

---

## 🔍 Detailed Comparative Breakdown

### 1. ECDAT vs. IBM CBOMkit
**IBM CBOMkit** is an open-source initiative from IBM Research designed to extract cryptographic assets and format them into CycloneDX CBOM files.
- **Where CBOMkit Excels**: Good coverage of Java and Python AST parsing.
- **Where ECDAT Wins**:
  1. **Quantum Urgency Modeling**: CBOMkit lists algorithms but does not model **Michele Mosca's Inequality** ($X + Y > Z$). ECDAT allows enterprise risk officers to configure data confidentiality shelf-life ($X$) and migration time ($Y$) to calculate exact risk margins.
  2. **Multi-Vector Infrastructure Coverage**: CBOMkit focuses strictly on application source code. ECDAT scans source code, package manifests, X.509 certificates, OpenSSH configs, Nginx/Apache cipher directives, and compiled binary libraries.
  3. **Container Layer Provenance**: ECDAT unpacks Docker image layers, tracking the exact layer hash from which each vulnerable cryptographic primitive originated.
  4. **Analyst Console & Migration Verification**: ECDAT features an interactive React + Tailwind console and a side-by-side **Scan Comparison** tool to verify posture improvement pre- and post-migration.

---

### 2. ECDAT vs. SonarQube Cryptographic Rules
**SonarQube** is the de facto standard for general code quality and security scanning.
- **Where SonarQube Excels**: Broad rule coverage across code smells, OWASP Top 10 vulnerabilities, and standard CI/CD integrations.
- **Where ECDAT Wins**:
  1. **No Standard CBOM**: SonarQube produces issue tickets (e.g. "Do not use MD5"), but cannot generate machine-readable **CycloneDX 1.6 CBOMs** required for federal compliance (e.g., CISA / White House OMB M-23-02 PQC directives).
  2. **Post-Quantum Blindness**: SonarQube lacks knowledge of post-quantum cryptography. It treats RSA-2048 as "safe" (because it is classically secure today), failing to alert enterprises to **Harvest Now, Decrypt Later (HNDL)** quantum risks.
  3. **No PQC Migration Advisory**: SonarQube does not recommend NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), or FIPS 205 (SLH-DSA) replacements, nor does it quantify public key size impact or performance trade-offs.

---

### 3. ECDAT vs. Academic Tools (CryptoGuard, CogniCrypt)
Academic tools like **CryptoGuard** and **CogniCrypt** focus on cryptographic API misuses (e.g. static IVs, ECB mode, low iteration counts in PBKDF2) in Java and Android apps.
- **Where Academic Tools Excel**: Deep inter-procedural dataflow analysis for specific Java parameter misuses.
- **Where ECDAT Wins**:
  1. **Enterprise Usability & Multi-Language Breadth**: Academic tools are notoriously brittle, requiring complex compilation steps and focusing almost exclusively on Java bytecode. ECDAT operates across Python, JavaScript, TypeScript, Go, Java, C/C++, Docker, and binary libraries with zero compilation prerequisites.
  2. **PQC Lifecycle Strategy**: Academic tools focus on classical bugs (e.g., non-random IVs). ECDAT addresses the strategic architectural transition from classical public-key cryptography to quantum-resistant standards.

---

### 4. ECDAT vs. GitHub CodeQL
**CodeQL** treats code as data, enabling semantic queries over Abstract Syntax Trees.
- **Where CodeQL Excels**: Deep taint tracking and variant analysis for complex logic bugs.
- **Where ECDAT Wins**:
  1. **Compilation Independence**: CodeQL requires compiled databases for compiled languages like C/C++, Go, and Java. ECDAT static scanners operate directly on raw source trees, configurations, binaries, and container tarballs without requiring a working build environment.
  2. **Dedicated Post-Quantum Taxonomy**: ECDAT ships with an integrated catalogue of 31+ cryptographic primitives, Shor/Grover asymptotic classifications, and automated NIST PQC migration mappings.

---

## 🎯 Summary of ECDAT's Unique Value Proposition

1. **Holistic Multi-Vector Discovery**: Code, binaries, certificates, dependencies, configs, and container layers analyzed simultaneously.
2. **Actionable Post-Quantum Roadmaps**: Automated recommendations with NIST standard designations (FIPS 203/204/205), library suggestions (`liboqs`, `OpenSSL 3.5`), key size overheads, and transitional hybrid guidance.
3. **Formal Mathematical Risk Quantification**: Live interactive Mosca's theorem simulation ($X + Y > Z$) with per-asset overrides for data shelf-life and business criticality.
4. **Audit-Ready Compliance Artifacts**: One-click generation of **CycloneDX 1.6 CBOM**, executive PDF reports, interactive HTML scorecards, and audit CSVs.
