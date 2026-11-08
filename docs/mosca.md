# Understanding Mosca's Theorem & Quantum Risk Scoring in ECDAT

> **ECDAT Quantum Risk Analysis Framework**  
> Formally quantifying the Post-Quantum Cryptography (PQC) migration timeline for enterprise assets.

---

## 📐 The Fundamental Formula: Mosca's Inequality

Dr. Michele Mosca (co-founder of the Institute for Quantum Computing) introduced a simple yet profound mathematical condition defining whether an organization's encrypted data is already vulnerable:

$$\text{Quantum Exposure Condition: } X + Y > Z$$

Where:
* **$X$ (Shelf-Life)**: The number of years encrypted data must remain strictly confidential (e.g. healthcare records = 20y, financial transactions = 10y, trade secrets = 25y).
* **$Y$ (Migration Time)**: The number of years required for the enterprise to fully re-architect systems, rotate keys, update protocols, and deploy quantum-resistant algorithms across production.
* **$Z$ (Collapse Horizon)**: The estimated number of years until a **Cryptanalytically Relevant Quantum Computer (CRQC)** capable of running Shor's algorithm at scale is operational (industry consensus: **10 to 15 years**, default = **12 years**).

---

## 🚨 The Threat: "Harvest Now, Decrypt Later" (HNDL)

If $X + Y > Z$, an adversary does **not** need to wait for a quantum computer to compromise your organization today:

```text
TODAY                                          CRQC ARRIVES (Year Z)
  |                                                      |
  v                                                      v
  [=== Harvest Encrypted Traffic & Backups ===] --------> [ Decrypt Everything ]
       |                                                      |
       |<------------ Data Still Legally Confidential ------->|
       |<------------------- Shelf Life (X) ----------------->|
```

Adversaries passively intercept and store encrypted enterprise traffic, TLS sessions, and database backups today. Once a quantum computer with sufficient logical qubits is brought online at year $Z$, every archived ciphertext encrypted with RSA, ECC, or Diffie-Hellman can be decrypted in polynomial time using Shor's algorithm.

---

## 📊 Concrete Numerical Worked Examples

### Example 1: Long-Term Healthcare Archive (RSA-2048) &rarr; **CRITICAL ALERT**

* **Asset**: Patient Electronic Health Records (EHR) encrypted with **RSA-2048**.
* **$X$ (Shelf-Life)**: **15 years** (HIPAA and state health record confidentiality laws).
* **$Y$ (Migration Time)**: **3 years** (Vendor upgrades, database re-encryption, API transitions).
* **$Z$ (Quantum Horizon)**: **12 years** (Consensus estimate for scalable fault-tolerant quantum computer).

$$\text{Calculation: } X + Y = 15 + 3 = 18 \text{ years}$$
$$18 > 12 \implies \mathbf{AT\ RISK\ (Deficit: } +6 \text{ years)}$$

**ECDAT Plain-English Explanation**:
> *"RSA-2048 protects 15-year data; 15 + 3 > 12, so this is at risk from Shor's algorithm. Adversaries archiving data today will decrypt confidential records 6 years before legal confidentiality expires."*
* **Calculated Risk Score**: **89.5 / 100 (CRITICAL)**

---

### Example 2: Ephemeral Web Session Token (ECDH P-256) &rarr; **SAFE MARGIN**

* **Asset**: Temporary e-commerce checkout session key generated using **ECDH (P-256)**.
* **$X$ (Shelf-Life)**: **0.1 years** (Session expires in 30 minutes; non-sensitive data).
* **$Y$ (Migration Time)**: **1 year** (Fast-moving web frontend microservice).
* **$Z$ (Quantum Horizon)**: **12 years**.

$$\text{Calculation: } X + Y = 0.1 + 1.0 = 1.1 \text{ years}$$
$$1.1 \le 12 \implies \mathbf{SAFE\ MARGIN\ (Buffer: } -10.9 \text{ years)}$$

**ECDAT Plain-English Explanation**:
> *"ECDH is vulnerable to Shor's algorithm, but migration horizon (0.1 + 1 = 1.1y) fits comfortably within estimated CRQC timeline (12y)."*
* **Calculated Risk Score**: **32.0 / 100 (LOW)**

---

### Example 3: Legacy Infrastructure Config (3DES / DES) &rarr; **IMMEDIATE REMEDIATION**

* **Asset**: Legacy internal API gateway using **3DES-CBC**.
* **Quantum Status**: **`classically_broken`** (Sweet32 64-bit collision attack, NIST SP 800-131A deprecated).

$$\text{Classical Vulnerability Supersedes Quantum Timeline: } \mathbf{AT\ RISK}$$

**ECDAT Plain-English Explanation**:
> *"3DES is classically broken and obsolete; vulnerable to immediate exploitation today regardless of quantum timeline."*
* **Calculated Risk Score**: **95.0 / 100 (CRITICAL)**

---

### Example 4: Modernized Post-Quantum Primitive (NIST ML-KEM-768) &rarr; **QUANTUM SAFE**

* **Asset**: Enterprise key establishment migrated to **ML-KEM-768 (FIPS 203)**.
* **$X$ (Shelf-Life)**: **25 years** (Top secret IP / National security retention).
* **$Y$ (Migration Time)**: **0 years** (Already deployed).
* **$Z$ (Quantum Horizon)**: **12 years**.

$$\text{Quantum-Resistant Primitive: } \mathbf{IMMUNE\ TO\ SHOR'S\ ALGORITHM}$$

**ECDAT Plain-English Explanation**:
> *"ML-KEM is quantum-safe (Standardized in NIST FIPS 203); timeline 25 + 0 > 12 does not present quantum compromise risk."*
* **Calculated Risk Score**: **5.0 / 100 (NEGLIGIBLE)**

---

## 🧮 ECDAT 0-100 Composite Risk Scoring Model

The ECDAT Risk Engine computes a normalized 0-100 risk score combining 4 orthogonal dimensions:

$$\text{Risk Score} = \min(100, \text{Base}(Q) + \text{Crit} + \text{Urgency}(\Delta) + \text{KeyPenalty})$$

1. **Base Score $\text{Base}(Q)$ by Quantum Status**:
   - `classically_broken`: **80.0**
   - `vulnerable_shor`: **70.0** (if $X+Y>Z$) or **45.0** (if $X+Y\le Z$)
   - `weakened_grover`: **50.0** (if $X+Y>Z$) or **30.0** (if $X+Y\le Z$)
   - `quantum_safe`: **5.0**

2. **Business Criticality $\text{Crit}$**:
   - `critical` (payment, auth, credentials, prod): **+15.0**
   - `high` (database, vault, secrets, admin): **+10.0**
   - `medium` (internal API, service, gateway): **+5.0**
   - `low` (test, mock, samples): **+0.0**

3. **Mosca Urgency $\text{Urgency}(\Delta)$**:
   - If $X + Y > Z$, urgency scales with deficit: $+ \min(10.0, 1.5 \times \Delta)$.

4. **Key Size & Algorithmic Weakness $\text{KeyPenalty}$**:
   - RSA $\le 1024$ bits: **+15.0**
   - DES $\le 56$ bits: **+10.0**
