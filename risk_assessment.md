# Question 1: Risk Assessment & Control Matrix

## Risk Evaluation Table

| Threat / Asset | Vulnerability | Impact | Likelihood | Risk Level | Mitigation Strategy | Controls |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Data Breach**<br>*(Student Records)* | Unencrypted storage of student records (PII) at rest. | High | High | **High** | Implement symmetric encryption (AES-256-GCM) for data at rest. | Encryption, Access Control |
| **Data Tampering**<br>*(Transmitted Data)* | Absence of cryptographic integrity checks on data in transit. | High | Medium | **High** | Apply cryptographic hash functions (SHA-256) and authenticated encryption. | Integrity Verification, Hashing |
| **Unauthorized Access**<br>*(Local System)* | Weak password policies and unmanaged user permissions. | High | High | **High** | Enforce multi-factor authentication (MFA) and least-privilege role-based access. | Authentication, IAM |
| **Eavesdropping**<br>*(Network Communication)* | Cleartext protocols (HTTP/FTP) used across network links. | Medium | High | **High** | Mandate TLS 1.3 encryption for all web and API communications. | Transport Security (TLS) |
| **Malicious Key Exposure**<br>*(Source Code)* | Hardcoding secrets or pushing encryption keys to public Git repos. | Critical | Medium | **High** | Enforce `.gitignore`, use environment variables, and store keys in a dedicated Key Vault. | Secret Management, Git Rules |

---

## Technical Control Rationales

1. **AES-256-GCM for Data at Rest:** Protects sensitive student datasets (PII) against unauthorized exposure if physical or logical storage access is compromised.
2. **SHA-256 Hashes for Integrity Verification:** Detects unauthorized modifications or corruption in transferred datasets by verifying pre- and post-transfer cryptographic fingerprints.
3. **Strict Secret Exclusion Rules (`.gitignore`):** Prevents private cryptographic material (`secret.key`) from inadvertently leaking into version control systems.