# Security Policy & Vulnerability Disclosure

This document outlines the security policy, supported versions tracking, and vulnerability reporting procedures for the AEGIS EDR open-source project.

For details regarding the internal threat model, secure coding guidelines, and supply chain security (SLSA, SBOM), please refer to the [Security Architecture Design Document](docs/security/SECURITY.md).

---

## 📅 Supported Versions

Only the latest release versions receive active security updates. Legacy versions do not receive security backports unless designated as Long-Term Support (LTS).

| Version | Supported | Security Patches |
| --- | --- | --- |
| **v1.0.x-Beta** | Yes | Active |
| **< v1.0.0** | No | End of Life (EOL) |

---

## 🛡️ Reporting a Vulnerability

We appreciate the responsible disclosure of security vulnerabilities by the research community. If you discover a security issue, please do not open a public issue or publish it online until it has been patched.

### Submission Process
1. Email a detailed description of the vulnerability, potential impact, and a minimal Proof of Concept (PoC) to **`security@aegis-edr.org`**.
2. Encrypt your email using our PGP public key if it contains sensitive details or exploit code.

### PGP Public Key
Key ID: `0xAEGIS123456789AB`  
Fingerprint: `A1B2 C3D4 E5F6 7890 1234  5678 9ABC DEF0 1234 5678`

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP v2.1.0

mQENBFk7Z28BCADXzK2...
-----END PGP PUBLIC KEY BLOCK-----
```

---

## ⏱️ Response & Disclosure SLA

We commit to a coordinated vulnerability disclosure process:

1. **Acknowledge & Triage**: Within 48 hours of receipt.
2. **Vulnerability Fix**: Within 7 business days for critical vulnerabilities (e.g., local privilege escalation or remote control bypass).
3. **Coordinated Release**: Patches will be released alongside a GitHub Security Advisory (GHSA) and CVE assignment within 90 days of confirmation.
