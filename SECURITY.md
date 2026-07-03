# Security Policy

We take the security of this SDK and the cryptographic integrity of the Creduent Protocol seriously.

---

## Supported Versions

Only the latest release of Creduent Python SDK is actively supported with security patches and enhancements.

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| < 2.0.0 | No        |

---

## Security Guarantees & Verification Integrity

Creduent Python SDK implements strict safety and cryptographic validation measures:
*   **Decentralized Verification:** Validates Ed25519 signatures locally. No third-party network resolution is trusted for cryptographic verification.
*   **Secure Dependency Practices:** Leverages standard and security-vetted packages (`cryptography`) to prevent timing and side-channel attacks on Ed25519 validation routines.

---

## Reporting a Vulnerability

If you discover a security vulnerability within the Creduent Python SDK (e.g., signature bypasses, JCS serialization bugs, or key parsing vulnerabilities), please report it responsibly:

1. Do NOT open a public GitHub issue detailing the vulnerability.
2. Email your findings and a proof-of-concept (PoC) directly to the maintainers or security contacts at `security@idevsec.com`.
3. Allow the maintainers time to analyze, reproduce, and release a patch before disclosing details publicly.
