# Creduent Python SDK

[![PyPI version](https://img.shields.io/pypi/v/creduent.svg?color=blue)](https://pypi.org/project/creduent/)
[![License](https://img.shields.io/github/license/idevsec/creduent.svg)](https://github.com/idevsec/creduent/blob/main/LICENSE)
[![Python Compatibility](https://img.shields.io/pypi/pyversions/creduent.svg)](https://pypi.org/project/creduent/)
[![Downloads](https://pepy.tech/badge/creduent)](https://pepy.tech/project/creduent)

The official Python SDK for the **Creduent Protocol** — a federated, open trust-verification layer and cryptographic identity infrastructure for autonomous AI agents.

Creduent enables autonomous agents to cryptographically sign metadata, verify identities across administrative domains via DNS bindings, and interact with the Creduent registry for secure, machine-to-machine trust checks.

---

## Key Features

- 🔑 **Cryptographic Identity Management**: Generate secure Ed25519 keypairs for AI agents.
- ✍️ **RFC 8785 Canonical Signatures**: Compute cryptographic signatures over JSON agent documents using JCS and Ed25519.
- 🛡️ **SSRF Protection**: Safe endpoint resolution blocking private/loopback network ranges.
- 🔗 **DNS Trust Binding**: Verify cryptographic bindings between `agent://` identifiers and web domains.
- 🏛️ **Registry Integration**: Register agents and resolve signed attestations from the Creduent Registry.
- 🛠️ **CLI Utilities**: Out-of-the-box CLI commands for signing, verification, and key generation.
- ⚙️ **Serverless-Safe Env Loader**: Avoids `.env` interference in Vercel and other serverless environments.

---

## Installation

```bash
pip install creduent
```

---

## Architectural Flow

```
+------------------+             +----------------------+             +------------------+
|   Agent Domain   |             |   Creduent Registry  |             |   Agent Client   |
|   (agent.json)   |             |   api.idevsec.com    |             |    (MCP Host)    |
+------------------+             +----------------------+             +------------------+
         |                                |                                |
         |---- 1. Serve agent.json ------>|                                |
         |                                |-- 2. Verify identity & DNS --->|
         |                                |      and sign attestation      |
         |<--- 3. Query agent endpoint ------------------------------------|
         |                                |                                |
         |                                |<--- 4. Fetch attestation ------|
```

---

## Registering Your Agent

Registration is **open** — no admin key required. Any developer can register an agent.
After registration, your agent gets `level: "unverified"`. Contact the registry admin for `verified` or `trusted` upgrade.

The backend runs **6 verification steps** — all must pass:

```
Step 1 → Fetch agent.json from your agent_json_url
Step 2 → Validate schema (7 required fields)
Step 3 → Confirm agent_id matches in both form and file
Step 4 → Verify Ed25519 self-signature
Step 5 → Check DNS TXT record: _creduent.yourdomain.com
Step 6 → Health check your agent endpoint (must be live HTTPS)
```

---

### Step 1 — Generate Ed25519 Keypair

```python
from creduent import generate_keys

private_key_pem, public_key_str = generate_keys()

with open("private_key.pem", "w") as f:
    f.write(private_key_pem)

print(public_key_str)  # ed25519:ABC123...  ← goes in agent.json
```

Or via CLI:
```bash
creduent-sign generate-keys
# Saves: private_key.pem  (KEEP SECRET)
# Prints: ed25519:...     (public key)
```

---

### Step 2 — Create agent.json

Create a draft with these **required fields**:

```json
{
  "version": "1.0",
  "agent_id": "agent://yourorg/youragent",
  "owner": "Your Name or Organization",
  "public_key": "ed25519:ABC123...",
  "endpoint": "https://yourdomain.com/agent",
  "capabilities": ["task_execution", "file_read"]
}
```

| Field | Requirement |
|-------|-------------|
| `version` | Must be exactly `"1.0"` |
| `agent_id` | Format: `agent://<namespace>/<name>` — lowercase, alphanumeric, hyphens |
| `owner` | Any string |
| `public_key` | Must start with `ed25519:` |
| `endpoint` | Live public HTTPS URL (no localhost, no private IPs) |
| `capabilities` | Array of strings |
| `signature` | Added in next step — do not add manually |

---

### Step 3 — Sign agent.json

```python
from creduent import sign
import json

with open("draft_agent.json") as f:
    draft = json.load(f)

with open("private_key.pem") as f:
    private_key_pem = f.read()

signed_doc = sign(draft, private_key_pem)

with open("agent.json", "w") as f:
    json.dump(signed_doc, f, indent=2)
```

Or via CLI:
```bash
creduent-sign sign \
  --key private_key.pem \
  --input draft_agent.json \
  --output agent.json
```

> **Important:** Re-sign every time you modify `agent.json`. Any change to the document invalidates the signature.

---

### Step 4 — Host agent.json

Serve the signed file at a public HTTPS URL. Recommended path:

```
https://yourdomain.com/.well-known/agent.json
```

Requirements:
- HTTP `200` response
- `Content-Type: application/json`
- No auth, no VPN, no private IPs — must be publicly reachable

---

## Cloudflare Users — Required Configuration

If your domain is proxied through Cloudflare (orange cloud), you must add a WAF rule before registering. Without this, Cloudflare will block the Creduent registry server from fetching your agent.json and health-checking your endpoint, returning HTTP 403.

### Rule 1 — Allow Registry Fetch and Endpoint Health Check

Cloudflare Dashboard → Security → Security Rules → Custom Rules → Create Rule

Name: Allow Creduent Manifest and Endpoint
Field: URI Path
Operator: is in
Value: 
- `/.well-known/agent.json`
- `/<your-agent-endpoint-path>` (e.g. `/agent` or `/api/agent`)
Action: Skip
Skip: All remaining custom rules + All rate limiting rules + All managed rules
Place at: First

### DNS TXT Record (Cloudflare)

When adding the _creduent TXT record in Cloudflare DNS:
- Make sure the orange cloud (proxy) is OFF for the TXT record
- TXT records do not need to be proxied
- TTL: Auto

### Common Cloudflare Errors

| Error | Cause | Fix |
|-------|-------|-----|
| Failed to fetch agent.json: HTTP 403 | Cloudflare WAF blocking registry server | Add the WAF rule above |
| Failed to fetch agent.json: HTTP 403 (after adding rules) | Bot Fight Mode JS challenge | Disable JS Detections under Security → Bots |
| Registration succeeds but resolver shows 403 | CSP blocking api.idevsec.com | Add api.idevsec.com to connect-src in your site's CSP headers |

---

### Step 5 — Add DNS TXT Record

Proves domain ownership. Add this to your domain's DNS:

| Type | Name | Value |
|------|------|-------|
| `TXT` | `_creduent` | `agent://yourorg/youragent` |

Full record name: `_creduent.yourdomain.com`

Verify propagation (~5 min):
```bash
# Windows
nslookup -type=TXT _creduent.yourdomain.com

# Linux / Mac
dig TXT _creduent.yourdomain.com
# Expected: "agent://yourorg/youragent"
```

---

### Step 6 — Register

```python
from creduent import register

result = register(
    agent_id="agent://yourorg/youragent",
    domain="yourdomain.com",
    agent_json_url="https://yourdomain.com/.well-known/agent.json"
)

if result.success:
    print(f"Registered! Level: {result.attestation['level']}")
    # → Registered! Level: unverified
else:
    print(f"Failed: {result.error}")
```

Or via curl:
```bash
curl -X POST https://api.idevsec.com/registry/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent://yourorg/youragent",
    "domain": "yourdomain.com",
    "agent_json_url": "https://yourdomain.com/.well-known/agent.json"
  }'
```

**Success response:**
```json
{
  "agent_id": "agent://yourorg/youragent",
  "issuer": "agent://creduent/registry",
  "level": "unverified",
  "issued_at": "2026-05-31T00:00:00Z",
  "expires_at": "2027-05-31T00:00:00Z",
  "public_key": "ed25519:...",
  "domain": "yourdomain.com",
  "signature": "...",
  "status": "registered"
}
```

---

### Common Registration Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Failed to fetch agent.json: HTTP 404` | File not at URL | Check URL is public and returns 200 |
| `Missing required field 'signature'` | Draft not signed | Run `creduent-sign sign` first |
| `agent_id in agent.json does not match` | Mismatch in form vs file | Use exact same string in both |
| `Cryptographic signature is INVALID` | File modified after signing | Re-sign with `creduent-sign sign` |
| `DNS TXT record not found (NXDOMAIN)` | TXT record missing | Add `_creduent` TXT to your DNS |
| `does not contain agent_id` | Wrong TXT value | Value must be exactly `agent://yourorg/youragent` |
| `Endpoint healthcheck failed` | Endpoint unreachable | Is your server live? Public HTTPS? |
| `429 Too many requests` | 5/hour rate limit | Wait 1 hour and retry |

---

### Registration Checklist

```
[ ] Ed25519 keypair generated (private_key.pem + public key)
[ ] draft_agent.json created with all required fields
[ ] agent.json signed (signature field present)
[ ] agent.json hosted at a public HTTPS URL
[ ] DNS TXT record added: _creduent.yourdomain.com = agent://yourorg/youragent
[ ] DNS propagated (verified with nslookup or dig)
[ ] register() called → status: "registered" received
```

---

## Quickstart (Full Example)

```python
from creduent import generate_keys, sign, verify, register, attest, CreduentError

try:
    # 1. Generate keypair
    private_key_pem, public_key_str = generate_keys()

    # 2. Sign a draft agent.json
    draft = {
        "version": "1.0",
        "agent_id": "agent://creduent/reconbot",
        "owner": "IDevSec",
        "public_key": public_key_str,
        "endpoint": "https://api.idevsec.com/recon",
        "capabilities": ["osint", "dns_lookup"]
    }
    signed_doc = sign(draft, private_key_pem)

    # 3. Verify self-signed document
    result = verify(signed_doc)
    print(f"Self-verify: {result.valid}")

    # 4. Register with registry (requires DNS + hosted agent.json)
    reg = register(
        agent_id="agent://creduent/reconbot",
        domain="api.idevsec.com",
        agent_json_url="https://api.idevsec.com/.well-known/agent.json"
    )
    print(f"Registered: {reg.success}, Level: {reg.attestation['level']}")

    # 5. Query attestation
    att = attest("agent://creduent/reconbot")
    print(f"Attested: {att.attested}, Level: {att.level}")

except CreduentError as e:
    print(f"Error: {e}")
```

---

## Challenge-Response Authentication

Allows agents to prove their cryptographically registered identity to other agents.

```python
# Agent proving its identity to another agent
from creduent import challenge

# Agent side — prove identity
proof = challenge.create_proof(
    agent_id="agent://cyberhavox/havox-ai",
    private_key_pem=open("private_key.pem").read()
)
# proof = {"verified": True, "level": "trusted", "proof_token": "...", "valid_until": "..."}

# Receiver side — verify the proof
is_valid = challenge.verify_proof(
    proof_token=proof["proof_token"],
    agent_id="agent://cyberhavox/havox-ai"
)
print(is_valid)  # True
```

---

## Command Line Interface

### `creduent-sign`

```bash
# Generate Ed25519 keypair
creduent-sign generate-keys

# Sign a draft agent.json
creduent-sign sign --key private_key.pem --input draft_agent.json --output agent.json
```

### `creduent-verify`

```bash
# Verify a local file
creduent-verify agent.json

# Verify by URL
creduent-verify https://yourdomain.com/.well-known/agent.json

# Verify by domain
creduent-verify yourdomain.com

# Verify by agent:// URI
creduent-verify agent://creduent/reconbot
```

---

## API Reference

### `generate_keys() → (private_key_pem: str, public_key_str: str)`
Generates a new Ed25519 keypair. Returns PEM private key and `ed25519:`-prefixed public key.

### `sign(draft: dict, private_key_pem: str) → dict`
Signs a draft agent.json using JCS canonicalization (RFC 8785) + Ed25519. Returns signed document with `signature` field.

### `verify(target: str | dict) → VerifyResult`
Verifies a self-signed agent.json. Accepts dict, HTTPS URL, domain, local path, or `agent://` URI.
- `result.valid` — bool
- `result.agent_id`, `result.public_key`, `result.endpoint`, `result.capabilities`
- `result.error` — str or None

### `register(agent_id, domain, agent_json_url, registry_url?) → RegisterResult`
Registers an agent with the Creduent registry.
- `result.success` — bool
- `result.attestation` — dict (level, issued_at, expires_at, ...)
- `result.error` — str or None

### `attest(agent_id, registry_url?) → AttestResult`
Fetches attestation status for an agent from the registry.
- `result.attested` — bool
- `result.level` — `"unverified"` | `"verified"` | `"trusted"`
- `result.issued_at`, `result.expires_at`
- `result.error` — str or None

### `challenge.create_proof(agent_id, private_key_pem, registry_url?) → dict`
Initiates a cryptographic challenge-response authentication flow to generate an identity verification proof.
- Returns dict containing `proof_token`, `verified` status, `level`, `valid_until` timestamp, and `issuer`.

### `challenge.verify_proof(proof_token, agent_id, registry_url?) → bool`
Decodes the proof token and verifies its authenticity using the registry's public key. Returns `True` if valid and not expired, `False` otherwise.

---

## Advanced Utilities

### SSRF Protection
```python
from creduent.utils import safe_requests_get

response = safe_requests_get("https://example.com/.well-known/agent.json", timeout=5)
```
Blocks private IPs (RFC 1918), loopback, and link-local addresses before connecting.

### Serverless Environment Loader
```python
from creduent.utils import load_dotenv

load_dotenv()  # Skips loading in Vercel (VERCEL=1) to avoid clobbering prod env vars
```

---

## Changelog

> Full history: [CHANGELOG.md](CHANGELOG.md)

### v0.4.5 (Current)
- Resolved PyPI `400 Bad Request` error caused by re-uploading an already-published version. Version bumped with a clean `dist/` rebuild.

### v0.4.4
- Updated project URL from `idevsec/creduent` to `idevsec/creduent-python` in `pyproject.toml` and `setup.py`.
- Configured `~/.pypirc` for token-based PyPI publishing.

### v0.4.3
- Version bumped to stay in sync with registry `1.0.3` deployment.
- Confirmed compatibility with registry `1.0.3` premium dashboard (Level, Renew, Revoke modal card headers, mobile card stack layout).

### v0.4.2
- Added dynamic public key pinning verification support in `challenge.verify_proof` via optional argument or `CREDUENT_REGISTRY_PUBKEY` environment variable.
- Outbound IPv6 DNS resolution support in `utils.resolve_ips` using `socket.getaddrinfo`.
- Standardized exception class name from `CreduEntError` to `CreduentError` (backward-compatible alias retained).

### v0.4.1
- Normalized `pyproject.toml` line endings from CRLF (`\r\n`) to LF (`\n`).
- Fixed metadata inconsistency by adding `python_requires=">=3.10"` to `setup.py` (matching `pyproject.toml`).
- Replaced the invalid `{text = "Apache-2.0 OR Commercial"}` SPDX expression in `pyproject.toml` with `license-files` declaration to properly package `LICENSE`, `LICENSE-APACHE`, and `LICENSE-COMMERCIAL` for PyPI.
- Created initial `CHANGELOG.md` tracking detailed package version history.

### v0.4.0
- Changed project license from MIT to Dual Licensing (Apache-2.0 and Commercial License).
- Updated package author metadata to IDevSec.
- Removed FastAPI dependency from client SDK/CLI.
- Added Challenge-Response Authentication feature: `challenge.create_proof` and `challenge.verify_proof`.
- Added dynamic public key query endpoint `/registry/public-key` to registry.
- Added outbound SSRF-protected POST helper `safe_requests_post`.

### v0.2.3
- Refactored `safe_requests_get` to fetch the original URL directly with `verify=True` enabled for secure SSL verification.
- Synced the SSRF safety request client between the Vercel registry server and Python SDK.

### v0.2.2
- Added custom headers support (`User-Agent` and `Accept: application/json`) to the registry's agent verification fetch requests.

### v0.2.1
- Complete registration guide added to README: 6-step pipeline, DNS TXT setup, error table, and checklist.
- Fixed function name documentation (register, attest, verify, sign).

### v0.2.0
- Replaced `requests.get` with `safe_requests_get` for SSRF protection.
- Added comprehensive Google-style docstrings and type hints.
- Updated documentation and simplified CLI usage.

### v0.1.5
- Internal beta release with security features and docstring polish.

### v0.1.2
- Initial release: core signing, verification, and registration logic.


---

## Contributing

Bugs, feature requests, and pull requests welcome via [GitHub Issues](https://github.com/idevsec/creduent/issues).

---

## License

Dual Licensed under Apache License 2.0 (Open Source) and Commercial License — see [LICENSE](LICENSE).
