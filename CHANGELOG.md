# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [2.0.5] - 2026-07-09

### Changed
- **Authorship Alignment**: Updated SDK readme to reflect that the Creduent Protocol was originally created by Kashish Kanojia and is stewarded by IDevSec.
- **Resolver Fallbacks**: Swapped legacy `reconbot` test agent references with the authoritative `steward` agent URI.
- **Capabilities Standardization**: Updated test suite capability tags to standard strings (`"query"`, `"resolve"`, `"verify"`) to align with v2.0 schema validator.

## [2.0.4] - 2026-07-05

### Changed

- **Documentation & Examples:** Updated the canonical example agent identity in all documentation and docstrings. Replaced the `reconbot` test agent with `agent://idevsec/steward` to align with the authoritative registry.
- **Test Suite Updates:** Refactored unit and integration tests to validate against the authoritative `steward` agent URI instead of legacy testing stubs.

## [2.0.3] - 2026-07-04

### Fixed
- **CI Test Suite Isolation:** Wrapped FastAPI and local registry imports in `try-except` blocks inside `tests/test_challenge.py`, allowing integration tests to be skipped cleanly in remote VM environments where sibling workspaces (`creduent-vercel`) do not exist.

### Added
- **Community Standards & Styling:** Integrated `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CONTRIBUTING.md`, `.editorconfig`, and `.pre-commit-config.yaml` utilizing Ruff hooks.
- **CI Workflows:** Set up automated Ruff styling checks and publication actions.

## [2.0.2] - 2026-06-27

### Changed
- **Unified Domain Name Migration:** Standardized default registry URL on `creduent.idevsec.com` across all SDK methods, default arguments, and environment configurations.

## [2.0.1] - 2026-06-27

### Fixed
- **Strict Key Storage Permissions:** Enforced owner-only read/write access (`0o600` permissions via `os.chmod`) on generated private key files in both `creduent-sign` (`sign.py`) and standard `creduent keygen` CLI (`cli.py`).

## [2.0.0] - 2026-06-23

### Added
- **v2.0 Schema Split Support**: Added dynamic parsing and version-gating for the v2.0 schema structure separating `identity`, `policy`, and `signature` blocks.
- **DNS Recovery Override Endpoint Support**: Updated SDK resolver to support recovery overrides.
- **Multisig Quorum Authorization Support**: Implemented threshold signature verification client support.
- **Expiry Enforcements**: Synced verification pipeline to handle the shortened 30-day attestation windows.

### Fixed
- **HTTP 410 Revoked Response Handling**: Fixed `attest` to cleanly catch HTTP 410 (revoked) registry status codes and return `AttestResult` with `attested=False` and `level="revoked"` instead of throwing a raw `AttestationError`.

## [0.5.0] - 2026-06-19

### Added
- **Multi-key Support**: Support for rotating signing keys via `keys` array in `agent.json` without losing historical attestation data.
- **Capability-level Attestations**: Support for `capabilities` defined as complex objects (`name` and `schema` properties).
- **Organization Namespaces**: Namespace validation allowing organizations to claim `agent://<org_name>/*` scopes.
- **Discovery API**: Native `discover()` API with support for authenticated, private capability sharing.
- **Creduent CLI v2**: Revamped CLI with `init`, `keygen`, `build`, and `discover` tools.
- **CRD Shorthand**: Support for declarative Kubernetes-style `agent.yaml` for generating `agent.json` documents.
- **Integrations**: Native verification tools/nodes for CrewAI, LangGraph, and AutoGen in `creduent.integrations`.

## [0.4.8] - 2026-06-13

### Changed
- Migrated default registry URL from `api.idevsec.com` to `creduent.idevsec.com`.

## [0.4.7] - 2026-06-11

### Fixed
- Cleaned up and consolidated public release history to remove internal packaging/deployment details.

## [0.4.6] - 2026-06-11

### Changed
- Documentation updates and formatting fixes in `README.md`.

## [0.4.3] - [0.4.5] - 2026-06-11

### Changed
- **Infrastructure:** Updated project repository URL and configured token-based PyPI publishing.
- **Maintenance:** Internal version bumps to align with registry `1.0.3` deployment and resolve publishing metadata (no public API changes).

## [0.4.2] - 2026-06-08

### Added
- Dynamic public key pinning verification support in `challenge.verify_proof` via optional argument or `CREDUENT_REGISTRY_PUBKEY` environment variable.
- Outbound IPv6 DNS resolution support in `utils.resolve_ips` using `socket.getaddrinfo`.

### Changed
- Standardized the base exception class name from `CreduEntError` to `CreduentError` for symmetry with JS/CLI, maintaining `CreduEntError` as a backward-compatible alias.

## [0.4.1] - 2026-06-02

### Fixed
- Normalized `pyproject.toml` line endings from CRLF (`\r\n`) to LF (`\n`) to look clean in diffs.
- Fixed metadata inconsistency by adding `python_requires=">=3.10"` to `setup.py` (matching `pyproject.toml`).
- Replaced the invalid `{text = "Apache-2.0 OR Commercial"}` SPDX expression in `pyproject.toml` with `license-files` declaration to properly package `LICENSE`, `LICENSE-APACHE`, and `LICENSE-COMMERCIAL` for PyPI.

### Added
- Created initial `CHANGELOG.md` for project version and release history tracking.

## [0.4.0] - 2026-06-02

### Changed
- Changed project license from MIT to Dual Licensing (Apache-2.0 and Commercial License).
- Updated package author metadata to IDevSec.
- Removed FastAPI dependency from client SDK/CLI.
- Added dynamic public key query endpoint `/registry/public-key` to registry.
- Added outbound SSRF-protected POST helper `safe_requests_post`.

### Added
- Added Challenge-Response Authentication feature: `challenge.create_proof` and `challenge.verify_proof`.

## [0.2.3] - 2026-05-31

### Changed
- Refactored `safe_requests_get` to fetch the original URL directly with `verify=True` enabled for secure SSL verification.
- Synced the SSRF safety request client between the Vercel registry server and Python SDK.

## [0.2.2] - 2026-05-30

### Added
- Added custom headers support (`User-Agent` and `Accept: application/json`) to the registry's agent verification fetch requests.

## [0.2.1] - 2026-05-29

### Added
- Complete registration guide added to README: 6-step pipeline, DNS TXT setup, error table, and checklist.

### Fixed
- Fixed function name documentation (register, attest, verify, sign).

## [0.2.0] - 2026-05-28

### Changed
- Replaced `requests.get` with `safe_requests_get` for SSRF protection.
- Updated documentation and simplified CLI usage.

### Added
- Added comprehensive Google-style docstrings and type hints.

## [0.1.5] - 2026-05-27

### Added
- Internal beta release with security features and docstring polish.

## [0.1.2] - 2026-05-26

### Added
- Initial release: core signing, verification, and registration logic.
