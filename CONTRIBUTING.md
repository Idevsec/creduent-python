# Contributing to Creduent Python SDK

Thank you for your interest in contributing to the Creduent Python SDK! This guide helps you set up your local development environment and outlines our contribution guidelines.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating. By contributing, you agree to abide by its terms.

---

## Contributor Licensing (DCO)

By submitting a Pull Request, you certify that your contribution is made under the terms of the [Developer Certificate of Origin](https://developercertificate.org). Add a sign-off to every commit:

```bash
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <your@email.com>` line to your commit. Pull Requests without a sign-off on every commit will not be merged.

---

## Development Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/idevsec/creduent-python.git
   cd creduent-python
   ```

2. **Set up a Virtual Environment:**
   Ensure you have Python 3.10+ installed, then run:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install Dependencies & Package in Editable Mode:**
   Install the package along with optional integrations and development test runners:
   ```bash
   pip install -e ".[all]" pytest
   ```

4. **Verify Installation & Run Tests:**
   Execute the test suite to verify everything passes:
   ```bash
   pytest
   ```

---

## Code Guidelines & Robustness Guarantees

Please ensure all contributions respect the security and design criteria of the Creduent Protocol:
* **Cryptographic Integrity:** Local signature verification must use standard cryptographic wrappers (like `cryptography` primitives) and reject signature mismatches with explicit errors.
* **Canonicalization:** Payloads must be formatted exactly using RFC 8785 JSON Canonicalization Scheme (JCS) before generating or verifying signatures.
* **Typing & Documentation:** Adhere to PEP 8 standards and ensure all new features include proper type hints and docstrings.

---

## Git Workflow & Branching Strategy

To keep the repository clean and manageable, please follow our branching conventions:

### Branch Naming Conventions

* **Features:** Use prefix `feature/` (e.g., `feature/crewai-integration-upgrade`) for new API capabilities or framework adapters.
* **Bugfixes:** Use prefix `bugfix/` (e.g., `bugfix/signature-validation-padding`) for fixing bugs or issues.
* **Documentation:** Use prefix `docs/` (e.g., `docs/usage-instructions-update`) for changes to documentation or README files.
* **Refactoring:** Use prefix `refactor/` (e.g., `refactor/async-network-layer`) for code refactors with no functional changes.

### Pull Request Process

1. Create a local branch from the `main` branch following the naming conventions above.
2. Make changes and verify them locally. Ensure code formatting is clean.
3. Push your branch to GitHub.
4. Open a Pull Request (PR) against the `main` branch.
5. Fill out the Pull Request template completely.
6. Ensure any checks (CI workflows) pass and request review from maintainers.

---

## Commit Message Conventions

We follow the Conventional Commits specification. Commit messages must be structured as follows:

```text
<type>(<scope>): <description>

[optional body]
```

Allowed types include:
- `feat`: A new protocol feature or SDK capability.
- `fix`: A bug fix in the reference implementation or schema.
- `docs`: Documentation updates.
- `refactor`: Code changes that do not alter behavior.

---

## Project Roadmap & Wanted Features

The Creduent Python SDK follows the global [Creduent Protocol Roadmap](https://github.com/idevsec/creduent/blob/main/ROADMAP.md). If you are looking for specific ways to contribute to the Python SDK ecosystem, please refer to our active hotspots below:

### Python SDK Active Hotspots
* **Framework Integrations (Phase 4):** Help expand framework adapters for:
  * **LlamaIndex Python** (custom tools and validation wrappers).
  * **Google ADK** (Agent Development Kit verification node).
  * **Semantic Kernel** (Python verification middleware).
* **Verifier Caching (Phase 4):** Implement thread-safe local caching wrappers for agent attestation lookups to protect registry origin endpoints under load.
* **Delegation (CREDUENT-007 / Phase 5):** Assist in implementing reference signing logic for delegation tokens (`sign_delegation()`) and recursive chain validation logic.

Before opening a Pull Request for a new feature, please open an Issue to align on the specification and design.

