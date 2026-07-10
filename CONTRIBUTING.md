# Contributing to Creduent Python SDK

Thank you for your interest in contributing to the Creduent Python SDK! This guide helps you set up your local development environment and outlines our contribution guidelines.

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
