# Creduent Python SDK

[![PyPI version](https://img.shields.io/pypi/v/creduent.svg?color=blue)](https://pypi.org/project/creduent/)
[![License](https://img.shields.io/github/license/idevsec/creduent.svg)](https://github.com/idevsec/creduent/blob/main/LICENSE)
[![Python Compatibility](https://img.shields.io/pypi/pyversions/creduent.svg)](https://pypi.org/project/creduent/)

The official Python SDK for the **Creduent Protocol** — a federated, open trust-verification layer and cryptographic identity infrastructure for autonomous AI agents.

Creduent enables autonomous agents to cryptographically sign metadata, verify identities across administrative domains via DNS bindings, and interact with the Creduent registry for secure, machine-to-machine trust checks.

---

## Key Features

- **Cryptographic Identity Management**: Generate secure Ed25519 keypairs for AI agents (multi-key support enabled).
- **RFC 8785 Canonical Signatures**: Compute cryptographic signatures over JSON agent documents using JCS and Ed25519.
- **DNS Trust Binding**: Verify cryptographic bindings between `agent://` identifiers and web domains.
- **Registry Integration**: Register agents and resolve signed attestations from the Creduent Registry.
- **Discovery API**: Directly fetch and parse an agent's `agent.json` from their well-known endpoint without needing the registry.
- **Framework Integrations**: Native middleware/tools for **CrewAI**, **LangGraph**, and **AutoGen**.
- **Unified CLI `creduent`**: Out-of-the-box CLI commands for CRD scaffolding, signing, and capability discovery.

---

## Installation

```bash
pip install creduent
```

To install with specific framework integration support:
```bash
pip install "creduent[crewai]"
pip install "creduent[langgraph]"
pip install "creduent[autogen]"
pip install "creduent[all]"
```

---

## Agent Framework Integrations

Creduent provides native verification adapters for major AI agent frameworks, ensuring you can verify another agent's identity before interacting with it.

### CrewAI
```python
from creduent.integrations.crewai import CreduentVerificationTool
from crewai import Agent, Task, Crew

verify_tool = CreduentVerificationTool()

security_agent = Agent(
    role='Security Verifier',
    goal='Verify the identity of external agents before interacting',
    backstory='You are a strict security officer enforcing the Creduent protocol.',
    tools=[verify_tool]
)
```

### LangGraph
```python
from creduent.integrations.langgraph import create_verification_node
from langgraph.graph import StateGraph

def my_agent_node(state):
    # your logic
    pass

workflow = StateGraph(MyState)
# Insert verification middleware before interaction
workflow.add_node("verify_agent", create_verification_node("agent://example/target_agent"))
workflow.add_node("interact", my_agent_node)
workflow.add_edge("verify_agent", "interact")
```

### AutoGen
```python
from creduent.integrations.autogen import CreduentAgentMiddleware
import autogen

# Wrap your assistant to automatically verify incoming/outgoing agent messages
secure_assistant = CreduentAgentMiddleware(
    autogen.AssistantAgent(name="assistant", llm_config=llm_config)
)
```

---

## Command Line Interface (CLI v2)

The new unified `creduent` CLI uses a YAML-first CRD (Custom Resource Definition) approach to manage your agent identities.

### 1. Scaffold `agent.yaml`
```bash
creduent init
```
*Creates a draft `agent.yaml` in the current directory.*

### 2. Generate Keys
```bash
creduent keygen
```
*Generates Ed25519 keys inside `.creduent/keys/` and prints your public key.*

### 3. Build & Sign `agent.json`
```bash
creduent build
```
*Reads `agent.yaml` and `.creduent/keys/private.pem` (or `CREDUENT_PRIVATE_KEY` env var) and compiles a fully canonicalized, signed `agent.json` ready for deployment.*

### 4. Discover Agent Capabilities
```bash
# Public discovery
creduent discover agent://stripe/payments

# Authenticated discovery (presents your agent identity)
creduent discover agent://stripe/payments --as agent://my_org/my_agent
```

---

## API Reference

### `discover(target_agent_id: str, my_agent_id: str = None, private_key_pem: str = None) -> DiscoveryResult`
Resolves an agent's URL from the registry, fetches their `agent.json`, verifies its cryptographic signature and DNS bindings offline, and returns their capabilities. Can optionally perform authenticated discovery using your own key.

### `sign(draft: dict, private_key_pem: str) -> dict`
Signs a draft agent document using JCS canonicalization (RFC 8785) + Ed25519. Returns signed document with the `keys` and `signature` fields.

### `verify(target: str | dict) -> VerifyResult`
Verifies a self-signed agent.json. Accepts dict, HTTPS URL, domain, local path, or `agent://` URI.
- `result.valid` — bool
- `result.agent_id`, `result.keys`, `result.endpoint`, `result.capabilities`
- `result.error` — str or None

### `register(agent_id, domain, agent_json_url, registry_url?) -> RegisterResult`
Registers an agent with the Creduent registry.
- `result.success` — bool
- `result.attestation` — dict (level, issued_at, expires_at, ...)

### `attest(agent_id, registry_url?) -> AttestResult`
Fetches attestation status for an agent from the registry.

---

## Contributing
Bugs, feature requests, and pull requests welcome via [GitHub Issues](https://github.com/idevsec/creduent/issues).

## License
Dual Licensed under Apache License 2.0 (Open Source) and Commercial License — see [LICENSE](LICENSE).
