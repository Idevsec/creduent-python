from setuptools import setup, find_packages

setup(
    name="creduent",
    version="2.0.6",
    author="IDevSec",
    url="https://github.com/idevsec/creduent-python",
    description="Creduent is the open application-layer protocol for cryptographic identity and trust verification of autonomous AI agents using Ed25519 and DNS.",
    keywords=[
        "creduent",
        "AI agent identity",
        "cryptographic trust",
        "agent.json",
        "Ed25519",
        "attestation registry",
    ],
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography",
        "requests",
        "jcs",
    ],
    extras_require={
        "crewai": ["crewai"],
        "langgraph": ["langgraph"],
        "autogen": ["autogen"],
        "all": ["crewai", "langgraph", "autogen"],
    },
    entry_points={
        "console_scripts": [
            "creduent=creduent.cli:main",
            "creduent-sign=creduent.sign:main",
            "creduent-verify=creduent.verify:main",
        ]
    },
)
