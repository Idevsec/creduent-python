from setuptools import setup, find_packages

setup(
    name="creduent",
    version="0.5.2",
    author="IDevSec",
    url="https://github.com/idevsec/creduent-python",
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
    }
)
