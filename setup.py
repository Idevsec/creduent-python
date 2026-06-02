from setuptools import setup, find_packages

setup(
    name="creduent",
    version="0.4.0",
    author="IDevSec",
    url="https://github.com/idevsec/creduent",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "requests",
        "jcs",
    ],
    entry_points={
        "console_scripts": [
            "creduent-sign=creduent.sign:main",
            "creduent-verify=creduent.verify:main",
        ]
    }
)
