from setuptools import setup, find_packages

setup(
    name="aws-security-auditor",
    version="1.0.0",
    author="SW1ZX (Anousone Phyakeo)",
    description="Automated AWS security misconfiguration scanner",
    packages=find_packages(),
    install_requires=["boto3", "requests"],
    entry_points={"console_scripts": ["aws-audit=auditor.cli:main"]},
    python_requires=">=3.9",
)
