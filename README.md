<div align="center">

# 🔐 AWS Security Auditor v2.0

**Aggressive Cloud Recon & Misconfiguration Scanner**
<br>
*Built for Security Engineers and Red Teamers.*

[![Build Status](https://img.shields.io/badge/Build-Passing-00ffff?style=for-the-badge&logo=githubactions&logoColor=black)](#)
[![Python Version](https://img.shields.io/badge/Python-3.9+-0d0d0d?style=for-the-badge&logo=python&logoColor=00ffff)](#)
[![License](https://img.shields.io/badge/License-MIT-0d0d0d?style=for-the-badge&logoColor=00ffff)](#)

<br>
<i>Insert 10-second Asciinema/Terminalizer GIF recording here showing the new Rich ASCII banner and scanning progress</i><br>
<code>![Terminal Demo](placeholder-for-demo.gif)</code>

</div>

---

## ⚡ Uncompromising Cloud Security

AWS Security Auditor is not just a linter—it is an aggressive, fast-paced reconnaissance tool designed to pinpoint critical IAM, S3, EC2, and CloudTrail misconfigurations before attackers do. With an overhauled **Dark-Mode Terminal UI**, it provides real-time progress bars alongside actionable, color-coded security intelligence.

<br>

## 🛡️ Core Capabilities

<table width="100%">
  <tr>
    <td width="50%">
      <h3>🔑 Identity & Access (IAM)</h3>
      Detects dormant Admin accounts, missing Root MFA, weak password policies, and unused access keys lying in wait.
    </td>
    <td width="50%">
      <h3>🪣 Storage Security (S3)</h3>
      Flags buckets exposing data publicly, lacking SSE (Server-Side Encryption), or operating without vital versioning protections.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🖥️ Compute Exposure (EC2)</h3>
      Pinpoints instances directly exposed to <code>0.0.0.0/0</code> on critical ports (SSH/RDP/DB) and enforces IMDSv2 against SSRF.
    </td>
    <td width="50%">
      <h3>📋 Audit & Logging (CloudTrail)</h3>
      Validates logging integrity, ensures multi-region trails exist, and verifies S3 bucket logging to prevent tampering.
    </td>
  </tr>
</table>

<br>

## 🚀 Quick Start & Execution

Get running in seconds. AWS Security Auditor automatically hooks into your local AWS CLI credentials profile.

### 1. Installation
```bash
git clone https://github.com/anousonephyakeo/aws-security-auditor.git
cd aws-security-auditor
pip install -r requirements.txt
```

### 2. General Audit (Basic Usage)
```bash
# Basic audit using your default AWS profile
python3 -m auditor.cli

# Audit a specific production profile
python3 -m auditor.cli --profile [YOUR_PROFILE_NAME]
```

### 3. Advanced Filtering & Output
Target specific regions, modules, or output the findings directly into CI/CD pipelines via JSON.

```bash
# Target ap-southeast-1 using a specific AWS profile
python3 -m auditor.cli --profile [YOUR_PROFILE_NAME] --region ap-southeast-1

# Run only IAM and S3 modules
python3 -m auditor.cli --checks iam s3

# Deep integration: Export structured JSON reports
python3 -m auditor.cli --output json --report-file audit_results.json
```

<br>

## 🧪 Local Testing Matrix

Ensure compatibility across multiple environments before deploying using standard formatting.

```bash
# Setup multi-version testing
pip install tox
tox -e py39,py310,py311,local
```

---
<div align="center">
<b>MIT License</b><br>
Maintained by SW1ZX (Anousone Phyakeo)
</div>
