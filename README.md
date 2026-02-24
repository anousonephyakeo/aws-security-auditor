# 🔐 AWS Security Auditor

> Automated AWS cloud misconfiguration scanner for IAM, S3, EC2, and CloudTrail — built for security engineers and red teamers.

[![CI](https://github.com/anousonephyakeo/aws-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/anousonephyakeo/aws-security-auditor/actions)
![Python](https://img.shields.io/badge/Python-3.9+-0d0d0d?style=flat-square&logo=python&logoColor=00ffff)
![License](https://img.shields.io/badge/License-MIT-0d0d0d?style=flat-square&logoColor=00ffff)

## ✨ Features

| Module | Checks |
|--------|--------|
| 🔑 **IAM** | Root MFA, password policy, unused keys, admin users |
| 🪣 **S3** | Public access blocks, encryption, logging, versioning |
| 🖥️ **EC2** | Open SGs (SSH/RDP/DB), IMDSv2 enforcement, public IPs |
| 📋 **CloudTrail** | Trail enabled, multi-region, log validation, bucket logging |

## 🚀 Quick Start

```bash
git clone https://github.com/anousonephyakeo/aws-security-auditor.git
cd aws-security-auditor
pip install -r requirements.txt

# Run all checks (uses your default AWS CLI profile)
python -m auditor.cli

# Run specific checks
python -m auditor.cli --checks iam s3

# Export to JSON
python -m auditor.cli --output json --report-file report.json

# Export to Markdown
python -m auditor.cli --output markdown --report-file report.md

# Use a named AWS profile + specific region
python -m auditor.cli --profile my-profile --region ap-southeast-1
```

## 📊 Sample Output

```
============================================================
  AWS Security Auditor — SW1ZX
  2025-01-01 00:00:00 UTC
============================================================

  [CRITICAL ] root_mfa                         | root
           → Root account MFA is DISABLED

  [HIGH     ] password_policy                  | account
           → Weak policy: min length < 14, symbols not required

  [HIGH     ] open_security_group              | sg-0abc123 (default)
           → Port 22 (SSH) open to the world
```

## 🧪 Running Tests

```bash
pip install pytest moto[all]
pytest tests/ -v
```

## 📚 Checks Reference

### IAM
- `root_mfa` — Root account must have MFA
- `password_policy` — Enforce strong passwords (length ≥14, symbols, numbers, uppercase, max age 90d)
- `unused_access_keys` — Flag keys inactive for 90+ days
- `admin_users` — Detect users with AdministratorAccess

### S3
- `s3_public_access` — All buckets must block public access
- `s3_encryption` — Server-side encryption required
- `s3_logging` — Access logging must be enabled
- `s3_versioning` — Versioning recommended for data protection

### EC2
- `open_security_group` — No SSH/RDP/DB ports to 0.0.0.0/0
- `imdsv2_not_enforced` — IMDSv2 (HttpTokens=required) prevents SSRF
- `public_ec2_instance` — Flag instances with public IPs

### CloudTrail
- `cloudtrail_enabled` — At least one trail must exist
- `cloudtrail_multi_region` — Should cover all regions
- `cloudtrail_log_validation` — Integrity validation prevents log tampering
- `cloudtrail_bucket_logging` — CloudTrail S3 bucket should log access

## ⚖️ License

MIT — SW1ZX / Anousone Phyakeo
