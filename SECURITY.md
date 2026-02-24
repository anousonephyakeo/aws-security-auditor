# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities through [GitHub Security Advisories](https://github.com/anousonephyakeo/aws-security-auditor/security/advisories/new) (private, encrypted).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact / severity assessment
- Any suggested fix (optional but appreciated)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Patch / workaround | 14 days (critical), 30 days (others) |
| Public disclosure | After patch is released |

### Scope

In scope:
- Code execution vulnerabilities in the tool itself
- Sensitive data leakage (credentials, secrets in output)
- Dependency vulnerabilities with active exploits

Out of scope:
- Findings on targets scanned *by* the tool (that's the tool's purpose)
- Issues requiring physical access to the machine
- Issues already publicly known

## Hall of Fame

Security researchers who responsibly disclosed vulnerabilities will be credited here.

---

*This project follows [Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/Wiki/Coordinated+Vulnerability+Disclosure+Guidance).*
