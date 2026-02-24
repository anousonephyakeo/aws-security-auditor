# Contributing

Thanks for your interest in contributing! This project welcomes issues, suggestions, and pull requests.

## Getting Started

```bash
git clone https://github.com/anousonephyakeo/\<REPO\>.git
cd <REPO>
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Development Workflow

1. **Fork** the repo and create a branch: `git checkout -b feat/my-feature`
2. **Write code** — follow the style guide below
3. **Add tests** — all new features must have tests
4. **Run checks** locally: `make all`
5. **Commit** with emoji prefix (see convention below)
6. **Open a PR** using the PR template

## Code Style

- **Formatter**: `black` — `make fmt`
- **Linter**: `ruff` — `make lint`
- **Type hints**: required on all public functions
- **Docstrings**: Google-style on all public classes/functions

## Commit Convention

| Prefix | When to use |
|--------|------------|
| `✨ feat:` | New feature or check |
| `🐛 fix:` | Bug fix |
| `🧪 test:` | Adding/fixing tests |
| `📄 docs:` | Documentation changes |
| `🔄 ci:` | CI/CD changes |
| `🧹 chore:` | Cleanup, formatting |
| `📦 deps:` | Dependency updates |
| `🔒 sec:` | Security fixes |

## Pull Request Checklist

Before submitting, ensure:
- [ ] `make test` passes (all tests green)
- [ ] `make lint` passes (no ruff/black errors)
- [ ] `make scan` passes (no high-severity bandit findings)
- [ ] New public functions have docstrings and type hints
- [ ] README is updated if you added a new feature

## Reporting Bugs

Open a [Bug Report](../../issues/new?template=bug_report.md).

## Suggesting Features

Open a [Feature Request](../../issues/new?template=feature_request.md).

## Security Vulnerabilities

See [SECURITY.md](SECURITY.md).

