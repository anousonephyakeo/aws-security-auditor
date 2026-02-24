.PHONY: install test lint fmt scan coverage all clean

PYTHON  := python
PYTEST  := pytest
MODULE  := auditor
VENV    := .venv

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[dev]"
	@echo "✅ Dev environment ready — activate with: source $(VENV)/bin/activate"

test:
	$(PYTEST) tests/ -v --tb=short
	@echo "✅ Tests passed"

lint:
	ruff check $(MODULE)/ tests/
	black --check $(MODULE)/ tests/
	@echo "✅ Lint passed"

fmt:
	black $(MODULE)/ tests/
	ruff check --fix $(MODULE)/ tests/
	@echo "✅ Formatted"

scan:
	bandit -r $(MODULE)/ -ll -q
	safety check -r requirements.txt --continue-on-error
	@echo "✅ Security scan complete"

coverage:
	$(PYTEST) tests/ --cov=$(MODULE) --cov-report=term-missing --cov-report=html
	@echo "✅ Coverage report in htmlcov/"

all: install lint test scan
	@echo "🎉 All checks passed!"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage coverage.xml dist build *.egg-info
	@echo "🧹 Cleaned"
