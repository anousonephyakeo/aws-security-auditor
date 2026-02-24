"""Tests for Reporter module."""
import json
import pytest
from auditor.reporter import Reporter


SAMPLE_FINDINGS = [
    {"check": "root_mfa", "severity": "CRITICAL", "message": "Root MFA disabled", "resource": "root"},
    {"check": "s3_logging", "severity": "MEDIUM", "message": "No logging", "resource": "my-bucket"},
    {"check": "imdsv2", "severity": "HIGH", "message": "IMDSv2 not enforced", "resource": "i-12345"},
    {"check": "password_policy", "severity": "OK", "message": "Strong policy", "resource": "account"},
]


def test_reporter_sorts_by_severity():
    reporter = Reporter(SAMPLE_FINDINGS)
    severities = [f["severity"] for f in reporter.findings]
    assert severities[0] == "CRITICAL"
    assert severities[-1] == "OK"


def test_reporter_to_json():
    reporter = Reporter(SAMPLE_FINDINGS)
    output = reporter.to_json()
    data = json.loads(output)
    assert "findings" in data
    assert data["total"] == 4


def test_reporter_to_markdown():
    reporter = Reporter(SAMPLE_FINDINGS)
    output = reporter.to_markdown()
    assert "| Severity |" in output
    assert "CRITICAL" in output
    assert "root_mfa" in output


def test_reporter_empty_findings():
    reporter = Reporter([])
    output = reporter.to_json()
    data = json.loads(output)
    assert data["total"] == 0


def test_reporter_print_terminal(capsys):
    reporter = Reporter(SAMPLE_FINDINGS)
    reporter.print_terminal()
    captured = capsys.readouterr()
    assert "AWS Security Auditor" in captured.out
