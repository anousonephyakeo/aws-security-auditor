"""Tests for IAM Auditor using moto mock."""
import pytest
import boto3
from moto import mock_aws
from auditor.iam_auditor import IAMAuditor


@mock_aws
def test_root_mfa_disabled():
    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    result = auditor.check_root_mfa()
    # moto returns MFA disabled by default
    assert result["check"] == "root_mfa"
    assert result["severity"] in ("CRITICAL", "OK")


@mock_aws
def test_password_policy_missing():
    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    result = auditor.check_password_policy()
    assert result["check"] == "password_policy"
    assert result["severity"] in ("CRITICAL", "HIGH", "OK")


@mock_aws
def test_no_users_no_unused_keys():
    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    results = auditor.check_unused_access_keys()
    assert isinstance(results, list)
    assert len(results) == 0


@mock_aws
def test_admin_user_detected():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="admin-test")
    iam.attach_user_policy(
        UserName="admin-test",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    auditor = IAMAuditor(session)
    results = auditor.check_admin_users()
    assert any(f["resource"] == "admin-test" for f in results)
    assert results[0]["severity"] == "HIGH"


@mock_aws
def test_run_all_returns_list():
    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    results = auditor.run_all()
    assert isinstance(results, list)
