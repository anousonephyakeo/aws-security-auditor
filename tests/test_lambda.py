"""Tests for Lambda Auditor using moto mock."""
import pytest
import boto3
from moto import mock_aws
from auditor.lambda_auditor import LambdaAuditor


@mock_aws
def test_no_functions_no_findings():
    session = boto3.Session(region_name="us-east-1")
    auditor = LambdaAuditor(session)
    results = auditor.run_all()
    assert isinstance(results, list)
    assert len(results) == 0


@mock_aws
def test_deprecated_runtime_flagged():
    session = boto3.Session(region_name="us-east-1")
    lmb = session.client("lambda")
    iam = session.client("iam")
    role = iam.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    lmb.create_function(
        FunctionName="old-function",
        Runtime="python3.6",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"ZipFile"},
    )
    auditor = LambdaAuditor(session)
    results = auditor.check_outdated_runtimes()
    assert any(f["resource"] == "old-function" for f in results)
    assert results[0]["severity"] == "MEDIUM"


@mock_aws
def test_env_secret_flagged():
    session = boto3.Session(region_name="us-east-1")
    lmb = session.client("lambda")
    iam = session.client("iam")
    role = iam.create_role(
        RoleName="lambda-role2",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    lmb.create_function(
        FunctionName="secrets-function",
        Runtime="python3.12",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"ZipFile"},
        Environment={"Variables": {"DB_PASSWORD": "hunter2", "API_KEY": "abc123"}},
    )
    auditor = LambdaAuditor(session)
    results = auditor.check_environment_secrets()
    assert len(results) >= 2
    assert all(f["severity"] == "HIGH" for f in results)
