"""Tests for S3 Auditor using moto mock."""
import pytest
import boto3
from moto import mock_aws
from auditor.s3_auditor import S3Auditor


@mock_aws
def test_no_buckets_no_findings():
    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session)
    results = auditor.run_all()
    assert isinstance(results, list)
    assert len(results) == 0


@mock_aws
def test_bucket_logging_missing():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-bucket-unprotected")
    auditor = S3Auditor(session)
    results = auditor.check_logging()
    assert any(f["resource"] == "test-bucket-unprotected" for f in results)


@mock_aws
def test_bucket_versioning_missing():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="test-no-versioning")
    auditor = S3Auditor(session)
    results = auditor.check_versioning()
    assert any(f["resource"] == "test-no-versioning" for f in results)
    assert results[0]["severity"] == "LOW"


@mock_aws
def test_run_all_returns_list():
    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session)
    results = auditor.run_all()
    assert isinstance(results, list)
