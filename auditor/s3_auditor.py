"""S3 Security Auditor — checks for public buckets, encryption, logging."""
import boto3
from typing import List, Dict


class S3Auditor:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.s3 = self.session.client("s3")
        self.findings: List[Dict] = []

    def _list_buckets(self) -> List[str]:
        return [b["Name"] for b in self.s3.list_buckets().get("Buckets", [])]

    def check_public_access_blocks(self) -> List[Dict]:
        """Ensure all buckets have public access blocked."""
        results = []
        for bucket in self._list_buckets():
            try:
                config = self.s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                issues = [k for k, v in config.items() if not v]
                if issues:
                    finding = {
                        "check": "s3_public_access",
                        "severity": "CRITICAL",
                        "message": f"Public access not fully blocked: {issues}",
                        "resource": bucket,
                    }
                    self.findings.append(finding)
                    results.append(finding)
            except Exception:
                finding = {
                    "check": "s3_public_access",
                    "severity": "CRITICAL",
                    "message": "No public access block configuration found",
                    "resource": bucket,
                }
                self.findings.append(finding)
                results.append(finding)
        return results

    def check_encryption(self) -> List[Dict]:
        """Check if server-side encryption is enabled on all buckets."""
        results = []
        for bucket in self._list_buckets():
            try:
                self.s3.get_bucket_encryption(Bucket=bucket)
            except self.s3.exceptions.ClientError:
                finding = {
                    "check": "s3_encryption",
                    "severity": "HIGH",
                    "message": "Bucket encryption not configured",
                    "resource": bucket,
                }
                self.findings.append(finding)
                results.append(finding)
        return results

    def check_logging(self) -> List[Dict]:
        """Check if access logging is enabled."""
        results = []
        for bucket in self._list_buckets():
            logging_cfg = self.s3.get_bucket_logging(Bucket=bucket)
            if "LoggingEnabled" not in logging_cfg:
                finding = {
                    "check": "s3_logging",
                    "severity": "MEDIUM",
                    "message": "Access logging not enabled",
                    "resource": bucket,
                }
                self.findings.append(finding)
                results.append(finding)
        return results

    def check_versioning(self) -> List[Dict]:
        """Check if versioning is enabled (data protection)."""
        results = []
        for bucket in self._list_buckets():
            vers = self.s3.get_bucket_versioning(Bucket=bucket)
            if vers.get("Status") != "Enabled":
                finding = {
                    "check": "s3_versioning",
                    "severity": "LOW",
                    "message": "Versioning not enabled",
                    "resource": bucket,
                }
                self.findings.append(finding)
                results.append(finding)
        return results

    def run_all(self) -> List[Dict]:
        self.check_public_access_blocks()
        self.check_encryption()
        self.check_logging()
        self.check_versioning()
        return self.findings
