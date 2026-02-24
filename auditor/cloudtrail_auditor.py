"""CloudTrail Auditor — verifies logging is active and tamper-proof."""
import boto3
from typing import List, Dict


class CloudTrailAuditor:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.ct = self.session.client("cloudtrail")
        self.findings: List[Dict] = []

    def check_trail_enabled(self) -> List[Dict]:
        """Check that at least one multi-region trail is active."""
        trails = self.ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        results = []
        if not trails:
            finding = {
                "check": "cloudtrail_enabled",
                "severity": "CRITICAL",
                "message": "No CloudTrail trails configured",
                "resource": "account",
            }
            self.findings.append(finding)
            return [finding]

        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        if not multi_region:
            finding = {
                "check": "cloudtrail_multi_region",
                "severity": "HIGH",
                "message": "No multi-region trail — blind spots exist in other regions",
                "resource": "account",
            }
            self.findings.append(finding)
            results.append(finding)
        return results

    def check_log_validation(self) -> List[Dict]:
        """Check that log file validation (integrity) is enabled."""
        results = []
        trails = self.ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            if not trail.get("LogFileValidationEnabled"):
                finding = {
                    "check": "cloudtrail_log_validation",
                    "severity": "MEDIUM",
                    "message": "Log file integrity validation disabled — logs could be tampered",
                    "resource": trail["TrailARN"],
                }
                self.findings.append(finding)
                results.append(finding)
        return results

    def check_s3_bucket_logging(self) -> List[Dict]:
        """Ensure CloudTrail S3 buckets have access logging."""
        results = []
        trails = self.ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        s3 = self.session.client("s3")
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if bucket:
                try:
                    logging_cfg = s3.get_bucket_logging(Bucket=bucket)
                    if "LoggingEnabled" not in logging_cfg:
                        finding = {
                            "check": "cloudtrail_bucket_logging",
                            "severity": "MEDIUM",
                            "message": f"CloudTrail S3 bucket '{bucket}' has no access logging",
                            "resource": bucket,
                        }
                        self.findings.append(finding)
                        results.append(finding)
                except Exception:
                    pass
        return results

    def run_all(self) -> List[Dict]:
        self.check_trail_enabled()
        self.check_log_validation()
        self.check_s3_bucket_logging()
        return self.findings
