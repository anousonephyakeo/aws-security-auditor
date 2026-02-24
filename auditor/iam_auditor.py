"""IAM Security Auditor — checks for risky IAM configurations."""
import boto3
from typing import List, Dict


class IAMAuditor:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.iam = self.session.client("iam")
        self.findings: List[Dict] = []

    def check_root_mfa(self) -> Dict:
        """Check if root account has MFA enabled."""
        summary = self.iam.get_account_summary()["SummaryMap"]
        enabled = summary.get("AccountMFAEnabled", 0) == 1
        finding = {
            "check": "root_mfa",
            "severity": "CRITICAL" if not enabled else "OK",
            "message": "Root account MFA is DISABLED" if not enabled else "Root MFA enabled",
            "resource": "root",
        }
        self.findings.append(finding)
        return finding

    def check_password_policy(self) -> Dict:
        """Check if a strong password policy is enforced."""
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("min length < 14")
            if not policy.get("RequireSymbols"):
                issues.append("symbols not required")
            if not policy.get("RequireNumbers"):
                issues.append("numbers not required")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("uppercase not required")
            if not policy.get("MaxPasswordAge", 999) <= 90:
                issues.append("max age > 90 days")

            severity = "HIGH" if issues else "OK"
            finding = {
                "check": "password_policy",
                "severity": severity,
                "message": f"Weak policy: {', '.join(issues)}" if issues else "Password policy is strong",
                "resource": "account",
            }
        except self.iam.exceptions.NoSuchEntityException:
            finding = {
                "check": "password_policy",
                "severity": "CRITICAL",
                "message": "No password policy configured",
                "resource": "account",
            }
        self.findings.append(finding)
        return finding

    def check_unused_access_keys(self, days: int = 90) -> List[Dict]:
        """Check for access keys unused for more than N days."""
        from datetime import datetime, timezone, timedelta
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        results = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                keys = self.iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active":
                        last_used = self.iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                        lu = last_used["AccessKeyLastUsed"].get("LastUsedDate")
                        if lu and lu < threshold:
                            finding = {
                                "check": "unused_access_key",
                                "severity": "MEDIUM",
                                "message": f"Key {key['AccessKeyId']} unused for {days}+ days",
                                "resource": user["UserName"],
                            }
                            self.findings.append(finding)
                            results.append(finding)
        return results

    def check_admin_users(self) -> List[Dict]:
        """Check for users with AdministratorAccess policy."""
        results = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                policies = self.iam.list_attached_user_policies(UserName=user["UserName"])
                for policy in policies["AttachedPolicies"]:
                    if policy["PolicyName"] == "AdministratorAccess":
                        finding = {
                            "check": "admin_user",
                            "severity": "HIGH",
                            "message": f"User has AdministratorAccess policy",
                            "resource": user["UserName"],
                        }
                        self.findings.append(finding)
                        results.append(finding)
        return results

    def run_all(self) -> List[Dict]:
        """Run all IAM checks."""
        self.check_root_mfa()
        self.check_password_policy()
        self.check_unused_access_keys()
        self.check_admin_users()
        return self.findings
