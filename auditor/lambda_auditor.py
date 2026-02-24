"""Lambda Security Auditor — checks for overly permissive roles and public functions."""
import boto3
from typing import List, Dict


class LambdaAuditor:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.lmb = self.session.client("lambda")
        self.iam = self.session.client("iam")
        self.findings: List[Dict] = []

    def check_public_functions(self) -> List[Dict]:
        """Check for Lambda functions with resource-based policies allowing public access."""
        results = []
        paginator = self.lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                name = fn["FunctionName"]
                try:
                    policy = self.lmb.get_policy(FunctionName=name)
                    import json
                    doc = json.loads(policy["Policy"])
                    for stmt in doc.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        if principal == "*" or principal.get("AWS") == "*":
                            finding = {
                                "check": "lambda_public_access",
                                "severity": "CRITICAL",
                                "message": "Function allows public invocation via resource policy",
                                "resource": name,
                            }
                            self.findings.append(finding)
                            results.append(finding)
                except Exception:
                    pass
        return results

    def check_environment_secrets(self) -> List[Dict]:
        """Flag Lambda functions with suspicious environment variable names."""
        SENSITIVE_KEYS = ["password", "secret", "key", "token", "api_key", "credential", "passwd"]
        results = []
        paginator = self.lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                env_vars = fn.get("Environment", {}).get("Variables", {})
                for var_name in env_vars:
                    if any(s in var_name.lower() for s in SENSITIVE_KEYS):
                        finding = {
                            "check": "lambda_env_secret",
                            "severity": "HIGH",
                            "message": f"Sensitive var '{var_name}' in plaintext env — use AWS Secrets Manager",
                            "resource": fn["FunctionName"],
                        }
                        self.findings.append(finding)
                        results.append(finding)
        return results

    def check_outdated_runtimes(self) -> List[Dict]:
        """Flag functions using deprecated or EOL runtimes."""
        DEPRECATED = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x",
                      "ruby2.5", "dotnetcore2.1", "dotnetcore3.1", "java8"]
        results = []
        paginator = self.lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                runtime = fn.get("Runtime", "")
                if runtime in DEPRECATED:
                    finding = {
                        "check": "lambda_deprecated_runtime",
                        "severity": "MEDIUM",
                        "message": f"EOL runtime '{runtime}' — upgrade to a supported version",
                        "resource": fn["FunctionName"],
                    }
                    self.findings.append(finding)
                    results.append(finding)
        return results

    def run_all(self) -> List[Dict]:
        self.check_public_functions()
        self.check_environment_secrets()
        self.check_outdated_runtimes()
        return self.findings
