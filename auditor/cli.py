"""CLI entrypoint for AWS Security Auditor."""
import argparse
import sys
import boto3
from .iam_auditor import IAMAuditor
from .s3_auditor import S3Auditor
from .ec2_auditor import EC2Auditor
from .cloudtrail_auditor import CloudTrailAuditor
from .reporter import Reporter


def build_session(profile: str = None, region: str = "us-east-1") -> boto3.Session:
    kwargs = {"region_name": region}
    if profile:
        kwargs["profile_name"] = profile
    return boto3.Session(**kwargs)


def main():
    parser = argparse.ArgumentParser(
        description="🔐 AWS Security Auditor — by SW1ZX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--checks", nargs="+",
                        choices=["iam", "s3", "ec2", "cloudtrail", "all"],
                        default=["all"], help="Which checks to run")
    parser.add_argument("--output", choices=["terminal", "json", "markdown"], default="terminal")
    parser.add_argument("--report-file", help="Output file path for json/markdown reports")
    args = parser.parse_args()

    print("🔐 AWS Security Auditor starting...")
    session = build_session(args.profile, args.region)
    all_findings = []
    run_all = "all" in args.checks

    if run_all or "iam" in args.checks:
        print("  → Running IAM checks...")
        all_findings.extend(IAMAuditor(session).run_all())
    if run_all or "s3" in args.checks:
        print("  → Running S3 checks...")
        all_findings.extend(S3Auditor(session).run_all())
    if run_all or "ec2" in args.checks:
        print("  → Running EC2 checks...")
        all_findings.extend(EC2Auditor(session).run_all())
    if run_all or "cloudtrail" in args.checks:
        print("  → Running CloudTrail checks...")
        all_findings.extend(CloudTrailAuditor(session).run_all())

    reporter = Reporter(all_findings)
    if args.output == "json":
        print(reporter.to_json(args.report_file))
    elif args.output == "markdown":
        print(reporter.to_markdown(args.report_file))
    else:
        reporter.print_terminal()

    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    sys.exit(1 if critical > 0 else 0)


if __name__ == "__main__":
    main()
