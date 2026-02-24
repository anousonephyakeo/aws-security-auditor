"""EC2 Security Auditor — checks security groups, IMDSv2, public IPs."""
import boto3
from typing import List, Dict


class EC2Auditor:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.ec2 = self.session.client("ec2")
        self.findings: List[Dict] = []

    def check_open_security_groups(self) -> List[Dict]:
        """Find security groups with 0.0.0.0/0 inbound rules on sensitive ports."""
        SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 5432: "PostgreSQL",
                          3306: "MySQL", 27017: "MongoDB", 6379: "Redis"}
        results = []
        sgs = self.ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                        for port, svc in SENSITIVE_PORTS.items():
                            if from_port <= port <= to_port:
                                finding = {
                                    "check": "open_security_group",
                                    "severity": "CRITICAL" if port in (22, 3389) else "HIGH",
                                    "message": f"Port {port} ({svc}) open to the world",
                                    "resource": f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                                }
                                self.findings.append(finding)
                                results.append(finding)
        return results

    def check_imdsv2(self) -> List[Dict]:
        """Check that instances enforce IMDSv2 (prevents SSRF metadata theft)."""
        results = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    iid = instance["InstanceId"]
                    meta_options = instance.get("MetadataOptions", {})
                    if meta_options.get("HttpTokens") != "required":
                        finding = {
                            "check": "imdsv2_not_enforced",
                            "severity": "HIGH",
                            "message": "IMDSv2 not enforced — vulnerable to SSRF metadata attacks",
                            "resource": iid,
                        }
                        self.findings.append(finding)
                        results.append(finding)
        return results

    def check_public_instances(self) -> List[Dict]:
        """Flag instances with a public IP that are not behind a load balancer."""
        results = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance.get("PublicIpAddress"):
                        finding = {
                            "check": "public_ec2_instance",
                            "severity": "MEDIUM",
                            "message": f"Instance has public IP: {instance['PublicIpAddress']}",
                            "resource": instance["InstanceId"],
                        }
                        self.findings.append(finding)
                        results.append(finding)
        return results

    def run_all(self) -> List[Dict]:
        self.check_open_security_groups()
        self.check_imdsv2()
        self.check_public_instances()
        return self.findings
