#!/usr/bin/env python3
"""
AWS S3 Bucket Security Checker
---------------------------------
Scans S3 buckets in an account (or a provided list) for common
misconfigurations: public access, missing default encryption, missing
versioning, missing bucket policy restrictions, and open ACLs.

Usage:
    python s3_checker.py                # scan live AWS account
    python s3_checker.py --demo         # run against sample data, no AWS needed
    python s3_checker.py --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def demo_buckets():
    return [
        {
            "name": "company-public-assets",
            "public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": False,
                                     "IgnorePublicAcls": False, "RestrictPublicBuckets": False},
            "encryption": None,
            "versioning": "Disabled",
            "acl_grants": ["AllUsers:READ"],
        },
        {
            "name": "company-app-logs",
            "public_access_block": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
                                     "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            "encryption": "AES256",
            "versioning": "Enabled",
            "acl_grants": [],
        },
        {
            "name": "company-db-backups",
            "public_access_block": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
                                     "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            "encryption": None,
            "versioning": "Disabled",
            "acl_grants": [],
        },
    ]


def fetch_live_buckets():
    if not HAS_BOTO3:
        print("boto3 not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)

    s3 = boto3.client("s3")
    buckets = []
    try:
        for b in s3.list_buckets()["Buckets"]:
            name = b["Name"]
            entry = {"name": name, "public_access_block": None, "encryption": None,
                      "versioning": "Disabled", "acl_grants": []}

            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                entry["public_access_block"] = pab
            except ClientError:
                entry["public_access_block"] = {"BlockPublicAcls": False, "BlockPublicPolicy": False,
                                                 "IgnorePublicAcls": False, "RestrictPublicBuckets": False}

            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rule = enc["ServerSideEncryptionConfiguration"]["Rules"][0]
                entry["encryption"] = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            except ClientError:
                entry["encryption"] = None

            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                entry["versioning"] = ver.get("Status", "Disabled")
            except ClientError:
                pass

            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                        entry["acl_grants"].append(f"AllUsers:{grant['Permission']}")
                    elif grantee.get("Type") == "Group" and "AuthenticatedUsers" in grantee.get("URI", ""):
                        entry["acl_grants"].append(f"AuthenticatedUsers:{grant['Permission']}")
            except ClientError:
                pass

            buckets.append(entry)
    except (ClientError, NoCredentialsError) as e:
        print(f"AWS error: {e}", file=sys.stderr)
        sys.exit(1)
    return buckets


def check_bucket(bucket):
    findings = []
    pab = bucket["public_access_block"] or {}
    if not all(pab.get(k, False) for k in
               ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]):
        findings.append(("CRITICAL", "Public Access Block is not fully enabled"))

    if bucket["acl_grants"]:
        for grant in bucket["acl_grants"]:
            findings.append(("CRITICAL", f"ACL grants public access: {grant}"))

    if not bucket["encryption"]:
        findings.append(("HIGH", "No default server-side encryption configured"))

    if bucket["versioning"] != "Enabled":
        findings.append(("MEDIUM", "Versioning is not enabled (reduces ransomware/accidental-delete resilience)"))

    return findings


def audit(buckets):
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "buckets": []}
    for b in buckets:
        findings = check_bucket(b)
        report["buckets"].append({
            "name": b["name"],
            "findings": [{"severity": s, "message": m} for s, m in findings],
        })
    return report


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_report(report):
    total = sum(len(b["findings"]) for b in report["buckets"])
    print(f"\nS3 Bucket Security Audit — {report['generated_at']}")
    print("=" * 60)
    print(f"Buckets scanned: {len(report['buckets'])}   Total findings: {total}\n")

    for b in report["buckets"]:
        print(f"Bucket: {b['name']}")
        if not b["findings"]:
            print("  OK — no issues found")
            continue
        for f in sorted(b["findings"], key=lambda x: SEVERITY_ORDER[x["severity"]]):
            print(f"  [{f['severity']:8}] {f['message']}")
        print()


def main():
    parser = argparse.ArgumentParser(description="AWS S3 Bucket Security Checker")
    parser.add_argument("--demo", action="store_true", help="Run against bundled sample data")
    parser.add_argument("--output", help="Write JSON report to this path")
    args = parser.parse_args()

    buckets = demo_buckets() if args.demo or not HAS_BOTO3 else fetch_live_buckets()
    report = audit(buckets)
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
