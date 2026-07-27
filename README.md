# AWS S3 Bucket Security Checker

A Python tool that scans S3 buckets for the misconfigurations behind most public-S3-bucket data breaches: disabled Public Access Block settings, open ACLs, missing default encryption, and disabled versioning.

## Why this exists

Misconfigured S3 buckets are one of the most common and highest-impact cloud security incidents (Capital One, numerous government contractor leaks, etc.). This tool automates the checklist a cloud security engineer would run manually against every bucket in an account.

## Features
- Checks Public Access Block configuration (all 4 settings)
- Flags ACL grants to `AllUsers` / `AuthenticatedUsers`
- Flags missing default server-side encryption
- Flags disabled versioning
- Works against a live AWS account via `boto3`, or in `--demo` mode with no AWS credentials required
- Optional JSON report export

## Usage

```bash
pip install -r requirements.txt

# Run against sample data (no AWS account needed)
python s3_checker.py --demo

# Run against your live AWS account
python s3_checker.py

# Export findings to JSON
python s3_checker.py --demo --output report.json
```

## Sample output

```
S3 Bucket Security Audit — 2026-07-24T15:27:41+00:00
============================================================
Buckets scanned: 3   Total findings: 5

Bucket: company-public-assets
  [CRITICAL] Public Access Block is not fully enabled
  [CRITICAL] ACL grants public access: AllUsers:READ
  [HIGH    ] No default server-side encryption configured
  [MEDIUM  ] Versioning is not enabled (reduces ransomware/accidental-delete resilience)

Bucket: company-app-logs
  OK — no issues found

Bucket: company-db-backups
  [HIGH    ] No default server-side encryption configured
```

## Requirements
- Python 3.9+
- `boto3` (only needed for live AWS scans; demo mode has no dependency)

## Notes
This is a read-only auditing tool — it never modifies bucket settings. It's meant as a starting point for a manual cloud security review, not a replacement for AWS Security Hub or a full configuration audit.
