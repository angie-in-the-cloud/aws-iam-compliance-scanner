"""
aws-iam-compliance-snapshot
Lambda handler — orchestrates all 3 IAM compliance scanners,
builds a unified report, and uploads it to S3.
"""

import json
import csv
import io
import os
import boto3
import logging
from datetime import datetime, timezone

from scanners.password_policy import scan_password_policy
from scanners.mfa_enforcement import scan_mfa_enforcement
from scanners.root_activity import scan_root_activity
from reporters.evidence_writer import build_report, upload_to_s3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """
    Entry point for the Lambda function.
    Runs all 3 scanners, builds a compliance report, and saves it to S3.
    """
    logger.info("Starting IAM Compliance Snapshot")

    s3_bucket = os.environ.get("S3_BUCKET_NAME")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")

    if not s3_bucket:
        raise ValueError("S3_BUCKET_NAME environment variable is not set")

    # Run all 3 scanners
    findings = []
    findings += scan_password_policy(aws_region)
    findings += scan_mfa_enforcement(aws_region)
    findings += scan_root_activity(aws_region)

    logger.info(f"Total findings collected: {len(findings)}")

    # Build and upload report
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_key = f"reports/iam_compliance_snapshot_{timestamp}"

    upload_to_s3(findings, s3_bucket, report_key, aws_region)

    compliant = sum(1 for f in findings if f["status"] == "COMPLIANT")
    non_compliant = sum(1 for f in findings if f["status"] == "NON_COMPLIANT")

    logger.info(f"Snapshot complete — Compliant: {compliant} | Non-Compliant: {non_compliant}")

    return {
        "statusCode": 200,
        "message": "IAM Compliance Snapshot complete",
        "bucket": s3_bucket,
        "report_prefix": report_key,
        "findings_count": len(findings),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "timestamp": timestamp
    }
