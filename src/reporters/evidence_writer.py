"""
Evidence Writer
Builds JSON and CSV compliance reports from scanner findings
and uploads both to S3.
"""

import json
import csv
import io
import boto3
import logging
from datetime import datetime, timezone

logger = logging.getLogger()

FIELDNAMES = [
    "scanner",
    "control",
    "status",
    "actual_value",
    "required_value",
    "nist_control",
    "soc2_control",
    "iso_control",
    "remediation",
]


def build_report(findings: list) -> dict:
    """
    Wraps findings in a structured report envelope with
    summary statistics and metadata.
    """
    total = len(findings)
    compliant = sum(1 for f in findings if f["status"] == "COMPLIANT")
    non_compliant = sum(1 for f in findings if f["status"] == "NON_COMPLIANT")
    errors = sum(1 for f in findings if f["status"] == "ERROR")

    compliance_score = round((compliant / total) * 100, 1) if total > 0 else 0

    return {
        "report_metadata": {
            "tool":           "aws-iam-compliance-snapshot",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "frameworks":     ["NIST 800-53", "SOC 2", "ISO 27001"],
            "scanners_run":   ["PasswordPolicy", "MFAEnforcement", "RootActivity"],
        },
        "summary": {
            "total_controls":  total,
            "compliant":       compliant,
            "non_compliant":   non_compliant,
            "errors":          errors,
            "compliance_score": f"{compliance_score}%",
            "overall_status":  "COMPLIANT" if non_compliant == 0 and errors == 0 else "NON_COMPLIANT",
        },
        "findings": findings,
    }


def upload_to_s3(findings: list, bucket: str, key_prefix: str, region: str):
    """
    Uploads JSON and CSV reports to S3.
    JSON is for automation and audit trails.
    CSV is for human review and stakeholder reporting.
    """
    s3 = boto3.client("s3", region_name=region)
    report = build_report(findings)

    # --- Upload JSON ---
    json_key = f"{key_prefix}.json"
    json_body = json.dumps(report, indent=2, default=str)
    s3.put_object(
        Bucket=bucket,
        Key=json_key,
        Body=json_body.encode("utf-8"),
        ContentType="application/json",
    )
    logger.info(f"JSON report uploaded: s3://{bucket}/{json_key}")

    # --- Upload CSV ---
    csv_key = f"{key_prefix}.csv"
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=FIELDNAMES, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(findings)

    s3.put_object(
        Bucket=bucket,
        Key=csv_key,
        Body=csv_buffer.getvalue().encode("utf-8"),
        ContentType="text/csv",
    )
    logger.info(f"CSV report uploaded: s3://{bucket}/{csv_key}")
