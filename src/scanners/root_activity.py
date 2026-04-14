"""
Scanner 3: Root Account Activity
Checks CloudTrail for root account usage in the last 90 days.
Root account usage is a high-risk indicator and should be flagged
regardless of the reason. Maps to NIST 800-53 AC-2(5),
SOC 2 CC6.2, and ISO 27001 A.9.2.3.
"""

import boto3
import logging
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()

LOOKBACK_DAYS = 30

FRAMEWORK_MAPPING = {
    "nist": "AC-2(5)",
    "soc2": "CC6.2",
    "iso":  "A.9.2.3",
}


def scan_root_activity(region: str) -> list:
    """
    Searches CloudTrail for any events where the principal
    was the root account in the last 90 days.
    Returns a single finding summarizing root activity status.
    """
    cloudtrail = boto3.client("cloudtrail", region_name=region)
    findings = []

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=LOOKBACK_DAYS)

    logger.info(f"Root activity scan — checking CloudTrail from {start_time.date()} to {end_time.date()}")

    root_events = []

    try:
        paginator = cloudtrail.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "Username", "AttributeValue": "root"}
            ],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": 50, "PageSize": 50}
        )

        for page in pages:
            root_events.extend(page.get("Events", []))
            time.sleep(1)  # Throttle to avoid API limits

    except Exception as e:
        logger.error(f"CloudTrail lookup failed: {e}")
        findings.append({
            "scanner":        "RootActivity",
            "control":        "Root account activity check",
            "status":         "ERROR",
            "actual_value":   f"CloudTrail lookup failed: {str(e)}",
            "required_value": "No root account activity in last 90 days",
            "nist_control":   FRAMEWORK_MAPPING["nist"],
            "soc2_control":   FRAMEWORK_MAPPING["soc2"],
            "iso_control":    FRAMEWORK_MAPPING["iso"],
            "remediation":    "Verify CloudTrail is enabled and the Lambda role has cloudtrail:LookupEvents permission",
        })
        return findings

    event_count = len(root_events)
    status = "NON_COMPLIANT" if event_count > 0 else "COMPLIANT"

    most_recent = None
    if root_events:
        most_recent = max(e["EventTime"] for e in root_events).strftime("%Y-%m-%d %H:%M:%S UTC")

    findings.append({
        "scanner":        "RootActivity",
        "control":        "Root account activity (last 90 days)",
        "status":         status,
        "actual_value":   f"{event_count} root event(s) detected" + (f" — most recent: {most_recent}" if most_recent else ""),
        "required_value": "0 root account events in last 90 days",
        "nist_control":   FRAMEWORK_MAPPING["nist"],
        "soc2_control":   FRAMEWORK_MAPPING["soc2"],
        "iso_control":    FRAMEWORK_MAPPING["iso"],
        "remediation":    "No action required" if status == "COMPLIANT"
                          else "Investigate root account usage. Use IAM roles instead of root for all operations. Enable root account MFA if not already set.",
    })

    logger.info(f"Root activity scan complete — {event_count} event(s) found")
    return findings