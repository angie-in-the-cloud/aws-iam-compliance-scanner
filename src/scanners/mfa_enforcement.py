"""
Scanner 2: MFA Enforcement
Checks whether MFA is enabled for all IAM users that have
console access (login profiles). Maps to NIST 800-53 IA-2(1),
SOC 2 CC6.1, and ISO 27001 A.9.4.2.
"""

import boto3
import logging

logger = logging.getLogger()

FRAMEWORK_MAPPING = {
    "nist": "IA-2(1)",
    "soc2": "CC6.1",
    "iso":  "A.9.4.2",
}


def scan_mfa_enforcement(region: str) -> list:
    """
    Lists all IAM users with console access and checks whether
    each has MFA enabled. Returns a finding per user.
    """
    iam = boto3.client("iam", region_name=region)
    findings = []

    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page["Users"])

    logger.info(f"MFA scan — evaluating {len(users)} IAM users")

    for user in users:
        username = user["UserName"]

        # Only check users with console access (login profile)
        has_console_access = _has_login_profile(iam, username)
        if not has_console_access:
            continue

        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        mfa_enabled = len(mfa_devices) > 0
        status = "COMPLIANT" if mfa_enabled else "NON_COMPLIANT"

        findings.append({
            "scanner":        "MFAEnforcement",
            "control":        f"MFA enabled for {username}",
            "status":         status,
            "actual_value":   "MFA enabled" if mfa_enabled else "No MFA device",
            "required_value": "MFA device required for console users",
            "nist_control":   FRAMEWORK_MAPPING["nist"],
            "soc2_control":   FRAMEWORK_MAPPING["soc2"],
            "iso_control":    FRAMEWORK_MAPPING["iso"],
            "remediation":    "No action required" if mfa_enabled
                              else f"Enable MFA for IAM user '{username}' via the AWS Console or CLI",
        })

    if not findings:
        logger.info("No console-enabled IAM users found — no MFA findings generated")

    return findings


def _has_login_profile(iam_client, username: str) -> bool:
    """Returns True if the user has a console login profile (password-based access)."""
    try:
        iam_client.get_login_profile(UserName=username)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False
