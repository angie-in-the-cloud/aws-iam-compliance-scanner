"""
Scanner 1: IAM Password Policy
Evaluates the account-level IAM password policy against
NIST 800-53 IA-5, SOC 2 CC6.6, and ISO 27001 A.9.4.3 requirements.
"""

import boto3
import logging

logger = logging.getLogger()

# Compliance baselines
REQUIRED_POLICY = {
    "MinimumPasswordLength": 14,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "MaxPasswordAge": 90,
    "PasswordReusePrevention": 12,
    "AllowUsersToChangePassword": True,
    "HardExpiry": False,
}

FRAMEWORK_MAPPING = {
    "MinimumPasswordLength":          {"nist": "IA-5(1)(a)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "RequireSymbols":                 {"nist": "IA-5(1)(a)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "RequireNumbers":                 {"nist": "IA-5(1)(a)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "RequireUppercaseCharacters":     {"nist": "IA-5(1)(a)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "RequireLowercaseCharacters":     {"nist": "IA-5(1)(a)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "MaxPasswordAge":                 {"nist": "IA-5(1)(d)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "PasswordReusePrevention":        {"nist": "IA-5(1)(e)", "soc2": "CC6.6", "iso": "A.9.4.3"},
    "AllowUsersToChangePassword":     {"nist": "IA-5",       "soc2": "CC6.6", "iso": "A.9.4.3"},
    "HardExpiry":                     {"nist": "IA-5(1)(d)", "soc2": "CC6.6", "iso": "A.9.4.3"},
}


def scan_password_policy(region: str) -> list:
    """
    Retrieves the IAM account password policy and evaluates each
    control against the compliance baseline.
    Returns a list of finding dicts.
    """
    iam = boto3.client("iam", region_name=region)
    findings = []

    try:
        response = iam.get_account_password_policy()
        policy = response["PasswordPolicy"]
        policy_exists = True
        logger.info("Password policy found — evaluating controls")
    except iam.exceptions.NoSuchEntityException:
        policy = {}
        policy_exists = False
        logger.warning("No IAM password policy configured — all controls flagged NON_COMPLIANT")

    for control, required_value in REQUIRED_POLICY.items():
        mapping = FRAMEWORK_MAPPING.get(control, {})

        if not policy_exists:
            status = "NON_COMPLIANT"
            actual_value = "No policy configured"
            remediation = "Create an IAM account password policy via the AWS Console or CLI"
        else:
            actual_value = policy.get(control, "Not set")
            status = _evaluate_control(control, actual_value, required_value)
            remediation = _get_remediation(control, required_value) if status == "NON_COMPLIANT" else "No action required"

        findings.append({
            "scanner":      "PasswordPolicy",
            "control":      control,
            "status":       status,
            "actual_value": str(actual_value),
            "required_value": str(required_value),
            "nist_control": mapping.get("nist", ""),
            "soc2_control": mapping.get("soc2", ""),
            "iso_control":  mapping.get("iso", ""),
            "remediation":  remediation,
        })

    return findings


def _evaluate_control(control: str, actual, required) -> str:
    """Returns COMPLIANT or NON_COMPLIANT for a single control."""
    if actual == "Not set" or actual is None:
        return "NON_COMPLIANT"

    # For numeric controls, check >= threshold (or <= for MaxPasswordAge)
    if control == "MaxPasswordAge":
        return "COMPLIANT" if isinstance(actual, int) and actual <= required else "NON_COMPLIANT"
    if control == "MinimumPasswordLength":
        return "COMPLIANT" if isinstance(actual, int) and actual >= required else "NON_COMPLIANT"
    if control == "PasswordReusePrevention":
        return "COMPLIANT" if isinstance(actual, int) and actual >= required else "NON_COMPLIANT"
    if control == "HardExpiry":
        return "COMPLIANT" if actual == required else "NON_COMPLIANT"

    # Boolean controls
    return "COMPLIANT" if actual == required else "NON_COMPLIANT"


def _get_remediation(control: str, required_value) -> str:
    remediation_map = {
        "MinimumPasswordLength":      f"Set minimum password length to at least {required_value} characters",
        "RequireSymbols":             "Enable 'Require at least one non-alphanumeric character'",
        "RequireNumbers":             "Enable 'Require at least one number'",
        "RequireUppercaseCharacters": "Enable 'Require at least one uppercase letter'",
        "RequireLowercaseCharacters": "Enable 'Require at least one lowercase letter'",
        "MaxPasswordAge":             f"Set password expiration to {required_value} days or fewer",
        "PasswordReusePrevention":    f"Prevent reuse of the last {required_value} passwords",
        "AllowUsersToChangePassword": "Allow users to change their own passwords",
        "HardExpiry":                 "Disable hard expiry to prevent account lockout on expiration",
    }
    return remediation_map.get(control, "Review and update the password policy")
