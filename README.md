# AWS IAM Compliance Snapshot

Automated IAM compliance scanner that checks three security controls in one run and produces audit-ready evidence mapped to NIST 800-53, SOC 2, and ISO 27001.

---

## What this project does

Most compliance teams check IAM controls manually — logging into the console, reviewing settings one by one, and copying findings into a spreadsheet. This project automates that entire process.

A Lambda function runs on a schedule, scans three IAM controls, and uploads JSON and CSV compliance reports directly to S3. No manual steps. No console access required after deployment.

---

## The three controls it checks

| Scanner | What it checks | Why it matters |
|---|---|---|
| **Password Policy** | Evaluates 9 IAM password settings against hardened baselines | Weak password policies are one of the most common audit findings |
| **MFA Enforcement** | Checks every console user for an active MFA device | Accounts without MFA are a leading cause of cloud breaches |
| **Root Account Activity** | Searches CloudTrail for root login events in the last 30 days | Root usage bypasses all IAM controls — it should never appear in logs |

---

## Compliance framework mapping

Every finding is mapped to the relevant control in each framework.

| Control Area | NIST 800-53 | SOC 2 | ISO 27001 |
|---|---|---|---|
| Password complexity & rotation | IA-5(1) | CC6.6 | A.9.4.3 |
| MFA for console access | IA-2(1) | CC6.1 | A.9.4.2 |
| Root account restrictions | AC-2(5) | CC6.2 | A.9.2.3 |

---

## Architecture

```
EventBridge (schedule)
        ↓
   Lambda Function
        ↓
  ┌─────────────────────────────┐
  │  Scanner 1: Password Policy │  → IAM API
  │  Scanner 2: MFA Enforcement │  → IAM API
  │  Scanner 3: Root Activity   │  → CloudTrail API
  └─────────────────────────────┘
        ↓
   S3 Bucket
   ├── report.json  (automation + audit trail)
   └── report.csv   (human review + stakeholder reporting)
```

---

## Prerequisites

Before you start, make sure you have:

- An AWS account
- AWS CLI installed and configured (`aws configure sso` or `aws configure`)
- Python 3.12 or higher
- Your AWS profile name ready (you will use it in the deployment steps)

---

## Deployment

### Step 1 — Clone the repo

```bash
git clone https://github.com/angie-in-the-cloud/aws-iam-compliance-snapshot.git
cd aws-iam-compliance-snapshot
```

### Step 2 — Package the Lambda source code

The Lambda function runs from a ZIP file. Package it like this:

```bash
cd src
zip -r ../lambda-source.zip .
cd ..
```

### Step 3 — Create your S3 bucket

This bucket stores your compliance reports. Bucket names must be globally unique — replace the name below with your own.

```bash
aws s3 mb s3://your-iam-snapshot-bucket --region us-east-1 --profile your-profile-name
```

### Step 4 — Upload the Lambda ZIP to S3

```bash
aws s3 cp lambda-source.zip s3://your-iam-snapshot-bucket/source/lambda-source.zip --profile your-profile-name
```

### Step 5 — Deploy the CloudFormation stack

```bash
aws cloudformation deploy \
  --stack-name iam-compliance-snapshot \
  --template-file templates/cloudformation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides S3BucketName=your-iam-snapshot-bucket \
  --region us-east-1 \
  --profile your-profile-name
```

You should see this in your terminal when it completes:

```
Successfully created/updated stack - iam-compliance-snapshot
```

### Step 6 — Update the Lambda with your source code

CloudFormation deploys a placeholder Lambda. Replace it with your actual code:

```bash
aws lambda update-function-code \
  --function-name iam-compliance-snapshot \
  --s3-bucket your-iam-snapshot-bucket \
  --s3-key source/lambda-source.zip \
  --region us-east-1 \
  --profile your-profile-name
```

### Step 7 — Run the snapshot manually

Test it before waiting for the schedule to trigger it:

```bash
aws lambda invoke \
  --function-name iam-compliance-snapshot \
  --region us-east-1 \
  --profile your-profile-name \
  --cli-read-timeout 300 \
  response.json
```

Check `response.json` for the output summary. A successful run looks like:

```json
{
  "statusCode": 200,
  "message": "IAM Compliance Snapshot complete",
  "findings_count": 15,
  "compliant": 6,
  "non_compliant": 9
}
```

### Step 8 — Check S3 for your reports

```bash
aws s3 ls s3://your-iam-snapshot-bucket/reports/ --profile your-profile-name
```

Download the CSV to review findings:

```bash
aws s3 cp s3://your-iam-snapshot-bucket/reports/iam_compliance_snapshot_<timestamp>.csv . --profile your-profile-name
```

---

## Report output

After the Lambda runs, two files appear in your S3 bucket.

**JSON report** — structured data for automation and audit trails

```json
{
  "report_metadata": {
    "tool": "aws-iam-compliance-snapshot",
    "generated_at": "2026-04-14T00:00:00+00:00",
    "frameworks": ["NIST 800-53", "SOC 2", "ISO 27001"]
  },
  "summary": {
    "total_controls": 15,
    "compliant": 6,
    "non_compliant": 9,
    "compliance_score": "40.0%",
    "overall_status": "NON_COMPLIANT"
  },
  "findings": [...]
}
```

**CSV report** — one row per control, ready for review or import into a GRC tool

| scanner | control | status | actual_value | required_value | nist_control | soc2_control | iso_control | remediation |
|---|---|---|---|---|---|---|---|---|
| PasswordPolicy | MinimumPasswordLength | NON_COMPLIANT | 10 | 14 | IA-5(1)(a) | CC6.6 | A.9.4.3 | Set minimum password length to at least 14 characters |
| MFAEnforcement | MFA enabled for jane.doe | NON_COMPLIANT | No MFA device | MFA device required | IA-2(1) | CC6.1 | A.9.4.2 | Enable MFA for IAM user 'jane.doe' |
| RootActivity | Root account activity (last 30 days) | NON_COMPLIANT | 50 root event(s) detected | 0 root events | AC-2(5) | CC6.2 | A.9.2.3 | Investigate root account usage |

---

## How the schedule works

By default the snapshot runs every 7 days. EventBridge triggers the Lambda automatically — no manual intervention needed after deployment.

To change the schedule, update the `ScheduleExpression` parameter when deploying:

```bash
# Run daily
--parameter-overrides ScheduleExpression="rate(1 day)"

# Run monthly
--parameter-overrides ScheduleExpression="rate(30 days)"
```

---

## IAM permissions

The Lambda role follows least privilege. It only has the permissions it needs:

| Permission | Why it's needed |
|---|---|
| `iam:GetAccountPasswordPolicy` | Reads the account password policy |
| `iam:ListUsers` | Gets the list of IAM users |
| `iam:GetLoginProfile` | Checks which users have console access |
| `iam:ListMFADevices` | Checks MFA status per user |
| `cloudtrail:LookupEvents` | Searches for root account events |
| `s3:PutObject` | Uploads reports to the S3 bucket |
| `logs:*` | Writes Lambda execution logs to CloudWatch |

---

## Cleanup

To remove all resources created by this project:

```bash
# Empty the S3 bucket first (required before stack deletion)
aws s3 rm s3://your-iam-snapshot-bucket --recursive --profile your-profile-name

# Delete the CloudFormation stack
aws cloudformation delete-stack \
  --stack-name iam-compliance-snapshot \
  --region us-east-1 \
  --profile your-profile-name
```

---

## Skills demonstrated

| Area | Description |
|---|---|
| GRC Automation | Automated three IAM compliance controls with structured evidence output |
| Framework Alignment | Mapped findings to NIST 800-53, SOC 2, and ISO 27001 |
| Serverless Architecture | Deployed scheduled Lambda with EventBridge trigger |
| Infrastructure as Code | Defined all AWS resources in a CloudFormation template |
| Least Privilege IAM | Lambda role scoped to only required read permissions |
| Evidence Generation | Produced JSON and CSV audit-ready reports automatically |

---

## Resources

- [AWS IAM Password Policy documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
- [AWS CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
- [NIST 800-53 IA Control Family](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home)
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/)
