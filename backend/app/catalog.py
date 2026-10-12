"""Service catalog: the AWS services GhostOps can generate Terraform for.

Only services that work in at least one of MiniStack (shadow run) or Infracost
(pricing) are listed. Both values were measured on 2026-10-08 with MiniStack
1.5.22 and Infracost 2.17.0, not assumed:

  shadow_supported   `terraform apply` of the generator's default output for the
                     service succeeded on MiniStack (re-checked by the mixed
                     architecture apply in tests/test_generator.py)
  pricing            what Infracost returned for the service's resources:
                     fixed        a non-zero price from the configuration alone
                     usage_based  supported, but priced at zero usage (lower bound)
                     free         supported and reported as free
                     unsupported  Infracost does not price it
  pricing_note       the measured figures behind that value
  usage_fields       (usage-priced services only) monthly usage inputs, taken from the
                     architecture JSON `usage` object and passed to Infracost through
                     a usage file (`infracost_key` is the usage-file key);
                     `usage_resource` is the Terraform type they apply to

Each field: name, label, kind (select | int | bool | cidr | string | list),
default, plus options / min / max / help. Defaults are deliberately safe (nothing
public, encryption on), so an untouched form produces a change GhostOps approves;
risky settings must be chosen explicitly.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

PRIVATE_CIDR = "10.0.0.0/16"


def _f(name: str, label: str, kind: str, default: Any, **extra: Any) -> dict[str, Any]:
    return {"name": name, "label": label, "kind": kind, "default": default, **extra}


def _u(name: str, label: str, default: int | None, maximum: int, infracost_key: str, **extra: Any) -> dict[str, Any]:
    """A usage input for Infracost: architecture JSON `usage.<name>` -> usage file `<infracost_key>`."""
    return {"name": name, "label": label, "kind": "int", "default": default, "min": 0, "max": maximum,
            "infracost_key": infracost_key, **extra}


NAME = _f("name", "Name", "string", "", pattern=r"^[a-z][a-z0-9-]{1,30}$",
          help="Lowercase letters, digits and dashes; used in resource names. Blank = auto.")

CATALOG: dict[str, dict[str, Any]] = {
    "ec2": {
        "label": "EC2 instances",
        "description": "Linux instances, each with an encrypted gp3 data volume, behind an SSH security group.",
        "resources": ["aws_instance", "aws_ebs_volume", "aws_volume_attachment", "aws_security_group"],
        "shadow_supported": True,
        "pricing": "fixed",
        "pricing_note": "Instance hours + EBS volume. Measured: t3.small $15.98/month (incl. 8 GB root), 30 GB gp3 $2.40/month.",
        "fields": [
            NAME,
            _f("instance_type", "Instance type", "select", "t3.micro",
               options=["t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large", "m5.large", "m5.xlarge", "c5.large"]),
            _f("count", "Instance count", "int", 1, min=1, max=10),
            _f("volume_gb", "Data volume (GB) per instance", "int", 20, min=1, max=16384,
               help="Attached gp3 EBS volume. (A root_block_device cannot be read back on MiniStack.)"),
            _f("ssh_source_cidr", "SSH allowed from (CIDR)", "cidr", PRIVATE_CIDR,
               help="0.0.0.0/0 opens SSH to the whole internet (SimulaCrum will block it)."),
            _f("expected_cpu_percent", "Expected average CPU (%)", "int", 40, min=1, max=100,
               help="Stated usage, tagged as ExpectedCpuPercent. At 20 or less, sizes above small are flagged as oversized."),
        ],
    },
    "s3": {
        "label": "S3 bucket",
        "description": "Bucket with versioning, server-side encryption and a public access block.",
        "resources": ["aws_s3_bucket", "aws_s3_bucket_versioning", "aws_s3_bucket_server_side_encryption_configuration",
                      "aws_s3_bucket_public_access_block", "aws_s3_bucket_ownership_controls", "aws_s3_bucket_acl"],
        "shadow_supported": True,
        "pricing": "usage_based",
        "pricing_note": "Storage and requests depend on usage; Infracost prices them at zero usage (lower bound).",
        "fields": [
            NAME,
            _f("public_access", "Public read access", "bool", False,
               help="Makes every object readable by anyone (SimulaCrum will block it)."),
            _f("versioning", "Versioning", "bool", True),
            _f("encryption", "Server-side encryption (AES-256)", "bool", True),
            _f("size_gb", "Expected size (GB)", "int", 10, min=0, max=100000,
               help="Tagged on the bucket and used as usage.storage_gb for pricing unless that is given."),
        ],
        "usage_resource": "aws_s3_bucket",
        "usage_fields": [
            _u("storage_gb", "Standard storage (GB)", None, 10_000_000, "standard.storage_gb",
               help="Blank = the bucket's size_gb."),
            _u("monthly_put_requests", "PUT/COPY/POST/LIST requests per month", 0, 10**12, "standard.monthly_tier_1_requests"),
            _u("monthly_get_requests", "GET and other requests per month", 0, 10**12, "standard.monthly_tier_2_requests"),
        ],
    },
    "rds": {
        "label": "RDS database",
        "description": "Single RDS instance; the master password is generated and kept in Secrets Manager.",
        "resources": ["aws_db_instance"],
        "shadow_supported": True,
        "pricing": "fixed",
        "pricing_note": "Instance hours + storage. Measured: db.t3.micro + 50 GB gp2 $18.89/month.",
        "fields": [
            NAME,
            _f("engine", "Engine", "select", "postgres", options=["postgres", "mysql", "mariadb"]),
            _f("instance_class", "Instance class", "select", "db.t3.micro",
               options=["db.t3.micro", "db.t3.small", "db.t3.medium", "db.m5.large"]),
            _f("storage_gb", "Storage (GB)", "int", 20, min=20, max=1000),
            _f("multi_az", "Multi-AZ", "bool", False),
            _f("backup_retention_days", "Backup retention (days)", "int", 7, min=0, max=35,
               help="0 turns automated backups off (SimulaCrum flags it)."),
            _f("encrypted", "Storage encrypted", "bool", True),
            _f("publicly_accessible", "Publicly accessible", "bool", False),
        ],
    },
    "vpc": {
        "label": "VPC + security group",
        "description": "VPC with subnets across availability zones and one ingress rule.",
        "resources": ["aws_vpc", "aws_subnet", "aws_security_group"],
        "shadow_supported": True,
        "pricing": "unsupported",
        "pricing_note": "Infracost does not price aws_vpc / aws_subnet (free in AWS); security groups are free.",
        "fields": [
            NAME,
            _f("cidr_block", "VPC CIDR", "cidr", PRIVATE_CIDR),
            _f("subnet_count", "Subnets", "int", 2, min=1, max=4),
            _f("ingress_port", "Ingress port", "int", 443, min=1, max=65535),
            _f("ingress_cidr", "Ingress allowed from (CIDR)", "cidr", PRIVATE_CIDR,
               help="0.0.0.0/0 exposes the port to the internet; on 22 or 3389 SimulaCrum blocks it."),
        ],
    },
    "iam": {
        "label": "IAM role + policy",
        "description": "Role assumable by an AWS service, with one customer-managed policy attached.",
        "resources": ["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment"],
        "shadow_supported": True,
        "pricing": "free",
        "pricing_note": "IAM roles, policies and attachments cost nothing.",
        "fields": [
            NAME,
            _f("trusted_service", "Trusted service", "select", "ec2.amazonaws.com",
               options=["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]),
            _f("actions", "Allowed actions", "list", ["s3:GetObject"],
               item_pattern=r"^(\*|[a-z0-9-]+:[A-Za-z0-9*]+)$",
               help='e.g. s3:GetObject. "*" grants every action (SimulaCrum will block it with Resource "*").'),
            _f("resource", "Resource ARN", "string", "arn:aws:s3:::example-bucket/*",
               pattern=r"^(\*|arn:aws[a-z-]*:[^\s\"]+)$"),
        ],
    },
    "lambda": {
        "label": "Lambda function",
        "description": "Function with a minimal handler and its own execution role.",
        "resources": ["aws_lambda_function", "aws_iam_role"],
        "shadow_supported": True,
        "pricing": "usage_based",
        "pricing_note": "Requests and duration depend on usage; priced at zero usage (lower bound).",
        "fields": [
            NAME,
            _f("runtime", "Runtime", "select", "python3.12", options=["python3.12", "python3.11", "nodejs20.x"]),
            _f("memory_mb", "Memory (MB)", "int", 256, min=128, max=10240,
               help="CPU scales with memory; 128 MB (the minimum) is flagged as slow."),
            _f("timeout_s", "Timeout (s)", "int", 10, min=1, max=900),
        ],
        "usage_resource": "aws_lambda_function",
        "usage_fields": [
            _u("monthly_requests", "Invocations per month", 0, 10**12, "monthly_requests"),
            _u("request_duration_ms", "Average duration (ms)", 100, 900_000, "request_duration_ms"),
        ],
    },
    "dynamodb": {
        "label": "DynamoDB table",
        "description": "Table with a string partition key.",
        "resources": ["aws_dynamodb_table"],
        "shadow_supported": True,
        "pricing": "usage_based",
        "pricing_note": "On-demand reads/writes/storage depend on usage; PROVISIONED capacity is a fixed charge.",
        "fields": [
            NAME,
            _f("billing_mode", "Billing mode", "select", "PAY_PER_REQUEST", options=["PAY_PER_REQUEST", "PROVISIONED"]),
            _f("read_capacity", "Read capacity (provisioned only)", "int", 5, min=1, max=40000),
            _f("write_capacity", "Write capacity (provisioned only)", "int", 5, min=1, max=40000),
            _f("hash_key", "Partition key", "string", "id", pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$"),
            _f("point_in_time_recovery", "Point-in-time recovery", "bool", True),
        ],
        "usage_resource": "aws_dynamodb_table",
        "usage_fields": [
            _u("monthly_write_request_units", "Write request units per month (on-demand)", 0, 10**13,
               "monthly_write_request_units"),
            _u("monthly_read_request_units", "Read request units per month (on-demand)", 0, 10**13,
               "monthly_read_request_units"),
            _u("storage_gb", "Table storage (GB)", 0, 10_000_000, "storage_gb"),
        ],
    },
    "cloudwatch_alarm": {
        "label": "CloudWatch alarm",
        "description": "Metric alarm on a standard AWS metric.",
        "resources": ["aws_cloudwatch_metric_alarm"],
        "shadow_supported": True,
        "pricing": "fixed",
        "pricing_note": "Measured: $0.10/month per standard alarm.",
        "fields": [
            NAME,
            _f("metric", "Metric", "select", "AWS/EC2:CPUUtilization",
               options=["AWS/EC2:CPUUtilization", "AWS/RDS:CPUUtilization", "AWS/RDS:FreeStorageSpace",
                        "AWS/Lambda:Errors", "AWS/DynamoDB:ThrottledRequests", "AWS/ApplicationELB:HTTPCode_ELB_5XX_Count"]),
            _f("threshold", "Threshold", "int", 80, min=0, max=1_000_000_000),
            _f("period_s", "Period (s)", "select", 300, options=[60, 300, 900, 3600]),
            _f("evaluation_periods", "Evaluation periods", "int", 2, min=1, max=10),
        ],
    },
    "alb": {
        "label": "Application Load Balancer",
        "description": "ALB with its own VPC (two subnets), a security group, a target group and an HTTP listener.",
        "resources": ["aws_lb", "aws_lb_target_group", "aws_lb_listener", "aws_vpc", "aws_subnet", "aws_security_group"],
        "shadow_supported": True,
        "pricing": "fixed",
        "pricing_note": "Measured: $16.43/month base; load balancer capacity units depend on usage.",
        "fields": [
            NAME,
            _f("internal", "Internal (not internet-facing)", "bool", True),
            _f("listener_port", "Listener port", "int", 80, min=1, max=65535),
            _f("ingress_cidr", "Clients allowed from (CIDR)", "cidr", PRIVATE_CIDR,
               help="0.0.0.0/0 makes the load balancer public (SimulaCrum flags new internet exposure)."),
        ],
    },
}


def catalog() -> list[dict[str, Any]]:
    """The catalog as JSON-ready data (copy: callers cannot mutate the source)."""
    return [{"type": t, **deepcopy(spec)} for t, spec in CATALOG.items()]


def defaults(service_type: str) -> dict[str, Any]:
    return {f["name"]: deepcopy(f["default"]) for f in CATALOG[service_type]["fields"]}


def usage_defaults(service_type: str) -> dict[str, Any]:
    return {f["name"]: f["default"] for f in CATALOG[service_type].get("usage_fields", [])}
