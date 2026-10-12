"""Generate Terraform (for MiniStack) from a catalog-based architecture.

    generate({"services": [{"type": "ec2", "config": {"count": 2}}, {"type": "s3"}]})

Every service is validated against app/catalog.py first (type, range, allowed
options, CIDR syntax, name pattern; unknown fields are rejected), missing fields
take the catalog default, and only then is HCL written. Every user string goes
through hcl_string(), which escapes quotes and Terraform's ${ / %{ sequences, so
input cannot inject Terraform.

Each service is self-contained (an ALB brings its own VPC and subnets, a Lambda
its execution role). The provider block targets MiniStack with fake keys, like
demo/; for real AWS replace the provider block and the placeholder AMI.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.catalog import CATALOG, defaults

PLACEHOLDER_AMI = "ami-12345678"  # MiniStack accepts any id; replace for real AWS
AZS = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d"]
MAX_SERVICES = 25
SUM_METRICS = {"Errors", "ThrottledRequests", "HTTPCode_ELB_5XX_Count"}


class ArchitectureError(ValueError):
    """The architecture is invalid. `errors` lists every problem found."""

    def __init__(self, errors: list[dict[str, Any]]):
        super().__init__("; ".join(f"services[{e['service']}].{e['field']}: {e['message']}" for e in errors))
        self.errors = errors


@dataclass
class Service:
    type: str
    slug: str        # AWS-facing name part, e.g. "web-tier"
    ident: str       # Terraform identifier, e.g. "web_tier"
    config: dict[str, Any]
    usage: dict[str, Any] = field(default_factory=dict)  # Infracost usage inputs (usage-priced types)

    @property
    def shadow_supported(self) -> bool:
        return bool(CATALOG[self.type]["shadow_supported"])

    @property
    def usage_address(self) -> str | None:
        rtype = CATALOG[self.type].get("usage_resource")
        return f"{rtype}.{self.ident}" if rtype else None


@dataclass
class GeneratedTerraform:
    main_tf: str
    services: list[Service]
    resources: list[str] = field(default_factory=list)
    owners: dict[str, Service] = field(default_factory=dict)  # resource address -> service that made it
    uid: str = ""

    def write(self, directory: str | Path) -> Path:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        (path / "main.tf").write_text(self.main_tf, encoding="utf-8", newline="\n")
        return path / "main.tf"

    def owner(self, address: str) -> Service | None:
        """Service owning a resource address (instance keys like [0] are ignored)."""
        return self.owners.get(re.sub(r"\[[^\]]*\]", "", address))

    def shadow_subset(self) -> GeneratedTerraform | None:
        """Terraform for the shadow_supported services only (same names), or None if there are none."""
        supported = [s for s in self.services if s.shadow_supported]
        if not supported:
            return None
        return self if len(supported) == len(self.services) else _render(supported, self.uid)

    def usage_inputs(self) -> dict[str, dict[str, Any]]:
        """{resource address: {usage field: value}} for usage-priced services."""
        return {s.usage_address: dict(s.usage) for s in self.services if s.usage_address}

    def usage_file(self) -> dict[str, dict[str, Any]]:
        """The same inputs keyed the way Infracost's usage file expects (nested keys)."""
        out: dict[str, dict[str, Any]] = {}
        for s in self.services:
            if not s.usage_address:
                continue
            entry: dict[str, Any] = {}
            for spec in CATALOG[s.type]["usage_fields"]:
                node = entry
                *parents, leaf = spec["infracost_key"].split(".")
                for p in parents:
                    node = node.setdefault(p, {})
                node[leaf] = s.usage[spec["name"]]
            out[s.usage_address] = entry
        return out


# --- HCL helpers -------------------------------------------------------------------------


def hcl_string(value: str) -> str:
    """A safe HCL string literal: JSON escaping plus Terraform template escapes."""
    return json.dumps(str(value)).replace("${", "$${").replace("%{", "%%{")


def hcl_list(values: list[str]) -> str:
    return "[" + ", ".join(hcl_string(v) for v in values) + "]"


def hcl_bool(value: bool) -> str:
    return "true" if value else "false"


def tags(svc: Service, name: str, **extra: str) -> str:
    items = {"Name": name, "ManagedBy": "ghostops", "GhostOpsService": svc.type, **extra}
    width = max(len(k) for k in items)  # align "=" the way terraform fmt does
    body = "\n".join(f"    {k:<{width}} = {hcl_string(v)}" for k, v in items.items())
    return f"  tags = {{\n{body}\n  }}"


def aligned(pairs: list[tuple[str, str]], indent: str = "  ") -> str:
    """Attribute lines with "=" aligned the way terraform fmt does."""
    width = max(len(k) for k, _ in pairs)
    return "\n".join(f"{indent}{k:<{width}} = {v}" for k, v in pairs)


def ingress_block(port: int, cidr: str, description: str | None = None) -> str:
    """One TCP ingress rule; cidr_blocks or ipv6_cidr_blocks by address family."""
    family = "ipv6_cidr_blocks" if ipaddress.ip_network(cidr, strict=True).version == 6 else "cidr_blocks"
    pairs = ([("description", hcl_string(description))] if description else []) + [
        ("from_port", str(port)), ("to_port", str(port)), ("protocol", '"tcp"'), (family, hcl_list([cidr]))]
    return "  ingress {\n" + aligned(pairs, "    ") + "\n  }"


# --- validation -----------------------------------------------------------------------------


def _check_field(spec: dict[str, Any], value: Any) -> str | None:
    kind = spec["kind"]
    if kind == "select":
        return None if value in spec["options"] else f"must be one of {spec['options']}"
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            return "must be an integer"
        if not spec["min"] <= value <= spec["max"]:
            return f"must be between {spec['min']} and {spec['max']}"
        return None
    if kind == "bool":
        return None if isinstance(value, bool) else "must be true or false"
    if kind == "cidr":
        if not isinstance(value, str):
            return "must be a CIDR string such as 10.0.0.0/16"
        try:
            ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            return f"is not a valid CIDR ({exc})"
        return None
    if kind == "string":
        if not isinstance(value, str):
            return "must be a string"
        if spec.get("pattern") and value and not re.fullmatch(spec["pattern"], value):
            return f"must match {spec['pattern']}"
        return None
    if kind == "list":
        if not isinstance(value, list) or not value or len(value) > 20:
            return "must be a list of 1 to 20 strings"
        bad = [v for v in value if not isinstance(v, str) or not re.fullmatch(spec["item_pattern"], v)]
        return f"invalid entries {bad}" if bad else None
    return f"unknown field kind {kind}"


def _validate_usage(stype: str, usage: Any, config: dict[str, Any], i: int,
                    errors: list[dict[str, Any]]) -> dict[str, Any]:
    specs = {f["name"]: f for f in CATALOG[stype].get("usage_fields", [])}
    if usage is None:
        usage = {}
    if not isinstance(usage, dict):
        errors.append({"service": i, "field": "usage", "message": "must be an object"})
        return {}
    if usage and not specs:
        errors.append({"service": i, "field": "usage",
                       "message": f"{stype} has no usage inputs (only S3, Lambda and DynamoDB are usage-priced)"})
        return {}
    for unknown in sorted(set(usage) - set(specs)):
        errors.append({"service": i, "field": f"usage.{unknown}", "message": f"unknown usage input for {stype}"})
    merged = {name: usage.get(name, spec["default"]) for name, spec in specs.items()}
    if stype == "s3" and merged["storage_gb"] is None:
        merged["storage_gb"] = config.get("size_gb", 0)  # the bucket's expected size
    for name, spec in specs.items():
        problem = _check_field(spec, merged[name])
        if problem:
            errors.append({"service": i, "field": f"usage.{name}", "message": problem})
    return merged


def validate(architecture: Any) -> list[Service]:
    if not isinstance(architecture, dict) or not isinstance(architecture.get("services"), list):
        raise ArchitectureError([{"service": "-", "field": "services", "message": "body must be {\"services\": [...]}"}])
    items = architecture["services"]
    if not 1 <= len(items) <= MAX_SERVICES:
        raise ArchitectureError([{"service": "-", "field": "services",
                                  "message": f"need between 1 and {MAX_SERVICES} services"}])
    errors: list[dict[str, Any]] = []
    services: list[Service] = []
    seen: dict[str, int] = {}
    counters: dict[str, int] = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict) or item.get("type") not in CATALOG:
            errors.append({"service": i, "field": "type", "message": f"must be one of {sorted(CATALOG)}"})
            continue
        stype = item["type"]
        config = item.get("config") or {}
        if not isinstance(config, dict):
            errors.append({"service": i, "field": "config", "message": "must be an object"})
            continue
        specs = {f["name"]: f for f in CATALOG[stype]["fields"]}
        for unknown in sorted(set(config) - set(specs)):
            errors.append({"service": i, "field": unknown, "message": f"unknown field for {stype}"})
        merged = {**defaults(stype), **{k: v for k, v in config.items() if k in specs}}
        for name, spec in specs.items():
            problem = _check_field(spec, merged[name])
            if problem:
                errors.append({"service": i, "field": name, "message": problem})
        if stype == "vpc" and not any(e["service"] == i and e["field"] == "cidr_block" for e in errors):
            net = ipaddress.ip_network(merged["cidr_block"])
            if net.version != 4 or not 16 <= net.prefixlen <= 24:
                errors.append({"service": i, "field": "cidr_block", "message": "must be an IPv4 range from /16 to /24"})

        usage = _validate_usage(stype, item.get("usage"), merged, i, errors)

        counters[stype] = counters.get(stype, 0) + 1
        slug = merged["name"] or f"{stype.replace('_', '-')}-{counters[stype]}"
        if slug in seen:
            errors.append({"service": i, "field": "name", "message": f"duplicate name {slug!r} (also services[{seen[slug]}])"})
        seen[slug] = i
        services.append(Service(stype, slug, slug.replace("-", "_"), {**merged, "name": slug}, usage))
    if errors:
        raise ArchitectureError(errors)
    return services


# --- per-service HCL --------------------------------------------------------------------------


def _egress_all() -> str:
    return ('  egress {\n    from_port   = 0\n    to_port     = 0\n    protocol    = "-1"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }')


def _ec2(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    return f"""resource "aws_security_group" "{i}_ssh" {{
  name        = {hcl_string(f"ghostops-{s.slug}-ssh")}
  description = {hcl_string(f"SSH access for {s.slug}")}

{ingress_block(22, c["ssh_source_cidr"], "SSH")}

{_egress_all()}
{tags(s, f"ghostops-{s.slug}-ssh")}
}}

resource "aws_instance" "{i}" {{
  count                  = {c["count"]}
  ami                    = {hcl_string(PLACEHOLDER_AMI)} # placeholder: replace for real AWS
  instance_type          = {hcl_string(c["instance_type"])}
  vpc_security_group_ids = [aws_security_group.{i}_ssh.id]

  tags = {{
    Name               = "ghostops-{s.slug}-${{count.index}}"
    ManagedBy          = "ghostops"
    GhostOpsService    = "ec2"
    ExpectedCpuPercent = "{c["expected_cpu_percent"]}"
  }}
}}

# Data volume per instance. A separate EBS volume rather than root_block_device:
# MiniStack instances have no root EBS volume, so the AWS provider fails to read
# root_block_device back ("collecting instance settings: empty result").
resource "aws_ebs_volume" "{i}" {{
  count             = {c["count"]}
  availability_zone = aws_instance.{i}[count.index].availability_zone
  size              = {c["volume_gb"]}
  type              = "gp3"
  encrypted         = true

  tags = {{
    Name            = "ghostops-{s.slug}-data-${{count.index}}"
    ManagedBy       = "ghostops"
    GhostOpsService = "ec2"
  }}
}}

resource "aws_volume_attachment" "{i}" {{
  count       = {c["count"]}
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.{i}[count.index].id
  instance_id = aws_instance.{i}[count.index].id
}}
"""


def _s3(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    bucket = f"ghostops-{s.slug}-{uid}"
    blocks = [f"""resource "aws_s3_bucket" "{i}" {{
  bucket = {hcl_string(bucket)}
{tags(s, bucket, ExpectedSizeGB=str(c["size_gb"]))}
}}
"""]
    if c["versioning"]:
        blocks.append(f"""resource "aws_s3_bucket_versioning" "{i}" {{
  bucket = aws_s3_bucket.{i}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
""")
    if c["encryption"]:
        blocks.append(f"""resource "aws_s3_bucket_server_side_encryption_configuration" "{i}" {{
  bucket = aws_s3_bucket.{i}.id
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
""")
    public = c["public_access"]
    blocks.append(f"""resource "aws_s3_bucket_public_access_block" "{i}" {{
  bucket                  = aws_s3_bucket.{i}.id
  block_public_acls       = {hcl_bool(not public)}
  block_public_policy     = {hcl_bool(not public)}
  ignore_public_acls      = {hcl_bool(not public)}
  restrict_public_buckets = {hcl_bool(not public)}
}}
""")
    if public:
        blocks.append(f"""resource "aws_s3_bucket_ownership_controls" "{i}" {{
  bucket = aws_s3_bucket.{i}.id
  rule {{
    object_ownership = "BucketOwnerPreferred"
  }}
}}

resource "aws_s3_bucket_acl" "{i}" {{
  bucket     = aws_s3_bucket.{i}.id
  acl        = "public-read"
  depends_on = [aws_s3_bucket_ownership_controls.{i}, aws_s3_bucket_public_access_block.{i}]
}}
""")
    return "\n".join(blocks)


def _rds(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    return f"""resource "aws_db_instance" "{i}" {{
  identifier                  = {hcl_string(f"ghostops-{s.slug}")}
  engine                      = {hcl_string(c["engine"])}
  instance_class              = {hcl_string(c["instance_class"])}
  allocated_storage           = {c["storage_gb"]}
  multi_az                    = {hcl_bool(c["multi_az"])}
  backup_retention_period     = {c["backup_retention_days"]}
  storage_encrypted           = {hcl_bool(c["encrypted"])}
  publicly_accessible         = {hcl_bool(c["publicly_accessible"])}
  username                    = "ghostops"
  manage_master_user_password = true # password generated and kept in Secrets Manager
  skip_final_snapshot         = true
{tags(s, f"ghostops-{s.slug}")}
}}
"""


def _vpc(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    azs = hcl_list(AZS)
    return f"""resource "aws_vpc" "{i}" {{
  cidr_block           = {hcl_string(c["cidr_block"])}
  enable_dns_hostnames = true
{tags(s, f"ghostops-{s.slug}")}
}}

resource "aws_subnet" "{i}" {{
  count             = {c["subnet_count"]}
  vpc_id            = aws_vpc.{i}.id
  cidr_block        = cidrsubnet(aws_vpc.{i}.cidr_block, 4, count.index)
  availability_zone = element({azs}, count.index)

  tags = {{
    Name            = "ghostops-{s.slug}-${{count.index}}"
    ManagedBy       = "ghostops"
    GhostOpsService = "vpc"
  }}
}}

resource "aws_security_group" "{i}" {{
  name        = {hcl_string(f"ghostops-{s.slug}")}
  description = {hcl_string(f"Ingress on port {c['ingress_port']} for {s.slug}")}
  vpc_id      = aws_vpc.{i}.id

{ingress_block(c["ingress_port"], c["ingress_cidr"])}

{_egress_all()}
{tags(s, f"ghostops-{s.slug}")}
}}
"""


def _iam(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    return f"""resource "aws_iam_role" "{i}" {{
  name = {hcl_string(f"ghostops-{s.slug}-role")}
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = {hcl_string(c["trusted_service"])} }}
      Action    = "sts:AssumeRole"
    }}]
  }})
{tags(s, f"ghostops-{s.slug}-role")}
}}

resource "aws_iam_policy" "{i}" {{
  name = {hcl_string(f"ghostops-{s.slug}-policy")}
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = {hcl_list(c["actions"])}
      Resource = {hcl_string(c["resource"])}
    }}]
  }})
{tags(s, f"ghostops-{s.slug}-policy")}
}}

resource "aws_iam_role_policy_attachment" "{i}" {{
  role       = aws_iam_role.{i}.name
  policy_arn = aws_iam_policy.{i}.arn
}}
"""


LAMBDA_CODE = {
    "python": ("index.py", 'def handler(event, context):\n    return {"statusCode": 200}\n'),
    "nodejs": ("index.js", "exports.handler = async () => ({ statusCode: 200 });\n"),
}


def _lambda(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    filename, code = LAMBDA_CODE["nodejs" if c["runtime"].startswith("nodejs") else "python"]
    return f"""data "archive_file" "{i}" {{
  type        = "zip"
  output_path = "${{path.module}}/{i}.zip"

  source {{
    filename = {hcl_string(filename)}
    content  = {hcl_string(code)}
  }}
}}

resource "aws_iam_role" "{i}_exec" {{
  name = {hcl_string(f"ghostops-{s.slug}-exec")}
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "lambda.amazonaws.com" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
{tags(s, f"ghostops-{s.slug}-exec")}
}}

resource "aws_lambda_function" "{i}" {{
  function_name    = {hcl_string(f"ghostops-{s.slug}")}
  role             = aws_iam_role.{i}_exec.arn
  handler          = "index.handler"
  runtime          = {hcl_string(c["runtime"])}
  memory_size      = {c["memory_mb"]}
  timeout          = {c["timeout_s"]}
  filename         = data.archive_file.{i}.output_path
  source_code_hash = data.archive_file.{i}.output_base64sha256
{tags(s, f"ghostops-{s.slug}")}
}}
"""


def _dynamodb(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    pairs = [("name", hcl_string(f"ghostops-{s.slug}")), ("billing_mode", hcl_string(c["billing_mode"])),
             ("hash_key", hcl_string(c["hash_key"]))]
    if c["billing_mode"] == "PROVISIONED":
        pairs += [("read_capacity", str(c["read_capacity"])), ("write_capacity", str(c["write_capacity"]))]
    return f"""resource "aws_dynamodb_table" "{i}" {{
{aligned(pairs)}

  attribute {{
    name = {hcl_string(c["hash_key"])}
    type = "S"
  }}

  point_in_time_recovery {{
    enabled = {hcl_bool(c["point_in_time_recovery"])}
  }}

{tags(s, f"ghostops-{s.slug}")}
}}
"""


def _cloudwatch_alarm(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    namespace, metric = c["metric"].split(":", 1)
    below = metric == "FreeStorageSpace"
    return f"""resource "aws_cloudwatch_metric_alarm" "{i}" {{
  alarm_name          = {hcl_string(f"ghostops-{s.slug}")}
  alarm_description   = {hcl_string(f"{metric} {'below' if below else 'above'} {c['threshold']}")}
  namespace           = {hcl_string(namespace)}
  metric_name         = {hcl_string(metric)}
  statistic           = {hcl_string("Sum" if metric in SUM_METRICS else "Average")}
  period              = {c["period_s"]}
  evaluation_periods  = {c["evaluation_periods"]}
  threshold           = {c["threshold"]}
  comparison_operator = {hcl_string("LessThanThreshold" if below else "GreaterThanThreshold")}
  treat_missing_data  = "notBreaching"
{tags(s, f"ghostops-{s.slug}")}
}}
"""


def _alb(s: Service, uid: str) -> str:
    c, i = s.config, s.ident
    lb_name = f"go-{s.slug}"[:32].rstrip("-")
    tg_name = f"go-{s.slug}"[:29].rstrip("-") + "-tg"
    igw = "" if c["internal"] else f"""
# An internet-facing ALB needs an internet gateway in its VPC.
resource "aws_internet_gateway" "{i}" {{
  vpc_id = aws_vpc.{i}.id
{tags(s, f"ghostops-{s.slug}")}
}}
"""
    return f"""resource "aws_vpc" "{i}" {{
  cidr_block = "10.200.0.0/16"
{tags(s, f"ghostops-{s.slug}")}
}}
{igw}
resource "aws_subnet" "{i}" {{
  count             = 2
  vpc_id            = aws_vpc.{i}.id
  cidr_block        = cidrsubnet(aws_vpc.{i}.cidr_block, 8, count.index)
  availability_zone = element({hcl_list(AZS[:2])}, count.index)

  tags = {{
    Name            = "ghostops-{s.slug}-${{count.index}}"
    ManagedBy       = "ghostops"
    GhostOpsService = "alb"
  }}
}}

resource "aws_security_group" "{i}" {{
  name        = {hcl_string(f"ghostops-{s.slug}-alb")}
  description = {hcl_string(f"Clients of {s.slug} on port {c['listener_port']}")}
  vpc_id      = aws_vpc.{i}.id

{ingress_block(c["listener_port"], c["ingress_cidr"])}

{_egress_all()}
{tags(s, f"ghostops-{s.slug}-alb")}
}}

resource "aws_lb" "{i}" {{
  name               = {hcl_string(lb_name)}
  internal           = {hcl_bool(c["internal"])}
  load_balancer_type = "application"
  security_groups    = [aws_security_group.{i}.id]
  subnets            = aws_subnet.{i}[*].id
{tags(s, lb_name)}
}}

resource "aws_lb_target_group" "{i}" {{
  name        = {hcl_string(tg_name)}
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.{i}.id
  target_type = "instance"
}}

resource "aws_lb_listener" "{i}" {{
  load_balancer_arn = aws_lb.{i}.arn
  port              = {c["listener_port"]}
  protocol          = "HTTP"

  default_action {{
    type             = "forward"
    target_group_arn = aws_lb_target_group.{i}.arn
  }}
}}
"""


RENDERERS = {
    "ec2": _ec2, "s3": _s3, "rds": _rds, "vpc": _vpc, "iam": _iam, "lambda": _lambda,
    "dynamodb": _dynamodb, "cloudwatch_alarm": _cloudwatch_alarm, "alb": _alb,
}

ENDPOINTS = ["cloudwatch", "dynamodb", "ec2", "elbv2", "iam", "lambda", "rds", "s3", "sts"]


def _header(services: list[Service]) -> str:
    providers = ['    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }']
    if any(s.type == "lambda" for s in services):
        providers.append('    archive = {\n      source  = "hashicorp/archive"\n      version = "~> 2.4"\n    }')
    endpoints = "\n".join(f"    {e:<10} = var.ministack_endpoint" for e in ENDPOINTS)
    summary = ", ".join(f"{s.type}:{s.slug}" for s in services)
    return f"""# Generated by SimulaCrum from the service catalog: {summary}
# Targets MiniStack (local AWS emulator) with fake credentials. For real AWS,
# replace the provider block and the placeholder AMI.

terraform {{
  required_version = ">= 1.6"
  required_providers {{
{chr(10).join(providers)}
  }}
}}

variable "ministack_endpoint" {{
  type    = string
  default = "http://localhost:4566"
}}

provider "aws" {{
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {{
{endpoints}
  }}
}}
"""


_RESOURCE = re.compile(r'^(resource|data) "([a-z0-9_]+)" "([a-z0-9_]+)"', re.M)


def _addresses(hcl: str) -> list[str]:
    return [f"{'data.' if kind == 'data' else ''}{rtype}.{name}" for kind, rtype, name in _RESOURCE.findall(hcl)]


def _render(services: list[Service], uid: str) -> GeneratedTerraform:
    chunks, owners = [], {}
    for s in services:
        hcl = RENDERERS[s.type](s, uid)
        owners.update({address: s for address in _addresses(hcl)})
        chunks.append(f"# --- {s.type}: {s.slug} " + "-" * max(4, 60 - len(s.type) - len(s.slug)) + "\n\n" + hcl)
    main_tf = _header(services) + "\n" + "\n".join(chunks)
    return GeneratedTerraform(main_tf=main_tf, services=services, resources=_addresses(main_tf), owners=owners, uid=uid)


def generate(architecture: Any) -> GeneratedTerraform:
    services = validate(architecture)
    # Stable short id for globally unique names (S3): same architecture -> same names.
    uid = hashlib.sha256(json.dumps([[s.type, s.config] for s in services], sort_keys=True).encode()).hexdigest()[:6]
    return _render(services, uid)
