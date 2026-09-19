data "aws_partition" "current" {}
data "aws_caller_identity" "workload" {}

data "aws_partition" "witness" {
  provider = aws.witness
}

data "aws_caller_identity" "witness" {
  provider = aws.witness
}

data "aws_subnet" "sandbox_node" {
  for_each = var.sandbox_node_subnets
  id       = each.value.subnet_id
}

locals {
  common_tags = merge(
    {
      Application      = "safe-qa-service"
      ManagedBy        = "terraform"
      EvidenceBoundary = "production-control-plane"
      ClinicalClaims   = "unverified"
      BiologicalClaims = "unverified"
    },
    var.tags,
  )

  prod_trail_name      = "${var.name_prefix}-production-evidence"
  witness_trail_name   = "${var.name_prefix}-witness-evidence"
  prod_trail_arn       = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${var.workload_account_id}:trail/${local.prod_trail_name}"
  witness_trail_arn    = "arn:${data.aws_partition.witness.partition}:cloudtrail:${var.witness_aws_region}:${var.witness_account_id}:trail/${local.witness_trail_name}"
  prod_trail_bucket    = "${var.name_prefix}-${var.workload_account_id}-${var.aws_region}-trail"
  witness_trail_bucket = "${var.name_prefix}-${var.witness_account_id}-${var.witness_aws_region}-witness"
  runtime_role_name    = "${var.name_prefix}-runtime"
  runtime_role_arn     = "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:role/${local.runtime_role_name}"
  witness_reader_name  = "${var.name_prefix}-witness-evidence-reader"
  irsa_subject         = "system:serviceaccount:${var.workload_namespace}:${var.workload_service_account}"
  firewall_name        = "${var.name_prefix}-egress"
  firewall_policy_name = "${var.name_prefix}-strict-egress"
  firewall_rg_name     = "${var.name_prefix}-strict-egress"
  approval_key_management_actions = [
    "kms:CancelKeyDeletion",
    "kms:CreateAlias",
    "kms:DeleteAlias",
    "kms:DescribeKey",
    "kms:DisableKey",
    "kms:EnableKey",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListKeyPolicies",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
  ]
  suricata_effective_lines = [
    for line in split("\n", var.suricata_rules) : trimspace(line)
    if trimspace(line) != "" && !startswith(trimspace(line), "#")
  ]
}

resource "terraform_data" "invariants" {
  input = {
    workload_account = data.aws_caller_identity.workload.account_id
    witness_account  = data.aws_caller_identity.witness.account_id
  }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.workload.account_id == var.workload_account_id
      error_message = "The workload provider is not operating in workload_account_id."
    }
    precondition {
      condition     = data.aws_caller_identity.witness.account_id == var.witness_account_id
      error_message = "The witness provider is not operating in witness_account_id."
    }
    precondition {
      condition     = var.workload_account_id != var.witness_account_id
      error_message = "The witness account must be different from the workload account."
    }
    precondition {
      condition     = var.security_approver_role_arn != var.release_approver_role_arn && var.security_approver_role_arn != var.witness_approver_role_arn && var.release_approver_role_arn != var.witness_approver_role_arn
      error_message = "Security, release, and witness principals must be three distinct role ARNs."
    }
    precondition {
      condition     = var.security_approver_user_id != var.release_approver_user_id && var.security_approver_user_id != var.witness_approver_user_id && var.release_approver_user_id != var.witness_approver_user_id
      error_message = "Security, release, and witness approvals must pin three distinct Identity Center UserIds."
    }
    precondition {
      condition     = startswith(var.security_approver_role_arn, "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:role/") && startswith(var.release_approver_role_arn, "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:role/")
      error_message = "Both production approver role ARNs must belong to workload_account_id."
    }
    precondition {
      condition     = startswith(var.witness_approver_role_arn, "arn:${data.aws_partition.witness.partition}:iam::${var.witness_account_id}:role/")
      error_message = "The witness approver role ARN must belong to witness_account_id."
    }
    precondition {
      condition     = startswith(var.security_identity_store_arn, "arn:${data.aws_partition.current.partition}:identitystore::${var.workload_account_id}:identitystore/") && startswith(var.release_identity_store_arn, "arn:${data.aws_partition.current.partition}:identitystore::${var.workload_account_id}:identitystore/")
      error_message = "Production identity-store ARNs must belong to workload_account_id."
    }
    precondition {
      condition     = startswith(var.witness_identity_store_arn, "arn:${data.aws_partition.witness.partition}:identitystore::${var.witness_account_id}:identitystore/")
      error_message = "The witness identity-store ARN must belong to witness_account_id."
    }
    precondition {
      condition     = alltrue([for arn in var.witness_evidence_auditor_role_arns : startswith(arn, "arn:${data.aws_partition.witness.partition}:iam::${var.witness_account_id}:role/")])
      error_message = "Every witness auditor role ARN must belong to witness_account_id."
    }
    precondition {
      condition = length(local.suricata_effective_lines) > 0 ? can(regex(
        "^(drop|reject)\\s+ip\\s+any\\s+any\\s+->\\s+any\\s+any\\s+\\(.+\\)$",
        lower(element(reverse(local.suricata_effective_lines), 0)),
      )) : false
      error_message = "The final effective Suricata rule must be a drop/reject ip any any -> any any (...) catch-all."
    }
    precondition {
      condition = alltrue([
        for name, subnet in data.aws_subnet.sandbox_node :
        subnet.vpc_id == var.vpc_id &&
        subnet.map_public_ip_on_launch == false &&
        subnet.availability_zone == var.sandbox_node_subnets[name].availability_zone
      ])
      error_message = "Every sandbox node subnet must belong to vpc_id, match its declared Availability Zone, and have public-IP assignment disabled."
    }
    precondition {
      condition     = length(distinct([for subnet in var.sandbox_node_subnets : subnet.availability_zone])) >= 2
      error_message = "Sandbox node subnets must span at least two Availability Zones."
    }
    precondition {
      condition = alltrue([
        for subnet in var.sandbox_node_subnets :
        contains([for route in var.protected_routes : route.route_table_id], subnet.route_table_id)
      ])
      error_message = "Every sandbox node route table must appear in protected_routes and be steered through Network Firewall."
    }
    precondition {
      condition     = var.sandbox_node_min_size >= 1 && var.sandbox_node_min_size <= var.sandbox_node_desired_size && var.sandbox_node_desired_size <= var.sandbox_node_max_size && var.sandbox_node_max_size <= 3
      error_message = "Sandbox autoscaling must satisfy 1 <= min <= desired <= max <= 3."
    }
    precondition {
      condition     = !contains(var.revocable_iam_role_arns, local.runtime_role_arn)
      error_message = "revocable_iam_role_arns must never include the safe-qa runtime role."
    }
  }
}

# EKS VPC CNI network-policy enforcement must already be supported by the
# selected cluster platform and exact add-on version. Import this resource when
# the existing add-on is not yet under this state file.
resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = var.eks_cluster_name
  addon_name                  = "vpc-cni"
  addon_version               = var.vpc_cni_addon_version
  resolve_conflicts_on_create = "NONE"
  resolve_conflicts_on_update = "PRESERVE"
  preserve                    = true

  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
    env = {
      NETWORK_POLICY_ENFORCING_MODE = "strict"
    }
  })

  service_account_role_arn = var.vpc_cni_service_account_role_arn

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [terraform_data.invariants]
}

# Sandbox workloads run only on this tainted, labeled EC2 Linux managed node
# group. The node role contains only EKS worker and ECR pull capabilities; the
# VPC CNI uses its own IRSA role and the sandbox ServiceAccount has no IRSA.
resource "aws_iam_role" "sandbox_node" {
  name = "${var.name_prefix}-sandbox-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "sandbox_node_worker" {
  role       = aws_iam_role.sandbox_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "sandbox_node_ecr_pull" {
  role       = aws_iam_role.sandbox_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
}

resource "aws_launch_template" "sandbox_node" {
  name_prefix            = "${var.name_prefix}-sandbox-node-"
  update_default_version = true

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    device_index                = 0
    security_groups             = [aws_security_group.sandbox_node.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = var.sandbox_root_volume_size_gib
      volume_type           = "gp3"
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.common_tags, { Name = "${var.name_prefix}-sandbox-node" })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.common_tags, { Name = "${var.name_prefix}-sandbox-node-root" })
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eks_node_group" "agent_sandbox" {
  cluster_name    = var.eks_cluster_name
  node_group_name = "${var.name_prefix}-agent-sandbox"
  node_role_arn   = aws_iam_role.sandbox_node.arn
  subnet_ids      = sort([for subnet in var.sandbox_node_subnets : subnet.subnet_id])
  ami_type        = "AL2023_x86_64_STANDARD"
  capacity_type   = "ON_DEMAND"
  instance_types  = sort(tolist(var.sandbox_node_instance_types))

  launch_template {
    id      = aws_launch_template.sandbox_node.id
    version = aws_launch_template.sandbox_node.latest_version
  }

  scaling_config {
    min_size     = var.sandbox_node_min_size
    desired_size = var.sandbox_node_desired_size
    max_size     = var.sandbox_node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "safe-qa.io/runtime"              = "ec2-network-policy-sandbox"
    "safe-qa.io/exclusive-node-group" = "true"
  }

  taint {
    key    = "safe-qa.io/agent-sandbox"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  depends_on = [
    aws_eks_addon.vpc_cni,
    aws_iam_role_policy_attachment.sandbox_node_worker,
    aws_iam_role_policy_attachment.sandbox_node_ecr_pull,
    aws_route_table_association.sandbox_node,
    aws_route.through_firewall,
    aws_flow_log.sandbox_node,
  ]

  lifecycle {
    prevent_destroy = true
  }
}

# Network Firewall: strict-order rules are an input so this package cannot
# silently invent permitted destinations. Route resources below enforce the
# caller's exact availability-zone to endpoint mapping.
resource "aws_networkfirewall_rule_group" "strict_egress" {
  name     = local.firewall_rg_name
  capacity = var.network_firewall_capacity
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = var.suricata_rules
    }

    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_networkfirewall_firewall_policy" "strict_egress" {
  name = local.firewall_policy_name

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = ["aws:drop_strict"]

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    stateful_rule_group_reference {
      priority     = 100
      resource_arn = aws_networkfirewall_rule_group.strict_egress.arn
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_networkfirewall_firewall" "egress" {
  name                              = local.firewall_name
  firewall_policy_arn               = aws_networkfirewall_firewall_policy.strict_egress.arn
  vpc_id                            = var.vpc_id
  delete_protection                 = true
  firewall_policy_change_protection = true
  subnet_change_protection          = true

  dynamic "subnet_mapping" {
    for_each = var.firewall_subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "firewall_alert" {
  name              = "/aws/network-firewall/${local.firewall_name}/alert"
  retention_in_days = var.cloudtrail_log_retention_days
  skip_destroy      = true
}

resource "aws_cloudwatch_log_group" "firewall_flow" {
  name              = "/aws/network-firewall/${local.firewall_name}/flow"
  retention_in_days = var.cloudtrail_log_retention_days
  skip_destroy      = true
}

resource "aws_networkfirewall_logging_configuration" "egress" {
  firewall_arn = aws_networkfirewall_firewall.egress.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_alert.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }

    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_flow.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}

resource "aws_route" "through_firewall" {
  for_each = var.protected_routes

  route_table_id         = each.value.route_table_id
  destination_cidr_block = each.value.destination_cidr_block
  vpc_endpoint_id = one([
    for sync_state in aws_networkfirewall_firewall.egress.firewall_status[0].sync_states :
    sync_state.attachment[0].endpoint_id
    if sync_state.availability_zone == each.value.availability_zone
  ])

  lifecycle {
    create_before_destroy = true
  }
}

# Own the actual subnet associations. A declared route-table identifier is not
# accepted as proof; Terraform reads and writes the provider association for
# every exact sandbox subnet.
resource "aws_route_table_association" "sandbox_node" {
  for_each = var.sandbox_node_subnets

  subnet_id      = each.value.subnet_id
  route_table_id = each.value.route_table_id
}

resource "aws_security_group" "sandbox_node" {
  name_prefix            = "${var.name_prefix}-sandbox-node-"
  description            = "Dedicated deny-by-default EKS sandbox node group"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "sandbox_node_self" {
  security_group_id            = aws_security_group.sandbox_node.id
  referenced_security_group_id = aws_security_group.sandbox_node.id
  ip_protocol                  = "-1"
  description                  = "Node-local traffic; pod isolation remains enforced by VPC CNI NetworkPolicy"
}

resource "aws_vpc_security_group_egress_rule" "sandbox_node_self" {
  security_group_id            = aws_security_group.sandbox_node.id
  referenced_security_group_id = aws_security_group.sandbox_node.id
  ip_protocol                  = "-1"
  description                  = "Node-local traffic; pod isolation remains enforced by VPC CNI NetworkPolicy"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_to_sandbox_kubelet" {
  security_group_id            = aws_security_group.sandbox_node.id
  referenced_security_group_id = var.eks_cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 10250
  to_port                      = 10250
  description                  = "Exact EKS control-plane kubelet path"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_to_sandbox_https" {
  security_group_id            = aws_security_group.sandbox_node.id
  referenced_security_group_id = var.eks_cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Exact EKS control-plane HTTPS path"
}

resource "aws_vpc_security_group_ingress_rule" "sandbox_to_cluster_api" {
  security_group_id            = var.eks_cluster_security_group_id
  referenced_security_group_id = aws_security_group.sandbox_node.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Sandbox node access to the private EKS API endpoint"
}

resource "aws_vpc_security_group_egress_rule" "sandbox_to_cluster_api" {
  security_group_id            = aws_security_group.sandbox_node.id
  referenced_security_group_id = var.eks_cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "Exact private EKS API security-group path"
}

resource "aws_vpc_security_group_egress_rule" "sandbox_node" {
  for_each = var.sandbox_node_egress_rules

  security_group_id = aws_security_group.sandbox_node.id
  description       = each.value.description
  cidr_ipv4         = each.value.cidr_ipv4
  ip_protocol       = each.value.ip_protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
}

resource "aws_cloudwatch_log_group" "sandbox_node_flow" {
  name              = "/aws/vpc/flowlogs/${var.name_prefix}-sandbox-node"
  retention_in_days = var.cloudtrail_log_retention_days
  skip_destroy      = true
}

resource "aws_iam_role" "sandbox_node_flow_logs" {
  name = "${var.name_prefix}-sandbox-node-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.workload_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.workload_account_id}:vpc-flow-log/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "sandbox_node_flow_logs" {
  name = "${var.name_prefix}-sandbox-node-flow-logs"
  role = aws_iam_role.sandbox_node_flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.sandbox_node_flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "sandbox_node" {
  for_each = var.sandbox_node_subnets

  subnet_id                = each.value.subnet_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.sandbox_node_flow.arn
  iam_role_arn             = aws_iam_role.sandbox_node_flow_logs.arn
  max_aggregation_interval = 60

  depends_on = [aws_iam_role_policy.sandbox_node_flow_logs]
}

# The two production keys are intentionally distinct. Key policies grant Sign
# to only one existing federated human role apiece. The runtime role is added
# later, after its trust policy exists, and receives Verify only.
resource "aws_kms_key" "security_approval" {
  description              = "Safe QA SECURITY_OWNER detached approvals"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false
  deletion_window_in_days  = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountKeyManagementWithoutCryptographicUseOrGrants"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:root" }
        Action    = local.approval_key_management_actions
        Resource  = "*"
      },
      {
        Sid       = "OneHumanSignerRole"
        Effect    = "Allow"
        Principal = { AWS = var.security_approver_role_arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "identitystore:UserId"           = var.security_approver_user_id
            "identitystore:IdentityStoreArn" = var.security_identity_store_arn
          }
        }
      },
      {
        Sid       = "RuntimeVerifyOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.runtime.arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]
        Resource  = "*"
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "security_approval" {
  name          = "alias/${var.name_prefix}-security-approval"
  target_key_id = aws_kms_key.security_approval.key_id
}

resource "aws_kms_key" "release_approval" {
  description              = "Safe QA RELEASE_OWNER detached approvals"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false
  deletion_window_in_days  = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountKeyManagementWithoutCryptographicUseOrGrants"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:root" }
        Action    = local.approval_key_management_actions
        Resource  = "*"
      },
      {
        Sid       = "OneHumanSignerRole"
        Effect    = "Allow"
        Principal = { AWS = var.release_approver_role_arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "identitystore:UserId"           = var.release_approver_user_id
            "identitystore:IdentityStoreArn" = var.release_identity_store_arn
          }
        }
      },
      {
        Sid       = "RuntimeVerifyOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.runtime.arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]
        Resource  = "*"
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "release_approval" {
  name          = "alias/${var.name_prefix}-release-approval"
  target_key_id = aws_kms_key.release_approval.key_id
}

resource "aws_kms_key" "witness_approval" {
  provider                 = aws.witness
  description              = "Independent Safe QA witness detached signatures"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false
  deletion_window_in_days  = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WitnessAccountKeyManagementWithoutCryptographicUseOrGrants"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.witness.partition}:iam::${var.witness_account_id}:root" }
        Action    = local.approval_key_management_actions
        Resource  = "*"
      },
      {
        Sid       = "IndependentHumanSignerRole"
        Effect    = "Allow"
        Principal = { AWS = var.witness_approver_role_arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "identitystore:UserId"           = var.witness_approver_user_id
            "identitystore:IdentityStoreArn" = var.witness_identity_store_arn
          }
        }
      },
      {
        Sid       = "RuntimeAndAuditorVerifyOnly"
        Effect    = "Allow"
        Principal = { AWS = concat([aws_iam_role.runtime.arn, aws_iam_role.witness_evidence_reader.arn], tolist(var.witness_evidence_auditor_role_arns)) }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]
        Resource  = "*"
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [terraform_data.invariants]
}

resource "aws_kms_alias" "witness_approval" {
  provider      = aws.witness
  name          = "alias/${var.name_prefix}-witness-approval"
  target_key_id = aws_kms_key.witness_approval.key_id
}

# Workload identity is exact IRSA: one issuer, audience, namespace, and
# ServiceAccount. It cannot sign any KMS payload, even if another policy grants
# the action later.
resource "aws_iam_role" "runtime" {
  name = local.runtime_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.eks_oidc_issuer_hostpath}:aud" = "sts.amazonaws.com"
          "${var.eks_oidc_issuer_hostpath}:sub" = local.irsa_subject
        }
      }
    }]
  })

  max_session_duration = 3600

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "runtime" {
  name = "${var.name_prefix}-fail-closed-runtime"
  role = aws_iam_role.runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "VerifyProductionApprovals"
          Effect   = "Allow"
          Action   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]
          Resource = [aws_kms_key.security_approval.arn, aws_kms_key.release_approval.arn, aws_kms_key.witness_approval.arn]
        },
        {
          Sid      = "NeverSignFromRuntime"
          Effect   = "Deny"
          Action   = "kms:Sign"
          Resource = "*"
        },
        {
          Sid    = "ReadExactEksControlState"
          Effect = "Allow"
          Action = ["eks:DescribeAddon", "eks:DescribeCluster"]
          Resource = [
            "arn:${data.aws_partition.current.partition}:eks:${var.aws_region}:${var.workload_account_id}:cluster/${var.eks_cluster_name}",
            "arn:${data.aws_partition.current.partition}:eks:${var.aws_region}:${var.workload_account_id}:addon/${var.eks_cluster_name}/vpc-cni/*",
          ]
        },
        {
          Sid      = "LookupProductionSigningEvidence"
          Effect   = "Allow"
          Action   = "cloudtrail:LookupEvents"
          Resource = "*"
        },
        {
          Sid      = "AssumeIndependentWitnessReader"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = aws_iam_role.witness_evidence_reader.arn
        }
      ],
      length(var.revocable_iam_user_arns) == 0 ? [] : [
        {
          Sid      = "DisableOnlyAllowlistedAccessKeys"
          Effect   = "Allow"
          Action   = ["iam:ListAccessKeys", "iam:UpdateAccessKey"]
          Resource = sort(tolist(var.revocable_iam_user_arns))
        }
      ],
      length(var.revocable_iam_role_arns) == 0 ? [] : [
        {
          Sid      = "RevokeOnlyAllowlistedRoleSessions"
          Effect   = "Allow"
          Action   = ["iam:GetRole", "iam:GetRolePolicy", "iam:PutRolePolicy"]
          Resource = sort(tolist(var.revocable_iam_role_arns))
        }
      ],
    )
  })
}

resource "aws_iam_role" "witness_evidence_reader" {
  provider = aws.witness
  name     = local.witness_reader_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.runtime.arn }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:RoleSessionName" = "safe-qa-evidence-reader"
        }
      }
    }]
  })

  max_session_duration = 3600

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "witness_evidence_reader" {
  provider = aws.witness
  name     = "${var.name_prefix}-witness-read-only"
  role     = aws_iam_role.witness_evidence_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LookupWitnessSigningEvidence"
        Effect   = "Allow"
        Action   = "cloudtrail:LookupEvents"
        Resource = "*"
      },
      {
        Sid      = "VerifyWitnessSignatures"
        Effect   = "Allow"
        Action   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]
        Resource = aws_kms_key.witness_approval.arn
      },
      {
        Sid      = "NeverSignFromWitnessReader"
        Effect   = "Deny"
        Action   = "kms:Sign"
        Resource = "*"
      }
    ]
  })
}

# Production CloudTrail: a validated, multi-region management-event trail is
# the durable source for KMS Sign attribution. LookupEvents remains useful for
# admission-time checks, while S3 holds the long-term evidence.
resource "aws_kms_key" "prod_trail" {
  description             = "Encrypt production approval CloudTrail evidence"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.workload_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.prod_trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = local.prod_trail_arn }
        }
      },
      {
        Sid       = "CloudWatchLogsEncrypt"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.workload_account_id}:log-group:/aws/cloudtrail/${local.prod_trail_name}"
          }
        }
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "prod_trail" {
  bucket        = local.prod_trail_bucket
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "prod_trail" {
  bucket                  = aws_s3_bucket.prod_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "prod_trail" {
  bucket = aws_s3_bucket.prod_trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_trail" {
  bucket = aws_s3_bucket.prod_trail.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.prod_trail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "prod_trail" {
  bucket = aws_s3_bucket.prod_trail.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_policy" "prod_trail" {
  bucket = aws_s3_bucket.prod_trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.prod_trail.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.prod_trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.prod_trail.arn}/AWSLogs/${var.workload_account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.prod_trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.prod_trail.arn, "${aws_s3_bucket.prod_trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_ownership_controls.prod_trail]
}

resource "aws_cloudwatch_log_group" "prod_trail" {
  name              = "/aws/cloudtrail/${local.prod_trail_name}"
  retention_in_days = var.cloudtrail_log_retention_days
  kms_key_id        = aws_kms_key.prod_trail.arn
  skip_destroy      = true
}

resource "aws_iam_role" "prod_trail_logs" {
  name = "${var.name_prefix}-prod-trail-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.prod_trail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "prod_trail_logs" {
  name = "${var.name_prefix}-prod-trail-logs"
  role = aws_iam_role.prod_trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.prod_trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "prod" {
  name                          = local.prod_trail_name
  s3_bucket_name                = aws_s3_bucket.prod_trail.id
  kms_key_id                    = aws_kms_key.prod_trail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.prod_trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.prod_trail_logs.arn
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }

  depends_on = [aws_s3_bucket_policy.prod_trail]

  lifecycle {
    prevent_destroy = true
  }
}

# Independent witness CloudTrail, encrypted and administered in the witness
# account. Its bucket grants read only to named external auditor roles and the
# narrowly trusted witness reader role.
resource "aws_kms_key" "witness_trail" {
  provider                = aws.witness
  description             = "Encrypt independent witness CloudTrail evidence"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WitnessAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.witness.partition}:iam::${var.witness_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.witness_trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = local.witness_trail_arn }
        }
      },
      {
        Sid       = "CloudWatchLogsEncrypt"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.witness_aws_region}.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.witness.partition}:logs:${var.witness_aws_region}:${var.witness_account_id}:log-group:/aws/cloudtrail/${local.witness_trail_name}"
          }
        }
      },
      {
        Sid       = "EvidenceReadersDecrypt"
        Effect    = "Allow"
        Principal = { AWS = concat([aws_iam_role.witness_evidence_reader.arn], tolist(var.witness_evidence_auditor_role_arns)) }
        Action    = ["kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "witness_trail" {
  provider      = aws.witness
  bucket        = local.witness_trail_bucket
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "witness_trail" {
  provider                = aws.witness
  bucket                  = aws_s3_bucket.witness_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "witness_trail" {
  provider = aws.witness
  bucket   = aws_s3_bucket.witness_trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "witness_trail" {
  provider = aws.witness
  bucket   = aws_s3_bucket.witness_trail.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.witness_trail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "witness_trail" {
  provider = aws.witness
  bucket   = aws_s3_bucket.witness_trail.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_policy" "witness_trail" {
  provider = aws.witness
  bucket   = aws_s3_bucket.witness_trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.witness_trail.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.witness_trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.witness_trail.arn}/AWSLogs/${var.witness_account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.witness_trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "NamedEvidenceReaders"
        Effect    = "Allow"
        Principal = { AWS = concat([aws_iam_role.witness_evidence_reader.arn], tolist(var.witness_evidence_auditor_role_arns)) }
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = "${aws_s3_bucket.witness_trail.arn}/AWSLogs/${var.witness_account_id}/*"
      },
      {
        Sid       = "NamedEvidenceReadersListExactPrefix"
        Effect    = "Allow"
        Principal = { AWS = concat([aws_iam_role.witness_evidence_reader.arn], tolist(var.witness_evidence_auditor_role_arns)) }
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.witness_trail.arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["AWSLogs/${var.witness_account_id}/*"]
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.witness_trail.arn, "${aws_s3_bucket.witness_trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_ownership_controls.witness_trail]
}

resource "aws_cloudwatch_log_group" "witness_trail" {
  provider          = aws.witness
  name              = "/aws/cloudtrail/${local.witness_trail_name}"
  retention_in_days = var.cloudtrail_log_retention_days
  kms_key_id        = aws_kms_key.witness_trail.arn
  skip_destroy      = true
}

resource "aws_iam_role" "witness_trail_logs" {
  provider = aws.witness
  name     = "${var.name_prefix}-witness-trail-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.witness_trail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "witness_trail_logs" {
  provider = aws.witness
  name     = "${var.name_prefix}-witness-trail-logs"
  role     = aws_iam_role.witness_trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.witness_trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "witness" {
  provider                      = aws.witness
  name                          = local.witness_trail_name
  s3_bucket_name                = aws_s3_bucket.witness_trail.id
  kms_key_id                    = aws_kms_key.witness_trail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.witness_trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.witness_trail_logs.arn
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }

  depends_on = [aws_s3_bucket_policy.witness_trail]

  lifecycle {
    prevent_destroy = true
  }
}
