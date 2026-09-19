variable "aws_region" {
  description = "AWS Region containing EKS and the production control plane."
  type        = string
  nullable    = false
}

variable "witness_aws_region" {
  description = "AWS Region used by the independent witness account."
  type        = string
  nullable    = false
}

variable "workload_account_id" {
  description = "Twelve-digit AWS account ID containing EKS and the runtime role."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.workload_account_id))
    error_message = "workload_account_id must be a twelve-digit AWS account ID."
  }
}

variable "witness_account_id" {
  description = "Twelve-digit, independently administered AWS account ID for the witness."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.witness_account_id))
    error_message = "witness_account_id must be a twelve-digit AWS account ID."
  }
}

variable "workload_deployer_role_arn" {
  description = "Existing deployment role assumed in the workload account."
  type        = string
  nullable    = false
}

variable "witness_deployer_role_arn" {
  description = "Existing deployment role assumed in the independently administered witness account."
  type        = string
  nullable    = false
}

variable "security_approver_role_arn" {
  description = "Existing federated human role allowed to sign only SECURITY_OWNER approvals."
  type        = string
  nullable    = false
}

variable "release_approver_role_arn" {
  description = "Existing federated human role allowed to sign only RELEASE_OWNER approvals."
  type        = string
  nullable    = false
}

variable "witness_approver_role_arn" {
  description = "Existing federated human role in the witness account allowed to sign witness statements."
  type        = string
  nullable    = false
}

variable "security_approver_user_id" {
  description = "Exact IAM Identity Center UserId required in the security signer's identity-enhanced role session."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$", var.security_approver_user_id))
    error_message = "security_approver_user_id must be a UUID or ten-lowercase-hex-prefix plus UUID."
  }
}

variable "security_identity_store_arn" {
  description = "Exact IdentityStoreArn required in the security signer's identity context."
  type        = string
  nullable    = false
}

variable "release_approver_user_id" {
  description = "Exact IAM Identity Center UserId required in the release signer's identity-enhanced role session."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$", var.release_approver_user_id))
    error_message = "release_approver_user_id must be a UUID or ten-lowercase-hex-prefix plus UUID."
  }
}

variable "release_identity_store_arn" {
  description = "Exact IdentityStoreArn required in the release signer's identity context."
  type        = string
  nullable    = false
}

variable "witness_approver_user_id" {
  description = "Exact IAM Identity Center UserId required in the witness signer's identity-enhanced role session."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$", var.witness_approver_user_id))
    error_message = "witness_approver_user_id must be a UUID or ten-lowercase-hex-prefix plus UUID."
  }
}

variable "witness_identity_store_arn" {
  description = "Exact witness-account IdentityStoreArn required in the witness signer's identity context."
  type        = string
  nullable    = false
}

variable "witness_evidence_auditor_role_arns" {
  description = "Existing third-party auditor role ARNs in the witness account that may read witness trail objects and verify signatures."
  type        = set(string)
  nullable    = false

  validation {
    condition     = length(var.witness_evidence_auditor_role_arns) > 0
    error_message = "At least one named third-party auditor role ARN is required."
  }
}

variable "eks_cluster_name" {
  description = "Exact existing EKS cluster name. Import the VPC CNI add-on if Terraform does not already own it."
  type        = string
  nullable    = false
}

variable "eks_cluster_security_group_id" {
  description = "Exact EKS cluster security group ID used only for node/API security-group references."
  type        = string
  nullable    = false
}

variable "vpc_cni_addon_version" {
  description = "Exact EKS-compatible VPC CNI add-on version selected through the provider compatibility matrix."
  type        = string
  nullable    = false
}

variable "vpc_cni_service_account_role_arn" {
  description = "Exact dedicated IRSA role ARN used by aws-node; keeps CNI permissions off the sandbox node role."
  type        = string
  nullable    = false
}

variable "eks_oidc_provider_arn" {
  description = "Exact IAM OIDC provider ARN for the EKS cluster."
  type        = string
  nullable    = false
}

variable "eks_oidc_issuer_hostpath" {
  description = "EKS OIDC issuer without https://, used in IRSA trust conditions."
  type        = string
  nullable    = false

  validation {
    condition     = !startswith(var.eks_oidc_issuer_hostpath, "http")
    error_message = "eks_oidc_issuer_hostpath must omit the URL scheme."
  }
}

variable "workload_namespace" {
  description = "Kubernetes namespace running the production control-plane workload."
  type        = string
  nullable    = false
}

variable "workload_service_account" {
  description = "Kubernetes ServiceAccount bound to the runtime IAM role."
  type        = string
  nullable    = false
}

variable "sandbox_namespace" {
  description = "Dedicated namespace for tokenless agent sandbox Jobs on the exclusive EC2 managed node group."
  type        = string
  default     = "safe-qa-agent-sandbox"

  validation {
    condition     = var.sandbox_namespace == "safe-qa-agent-sandbox"
    error_message = "This reference pins the sandbox boundary to safe-qa-agent-sandbox."
  }
}

variable "sandbox_node_subnets" {
  description = "Exact private subnet, route table, and Availability Zone tuples used only by the sandbox managed node group."
  type = map(object({
    subnet_id         = string
    route_table_id    = string
    availability_zone = string
  }))
  nullable = false

  validation {
    condition     = length(var.sandbox_node_subnets) >= 2
    error_message = "At least two exact private sandbox-node subnet tuples are required."
  }
}

variable "sandbox_node_instance_types" {
  description = "Reviewed x86-64 EC2 instance types permitted for the sandbox node group."
  type        = set(string)
  nullable    = false

  validation {
    condition     = length(var.sandbox_node_instance_types) > 0
    error_message = "At least one exact sandbox-node EC2 instance type is required."
  }
}

variable "sandbox_node_egress_rules" {
  description = "Exact private IPv4 egress rules required by managed nodes for EKS API, registry, DNS, time, and reviewed endpoints. No default route is permitted here."
  type = map(object({
    description = string
    cidr_ipv4   = string
    from_port   = number
    to_port     = number
    ip_protocol = string
  }))
  nullable = false

  validation {
    condition = length(var.sandbox_node_egress_rules) > 0 && alltrue([
      for rule in var.sandbox_node_egress_rules :
      can(cidrnetmask(rule.cidr_ipv4)) &&
      rule.cidr_ipv4 != "0.0.0.0/0" &&
      contains(["tcp", "udp"], lower(rule.ip_protocol)) &&
      rule.from_port >= 1 &&
      rule.to_port <= 65535 &&
      rule.from_port <= rule.to_port
    ])
    error_message = "Sandbox node egress rules require exact non-default IPv4 CIDRs, tcp/udp, and an ordered 1-65535 port range."
  }
}

variable "sandbox_root_volume_size_gib" {
  description = "Encrypted gp3 root-volume size for each sandbox node."
  type        = number
  default     = 40

  validation {
    condition     = var.sandbox_root_volume_size_gib >= 20 && var.sandbox_root_volume_size_gib <= 200
    error_message = "sandbox_root_volume_size_gib must be between 20 and 200 GiB."
  }
}

variable "sandbox_node_min_size" {
  description = "Minimum always-ready sandbox nodes; at least one is required for policy-agent readiness checks before Jobs activate."
  type        = number
  default     = 1
}

variable "sandbox_node_desired_size" {
  description = "Desired sandbox node count."
  type        = number
  default     = 1
}

variable "sandbox_node_max_size" {
  description = "Hard maximum sandbox node count."
  type        = number
  default     = 3
}

variable "vpc_id" {
  description = "Exact VPC ID containing the EKS cluster and Network Firewall."
  type        = string
  nullable    = false
}

variable "firewall_subnet_ids" {
  description = "Dedicated Network Firewall subnet IDs, exactly one per protected Availability Zone."
  type        = set(string)
  nullable    = false

  validation {
    condition     = length(var.firewall_subnet_ids) >= 2
    error_message = "At least two dedicated firewall subnets are required."
  }
}

variable "protected_routes" {
  description = "Exact routes that must be steered to the firewall endpoint in the route table's Availability Zone."
  type = map(object({
    route_table_id         = string
    destination_cidr_block = string
    availability_zone      = string
  }))
  nullable = false

  validation {
    condition     = length(var.protected_routes) > 0
    error_message = "protected_routes must contain every route that the design requires Terraform to enforce."
  }
}

variable "network_firewall_capacity" {
  description = "Capacity reserved for the supplied strict-order Suricata rule group."
  type        = number
  nullable    = false

  validation {
    condition     = var.network_firewall_capacity >= 100
    error_message = "network_firewall_capacity must be at least 100."
  }
}

variable "suricata_rules" {
  description = "Reviewed strict-order Suricata rules. The final rule must fail closed for traffic not explicitly allowed."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.suricata_rules)) > 0
    error_message = "suricata_rules cannot be empty."
  }
}

variable "revocable_iam_user_arns" {
  description = "Exact IAM user ARN allowlist whose access keys the runtime may set Inactive. Empty disables that action."
  type        = set(string)
  default     = []
}

variable "revocable_iam_role_arns" {
  description = "Exact IAM role ARN allowlist on which the runtime may install AWSRevokeOlderSessions. Empty disables that action."
  type        = set(string)
  default     = []
}

variable "cloudtrail_log_retention_days" {
  description = "CloudWatch retention for operational CloudTrail copies. S3 trails remain the durable evidence source."
  type        = number
  default     = 365
}

variable "name_prefix" {
  description = "Lowercase name prefix for resources; choose a globally distinguishable value for S3 bucket names."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,31}$", var.name_prefix))
    error_message = "name_prefix must be 3-32 lowercase letters, digits, or hyphens."
  }
}

variable "tags" {
  description = "Additional organization tags."
  type        = map(string)
  default     = {}
}
