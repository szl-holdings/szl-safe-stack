# Production-provider mutation boundary.
#
# IMPORTANT: Change Manager stopped onboarding new customers on 2025-11-07.
# The default is therefore a hard deny.  Setting the opt-in variable to true is
# an operator attestation that this exact AWS account was already enrolled and
# that the numerically versioned template was independently reviewed in AWS.

variable "provider_gate_change_manager_existing_customer_confirmed" {
  description = "True only after live confirmation that workload_account_id was enrolled in Change Manager before AWS closed new-customer access. False installs a fail-closed runtime deny and creates no gate resources."
  type        = bool
  default     = false
  nullable    = false
}

variable "provider_gate_witness_external_id" {
  description = "Exact external ID required when the witness-account approver assumes the workload-account witness bridge role. Required only when the provider gate is enabled."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
}

variable "provider_gate_approval_timeout_seconds" {
  description = "Timeout for each of the three sequential Change Manager approval levels."
  type        = number
  default     = 604800
  nullable    = false

  validation {
    condition     = var.provider_gate_approval_timeout_seconds >= 3600 && var.provider_gate_approval_timeout_seconds <= 2592000
    error_message = "provider_gate_approval_timeout_seconds must be between one hour and the aws:approve 30-day maximum."
  }
}

variable "provider_gate_eks_deployment_targets" {
  description = "Exact namespace/deployment/container targets and immutable-image repository prefixes the approved Automation may mutate."
  type = set(object({
    namespace               = string
    deployment_name         = string
    container_name          = string
    image_repository_prefix = string
  }))
  default  = []
  nullable = false

  validation {
    condition = alltrue([
      for target in var.provider_gate_eks_deployment_targets :
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", target.namespace)) &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", target.deployment_name)) &&
      can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", target.container_name)) &&
      length(target.image_repository_prefix) >= 3 &&
      length(target.image_repository_prefix) <= 512 &&
      !strcontains(target.image_repository_prefix, "@") &&
      !strcontains(target.image_repository_prefix, "*")
    ])
    error_message = "Provider-gate EKS targets require DNS-label names and literal, non-wildcard repository prefixes without digests."
  }
}

variable "provider_gate_isolation_namespaces" {
  description = "Exact emergency-isolation namespaces. This reference permits only the dedicated agent sandbox."
  type        = set(string)
  default     = ["safe-qa-agent-sandbox"]
  nullable    = false

  validation {
    condition     = var.provider_gate_isolation_namespaces == toset(["safe-qa-agent-sandbox"])
    error_message = "provider_gate_isolation_namespaces must remain exactly safe-qa-agent-sandbox."
  }
}

locals {
  provider_gate_enabled               = var.provider_gate_change_manager_existing_customer_confirmed
  provider_gate_runbook_name          = "${var.name_prefix}-provider-mutation"
  provider_gate_template_name         = "${var.name_prefix}-provider-change"
  provider_gate_group                 = "safe-qa-provider-gate"
  provider_gate_execution_arn_pattern = "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.workload_account_id}:automation-execution/*"
  provider_gate_deployment_map = {
    for target in var.provider_gate_eks_deployment_targets :
    "${target.namespace}/${target.deployment_name}/${target.container_name}" => target.image_repository_prefix
  }
  provider_gate_mutation_actions = [
    "iam:PutRolePolicy",
    "iam:UpdateAccessKey",
  ]
}

data "aws_eks_cluster" "provider_gate" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = var.eks_cluster_name
}

resource "terraform_data" "provider_gate_invariants" {
  count = local.provider_gate_enabled ? 1 : 0

  input = {
    account_id           = data.aws_caller_identity.workload.account_id
    cluster_name         = var.eks_cluster_name
    deployment_targets   = local.provider_gate_deployment_map
    isolation_namespaces = sort(tolist(var.provider_gate_isolation_namespaces))
  }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.workload.account_id == var.workload_account_id
      error_message = "The provider gate must be created in workload_account_id."
    }
    precondition {
      condition     = var.provider_gate_witness_external_id != null && length(var.provider_gate_witness_external_id) >= 32 && length(var.provider_gate_witness_external_id) <= 1224
      error_message = "An exact 32-1224 character witness external ID is required when the provider gate is enabled."
    }
    precondition {
      condition     = length(var.provider_gate_eks_deployment_targets) > 0
      error_message = "At least one exact EKS deployment target is required when the provider gate is enabled."
    }
    precondition {
      condition = contains(
        ["API", "API_AND_CONFIG_MAP"],
        data.aws_eks_cluster.provider_gate[0].access_config[0].authentication_mode,
      )
      error_message = "EKS authentication mode must support access entries (API or API_AND_CONFIG_MAP)."
    }
  }
}

# Runtime guardrails exist even when Change Manager is unavailable.  The
# aws:CalledVia conditions are defense in depth for forward-access sessions:
# direct requests have no CalledVia value and are denied.  The Automation
# execution role below is a service role, so its enforcement is instead the
# exact SSM trust policy plus the requester's exact PassRole grant.
resource "aws_iam_role_policy" "runtime_provider_gate_guard" {
  name = "${var.name_prefix}-provider-gate-guard"
  role = aws_iam_role.runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "DenyDirectProviderMutation"
          Effect   = "Deny"
          Action   = local.provider_gate_mutation_actions
          Resource = "*"
          Condition = {
            Null = { "aws:CalledVia" = "true" }
          }
        },
        {
          Sid      = "DenyProviderMutationViaUnexpectedService"
          Effect   = "Deny"
          Action   = local.provider_gate_mutation_actions
          Resource = "*"
          Condition = {
            Null = { "aws:CalledVia" = "false" }
            "ForAllValues:StringNotEquals" = {
              "aws:CalledVia" = "ssm.amazonaws.com"
            }
          }
        },
        {
          Sid    = "DenyDirectAutomationAndGateDocumentMutation"
          Effect = "Deny"
          Action = [
            "ssm:CreateDocument",
            "ssm:DeleteDocument",
            "ssm:ModifyDocumentPermission",
            "ssm:StartAutomationExecution",
            "ssm:UpdateDocument",
            "ssm:UpdateDocumentDefaultVersion",
            "ssm:UpdateDocumentMetadata",
          ]
          Resource = "*"
        },
        {
          Sid    = "DenyEksPrivilegeEscalation"
          Effect = "Deny"
          Action = [
            "eks:AssociateAccessPolicy",
            "eks:CreateAccessEntry",
            "eks:DeleteAccessEntry",
            "eks:DisassociateAccessPolicy",
            "eks:UpdateAccessEntry",
            "eks:UpdateClusterConfig",
          ]
          Resource = "*"
        },
      ],
      local.provider_gate_enabled ? [
        {
          Sid         = "DenyPassingAnyOtherRole"
          Effect      = "Deny"
          Action      = "iam:PassRole"
          NotResource = aws_iam_role.provider_gate_execution[0].arn
        },
      ] : [],
      local.provider_gate_enabled ? [
        {
          Sid      = "DenyPassingGateRoleToOtherServices"
          Effect   = "Deny"
          Action   = "iam:PassRole"
          Resource = aws_iam_role.provider_gate_execution[0].arn
          Condition = {
            StringNotEqualsIfExists = {
              "iam:PassedToService" = "ssm.amazonaws.com"
            }
          }
        },
      ] : [],
      local.provider_gate_enabled ? [] : [
        {
          Sid      = "DenyUnavailableChangeManagerAndPassRole"
          Effect   = "Deny"
          Action   = ["iam:PassRole", "ssm:StartChangeRequestExecution"]
          Resource = "*"
        },
      ],
    )
  })
}

resource "aws_sns_topic" "provider_gate_approvals" {
  count             = local.provider_gate_enabled ? 1 : 0
  name              = "Automation-${var.name_prefix}-provider-gate"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "provider_gate_approvals" {
  count = local.provider_gate_enabled ? 1 : 0
  arn   = aws_sns_topic.provider_gate_approvals[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OnlySystemsManagerAutomationMayPublish"
        Effect    = "Allow"
        Principal = { Service = "ssm.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.provider_gate_approvals[0].arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.workload_account_id }
          ArnLike      = { "aws:SourceArn" = local.provider_gate_execution_arn_pattern }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:*"
        Resource  = aws_sns_topic.provider_gate_approvals[0].arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

resource "aws_iam_role" "provider_gate_execution" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-pg-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.workload_account_id }
        ArnLike      = { "aws:SourceArn" = local.provider_gate_execution_arn_pattern }
      }
    }]
  })

  max_session_duration = 3600

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [terraform_data.provider_gate_invariants]
}

resource "aws_iam_role_policy" "provider_gate_execution" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-pg-exact-mutations"
  role  = aws_iam_role.provider_gate_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "ReadExactClusterForKubernetesApi"
          Effect = "Allow"
          Action = ["eks:DescribeAddon", "eks:DescribeCluster"]
          Resource = [
            "arn:${data.aws_partition.current.partition}:eks:${var.aws_region}:${var.workload_account_id}:cluster/${var.eks_cluster_name}",
            "arn:${data.aws_partition.current.partition}:eks:${var.aws_region}:${var.workload_account_id}:addon/${var.eks_cluster_name}/vpc-cni/*",
          ]
        },
        {
          Sid    = "DenyPrivilegeDelegationAndGateBypass"
          Effect = "Deny"
          Action = [
            "iam:PassRole",
            "kms:Sign",
            "ssm:CreateDocument",
            "ssm:StartAutomationExecution",
            "ssm:StartChangeRequestExecution",
            "ssm:UpdateDocument*",
            "sts:AssumeRole",
          ]
          Resource = "*"
        },
      ],
      length(var.revocable_iam_user_arns) == 0 ? [] : [
        {
          Sid      = "DisableOnlyAllowlistedUserKeys"
          Effect   = "Allow"
          Action   = ["iam:GetUser", "iam:ListAccessKeys", "iam:UpdateAccessKey"]
          Resource = sort(tolist(var.revocable_iam_user_arns))
        },
      ],
      length(var.revocable_iam_role_arns) == 0 ? [] : [
        {
          Sid      = "RevokeOnlyAllowlistedRoleSessions"
          Effect   = "Allow"
          Action   = ["iam:GetRole", "iam:GetRolePolicy", "iam:PutRolePolicy"]
          Resource = sort(tolist(var.revocable_iam_role_arns))
        },
      ],
    )
  })
}

# Three local bridge roles are the exact Change Manager approvers.  Their trust
# policies bind the already-configured human roles and Identity Center context;
# the witness bridge additionally crosses the independently administered
# witness account and requires an external ID.
resource "aws_iam_role" "provider_gate_security_approver" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-pg-security"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.security_approver_role_arn }
      Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
      Condition = {
        StringEquals = {
          "identitystore:IdentityStoreArn" = var.security_identity_store_arn
          "identitystore:UserId"           = var.security_approver_user_id
          "sts:SourceIdentity"             = var.security_approver_user_id
        }
      }
    }]
  })

  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role" "provider_gate_release_approver" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-pg-release"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.release_approver_role_arn }
      Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
      Condition = {
        StringEquals = {
          "identitystore:IdentityStoreArn" = var.release_identity_store_arn
          "identitystore:UserId"           = var.release_approver_user_id
          "sts:SourceIdentity"             = var.release_approver_user_id
        }
      }
    }]
  })

  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role" "provider_gate_witness_approver" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-pg-witness"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.witness_approver_role_arn }
      Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
      Condition = {
        StringEquals = {
          "identitystore:IdentityStoreArn" = var.witness_identity_store_arn
          "identitystore:UserId"           = var.witness_approver_user_id
          "sts:ExternalId"                 = var.provider_gate_witness_external_id
          "sts:SourceIdentity"             = var.witness_approver_user_id
        }
      }
    }]
  })

  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
}

resource "aws_eks_access_entry" "provider_gate" {
  count             = local.provider_gate_enabled ? 1 : 0
  cluster_name      = var.eks_cluster_name
  principal_arn     = aws_iam_role.provider_gate_execution[0].arn
  kubernetes_groups = [local.provider_gate_group]
  type              = "STANDARD"

  depends_on = [terraform_data.provider_gate_invariants]
}

resource "aws_ssm_document" "provider_gate_runbook" {
  count           = local.provider_gate_enabled ? 1 : 0
  name            = local.provider_gate_runbook_name
  document_type   = "Automation"
  document_format = "JSON"

  content = jsonencode({
    description   = "Execute one exact, hash-bound Safe QA provider mutation after Change Manager approval."
    schemaVersion = "0.3"
    assumeRole    = aws_iam_role.provider_gate_execution[0].arn
    parameters = {
      ChangeEnvelopeJson = {
        type        = "String"
        description = "Canonical safe-qa-provider-change/v1 envelope containing one plan action and its signed preview."
      }
      ChangeEnvelopeSha256 = {
        type           = "String"
        description    = "Lowercase SHA-256 of the canonical change envelope."
        allowedPattern = "^[0-9a-f]{64}$"
      }
    }
    mainSteps = [{
      name           = "executeExactProviderMutation"
      action         = "aws:executeScript"
      timeoutSeconds = 600
      onFailure      = "Abort"
      isCritical     = true
      inputs = {
        Runtime = "python3.12"
        Handler = "execute"
        Script  = file("${path.module}/provider-gate-handler.py")
        InputPayload = {
          change_envelope_json         = "{{ ChangeEnvelopeJson }}"
          change_envelope_sha256       = "{{ ChangeEnvelopeSha256 }}"
          account_id                   = var.workload_account_id
          region                       = var.aws_region
          partition                    = data.aws_partition.current.partition
          controller_principal_arn     = aws_iam_role.runtime.arn
          automation_role_arn          = aws_iam_role.provider_gate_execution[0].arn
          cluster_name                 = var.eks_cluster_name
          allowed_eks_deployments      = local.provider_gate_deployment_map
          allowed_isolation_namespaces = sort(tolist(var.provider_gate_isolation_namespaces))
          allowed_user_arns            = sort(tolist(var.revocable_iam_user_arns))
          allowed_role_arns            = sort(tolist(var.revocable_iam_role_arns))
        }
      }
      outputs = [{
        Name     = "ReceiptJson"
        Selector = "$.Payload.receipt_json"
        Type     = "String"
      }]
    }]
    outputs = ["executeExactProviderMutation.ReceiptJson"]
  })

  tags = merge(local.common_tags, {
    ProviderGate = "exact-provider-mutation"
    AutoApprove  = "forbidden"
  })

  lifecycle {
    prevent_destroy = true
    postcondition {
      condition     = can(regex("^[1-9][0-9]*$", self.document_version))
      error_message = "The provider-gate runbook did not receive a numeric document version."
    }
  }
}

resource "aws_ssm_document" "provider_gate_change_template" {
  count           = local.provider_gate_enabled ? 1 : 0
  name            = local.provider_gate_template_name
  document_type   = "Automation.ChangeTemplate"
  document_format = "JSON"

  content = jsonencode({
    description         = "Three-level, non-emergency, non-auto-approvable gate for one exact Safe QA provider mutation."
    templateInformation = <<-EOT
      # Safe QA exact provider change

      Review the complete canonical `ChangeEnvelopeJson` and its SHA-256. The
      envelope must contain exactly one provider action and the immutable
      provider preview already covered by the detached approval bundle.

      This template does not validate clinical or biological claims. Those
      remain explicitly unverified and are outside this infrastructure gate.
    EOT
    schemaVersion       = "0.3"
    emergencyChange     = false
    autoApprovable      = false
    parameters = {
      ChangeEnvelopeJson = {
        type        = "String"
        description = "Canonical safe-qa-provider-change/v1 envelope."
      }
      ChangeEnvelopeSha256 = {
        type           = "String"
        description    = "Lowercase SHA-256 of the canonical change envelope."
        allowedPattern = "^[0-9a-f]{64}$"
      }
    }
    executableRunBooks = [{
      name    = aws_ssm_document.provider_gate_runbook[0].name
      version = aws_ssm_document.provider_gate_runbook[0].document_version
    }]
    mainSteps = [
      {
        name           = "SecurityOwnerApproval"
        action         = "aws:approve"
        timeoutSeconds = var.provider_gate_approval_timeout_seconds
        inputs = {
          Message              = "Security owner: review the exact canonical envelope, target, preview, digest, expiry, and rollback plan."
          MinRequiredApprovals = 1
          EnhancedApprovals = {
            NotificationArn = aws_sns_topic.provider_gate_approvals[0].arn
            Approvers = [{
              approver             = aws_iam_role.provider_gate_security_approver[0].arn
              type                 = "IamRole"
              minRequiredApprovals = 0
            }]
          }
        }
      },
      {
        name           = "ReleaseOwnerApproval"
        action         = "aws:approve"
        timeoutSeconds = var.provider_gate_approval_timeout_seconds
        inputs = {
          Message              = "Release owner: verify the exact source revision, immutable image digest, environment, and provider action."
          MinRequiredApprovals = 1
          EnhancedApprovals = {
            NotificationArn = aws_sns_topic.provider_gate_approvals[0].arn
            Approvers = [{
              approver             = aws_iam_role.provider_gate_release_approver[0].arn
              type                 = "IamRole"
              minRequiredApprovals = 0
            }]
          }
        }
      },
      {
        name           = "IndependentWitnessApproval"
        action         = "aws:approve"
        timeoutSeconds = var.provider_gate_approval_timeout_seconds
        inputs = {
          Message              = "Independent witness: attest only that the named evidence and approval records were observed; do not infer clinical or biological validity."
          MinRequiredApprovals = 1
          EnhancedApprovals = {
            NotificationArn = aws_sns_topic.provider_gate_approvals[0].arn
            Approvers = [{
              approver             = aws_iam_role.provider_gate_witness_approver[0].arn
              type                 = "IamRole"
              minRequiredApprovals = 0
            }]
          }
        }
      },
    ]
  })

  tags = merge(local.common_tags, {
    ProviderGate = "three-fixed-levels"
    AutoApprove  = "forbidden"
  })

  lifecycle {
    prevent_destroy = true
    postcondition {
      condition     = can(regex("^[1-9][0-9]*$", self.document_version))
      error_message = "The provider-gate change template did not receive a numeric document version."
    }
  }
}

resource "aws_iam_role_policy" "runtime_provider_gate_requester" {
  count = local.provider_gate_enabled ? 1 : 0
  name  = "${var.name_prefix}-provider-gate-requester"
  role  = aws_iam_role.runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StartOnlyExactReviewedChangeTemplateVersion"
        Effect = "Allow"
        Action = "ssm:StartChangeRequestExecution"
        Resource = [
          aws_ssm_document.provider_gate_change_template[0].arn,
          "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.workload_account_id}:automation-definition/${aws_ssm_document.provider_gate_change_template[0].name}:${aws_ssm_document.provider_gate_change_template[0].document_version}",
          local.provider_gate_execution_arn_pattern,
        ]
        Condition = {
          Bool = { "ssm:AutoApprove" = "false" }
          StringEquals = {
            "aws:RequestTag/safe-qa:provider-gate" = "true"
            "ssm:DocumentType"                     = "Automation.ChangeTemplate"
            "ssm:DocumentVersion"                  = aws_ssm_document.provider_gate_change_template[0].document_version
          }
        }
      },
      {
        Sid      = "PassOnlyExactAutomationRoleToSystemsManager"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.provider_gate_execution[0].arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "ssm.amazonaws.com" }
        }
      },
      {
        Sid    = "ReadExactGateDocuments"
        Effect = "Allow"
        Action = ["ssm:DescribeDocument", "ssm:GetDocument"]
        Resource = [
          aws_ssm_document.provider_gate_runbook[0].arn,
          aws_ssm_document.provider_gate_change_template[0].arn,
        ]
        Condition = {
          StringEquals = {
            "ssm:DocumentVersion" = [
              aws_ssm_document.provider_gate_runbook[0].document_version,
              aws_ssm_document.provider_gate_change_template[0].document_version,
            ]
          }
        }
      },
      {
        Sid      = "ReadTaggedGateExecution"
        Effect   = "Allow"
        Action   = "ssm:GetAutomationExecution"
        Resource = local.provider_gate_execution_arn_pattern
        Condition = {
          StringEquals = { "aws:ResourceTag/safe-qa:provider-gate" = "true" }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "provider_gate_approver" {
  for_each = local.provider_gate_enabled ? {
    security = aws_iam_role.provider_gate_security_approver[0].id
    release  = aws_iam_role.provider_gate_release_approver[0].id
    witness  = aws_iam_role.provider_gate_witness_approver[0].id
  } : {}

  name = "${var.name_prefix}-provider-gate-${each.key}-approval"
  role = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ApproveOnlyTaggedProviderGateExecutions"
        Effect   = "Allow"
        Action   = ["ssm:GetAutomationExecution", "ssm:SendAutomationSignal"]
        Resource = local.provider_gate_execution_arn_pattern
        Condition = {
          StringEquals = { "aws:ResourceTag/safe-qa:provider-gate" = "true" }
        }
      },
      {
        Sid      = "ReadOnlyExactChangeTemplateVersion"
        Effect   = "Allow"
        Action   = ["ssm:DescribeDocument", "ssm:GetDocument"]
        Resource = aws_ssm_document.provider_gate_change_template[0].arn
        Condition = {
          StringEquals = {
            "ssm:DocumentVersion" = aws_ssm_document.provider_gate_change_template[0].document_version
          }
        }
      },
    ]
  })
}

output "provider_gate_mode" {
  description = "DECLARED_CHANGE_MANAGER_GATE only means Terraform declared the gate; it is not apply, template-review, approval, execution, or deployment evidence."
  value       = local.provider_gate_enabled ? "DECLARED_CHANGE_MANAGER_GATE" : "FAILED_CLOSED_CHANGE_MANAGER_UNAVAILABLE_OR_UNCONFIRMED"
}

output "provider_gate_numeric_versions" {
  description = "Numerically pinned document versions, or null while the fail-closed fallback is selected."
  value = local.provider_gate_enabled ? {
    change_template = aws_ssm_document.provider_gate_change_template[0].document_version
    runbook         = aws_ssm_document.provider_gate_runbook[0].document_version
  } : null
}
