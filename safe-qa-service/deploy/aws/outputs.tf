output "runtime_role_arn" {
  description = "IRSA workload role. Render this exact value into kubernetes-v2.yaml."
  value       = aws_iam_role.runtime.arn
}

output "approval_key_arns" {
  description = "Exact asymmetric KMS keys the verifier must pin by approval role."
  value = {
    SECURITY_OWNER = aws_kms_key.security_approval.arn
    RELEASE_OWNER  = aws_kms_key.release_approval.arn
    WITNESS        = aws_kms_key.witness_approval.arn
  }
}

output "witness_evidence_reader_role_arn" {
  description = "Role the runtime assumes only while validating witness-account CloudTrail events."
  value       = aws_iam_role.witness_evidence_reader.arn
}

output "cloudtrail_evidence" {
  description = "Trails and durable buckets. A created trail is not evidence until status and signed digest files are read back."
  value = {
    production = {
      trail_arn   = aws_cloudtrail.prod.arn
      bucket_name = aws_s3_bucket.prod_trail.id
    }
    witness = {
      trail_arn   = aws_cloudtrail.witness.arn
      bucket_name = aws_s3_bucket.witness_trail.id
    }
  }
}

output "network_firewall" {
  description = "Firewall identifiers for post-apply route and logging readback."
  value = {
    arn              = aws_networkfirewall_firewall.egress.arn
    policy_arn       = aws_networkfirewall_firewall_policy.strict_egress.arn
    rule_group_arn   = aws_networkfirewall_rule_group.strict_egress.arn
    protected_routes = { for name, route in aws_route.through_firewall : name => route.id }
  }
}

output "eks_network_policy_addon" {
  description = "Exact managed add-on revision requested by this state. Verify live health independently after apply."
  value = {
    cluster       = aws_eks_addon.vpc_cni.cluster_name
    addon_version = aws_eks_addon.vpc_cni.addon_version
  }
}

output "agent_sandbox_node_group" {
  description = "Dedicated tainted EC2 Linux managed node group. It is not isolation evidence until strict-policy-agent and network negative tests pass."
  value = {
    arn                = aws_eks_node_group.agent_sandbox.arn
    namespace          = var.sandbox_namespace
    node_role          = aws_iam_role.sandbox_node.arn
    security_group_id  = aws_security_group.sandbox_node.id
    launch_template_id = aws_launch_template.sandbox_node.id
    required_pod_label = "safe-qa.io/runtime=ec2-network-policy-sandbox"
    required_taint     = "safe-qa.io/agent-sandbox=true:NoSchedule"
    route_associations = { for name, association in aws_route_table_association.sandbox_node : name => association.id }
    flow_log_ids       = { for name, flow_log in aws_flow_log.sandbox_node : name => flow_log.id }
  }
}
