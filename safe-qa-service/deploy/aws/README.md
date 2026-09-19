# AWS/EKS production reference

This directory is an unapplied, fail-closed Terraform reference. It creates no
credentials and contains no account IDs, ARNs, routes, permitted destinations,
or human identities. Every such value is a required operator input.

It provisions:

- EKS VPC CNI network-policy support in `strict` enforcement mode;
- a dedicated tainted and labeled EKS managed EC2 Linux node group for
  `safe-qa-agent-sandbox`; nodes use private firewall-steered subnets, IMDSv2
  with hop limit 1, encrypted root storage, and bounded autoscaling;
- provider-owned subnet-to-route-table associations, a dedicated
  deny-by-default node security group, and per-subnet VPC Flow Logs;
- a tokenless sandbox ServiceAccount with no IRSA or RBAC, distinct from the
  privileged control-plane workload;
- a distinct tokenless, RBAC-free, zero-network managed Deployment as the only
  rollout target, so the control API cannot patch or terminate itself before
  terminal evidence is persisted;
- AWS Network Firewall with caller-supplied strict-order Suricata rules and
  exact Availability Zone route steering, `aws:drop_strict` unmatched state,
  and a required final catch-all drop/reject rule;
- distinct asymmetric KMS `SIGN_VERIFY` keys for security and release human
  roles, each also conditioned on an exact identity-enhanced Identity Center
  user/store context, plus a witness key in a separately authenticated AWS
  account;
- a single IRSA workload role that can verify but is explicitly denied Sign;
- exact IAM user/role revocation allowlists, empty by default, with the
  generated runtime role explicitly forbidden as a self-revocation target;
- validated multi-region CloudTrail trails with encrypted S3 evidence in both
  the workload and witness accounts; and
- a narrowly trusted cross-account role for admission-time witness evidence
  lookup.

## Validation

Use a private backend with state locking. Never commit a populated variable
file or a saved plan.

```bash
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform plan -refresh=true -input=false -var-file=/secure/path/production.tfvars -out=/secure/path/safe-qa.tfplan
terraform show -json /secure/path/safe-qa.tfplan > /secure/path/safe-qa.tfplan.json
sha256sum /secure/path/safe-qa.tfplan /secure/path/safe-qa.tfplan.json
```

`terraform validate` checks shape, not AWS ownership, routes, signer
independence, cluster compatibility, or enforcement. Do not apply until the
plan digests and exact target state are bound into external human approvals.

This reference uses an exclusive EC2 Linux managed node group compatible with
VPC CNI NetworkPolicy enforcement. Leave the example sandbox Job suspended
unless the `aws-network-policy-agent` is ready on every eligible node and live
zero-egress tests, including both link-local metadata IPs, pass on the exact
cluster, CNI, launch-template, node, security-group, and route revisions.

Follow `docs/AWS_PRODUCTION_RUNBOOK.md` for bootstrap sequencing, live
readback, negative authorization tests, witness handling, and rollback rules.
