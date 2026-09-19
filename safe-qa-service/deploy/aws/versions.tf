terraform {
  required_version = ">= 1.7.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.workload_account_id]

  assume_role {
    role_arn     = var.workload_deployer_role_arn
    session_name = "safe-qa-terraform"
  }

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias               = "witness"
  region              = var.witness_aws_region
  allowed_account_ids = [var.witness_account_id]

  assume_role {
    role_arn     = var.witness_deployer_role_arn
    session_name = "safe-qa-witness-terraform"
  }

  default_tags {
    tags = local.common_tags
  }
}
