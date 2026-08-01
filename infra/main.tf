# Level 5 — root Terraform config
# Wire up oracle_cloud.tf, cloudflare.tf, database.tf as modules/resources here.
# Level 5 — root Terraform config
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "cloudflare" {
  # set CLOUDFLARE_API_TOKEN as an env var — never hardcode here
}