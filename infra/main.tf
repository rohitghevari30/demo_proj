# Level 5 — root Terraform config
# Wire up oracle_cloud.tf, cloudflare.tf, database.tf as modules/resources here.

terraform {
  required_providers {
    # oci = { source = "oracle/oci" }
    # cloudflare = { source = "cloudflare/cloudflare" }
  }
}
