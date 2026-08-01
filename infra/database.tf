# TODO: Supabase / Neon managed Postgres config
# Level 5 — Managed Postgres (Supabase or Neon)
#
# Neither Supabase nor Neon has a first-party Terraform provider that
# manages full project lifecycle the way aws/cloudflare do, so the
# pattern here is: provision the project manually via their console
# (as you already did), then reference the connection details as
# Terraform variables so they flow into GitHub Actions secrets and
# app config the same way everything else in infra/ does. This also
# means there's no "before" misconfiguration for Checkov to catch on
# the DB resource itself — the IaC-scan surface for this file is
# really just "are secrets marked sensitive / not hardcoded".

variable "database_url" {
  description = "Full Postgres connection string from Supabase/Neon (never commit the real value — pass via TF_VAR_database_url or GitHub Actions secret)"
  type        = string
  sensitive   = true
}

variable "database_host" {
  description = "Supabase/Neon Postgres host"
  type        = string
  sensitive   = true
}

variable "database_name" {
  description = "Postgres database name"
  type        = string
  default     = "secureapp"
}

# Restrict the EC2 backend's outbound reach to just what it needs,
# and document that inbound 5432 stays closed since the DB is managed
# (Supabase/Neon), not self-hosted — this is what Level 7's Nmap scan
# should confirm.
output "database_connection_note" {
  value = "Postgres is managed via Supabase/Neon — no inbound 5432 exposed on the EC2 security group."
}