# Level 5 — Findings

## Before (vulnerable state)
Initial Terraform for the AWS backend (EC2 + security group) had no IAM role attached,
detailed monitoring disabled, EBS optimization disabled, and security group rules with
no descriptions. Checkov flagged 5 failed checks against a 10-passed baseline.

## Tool(s) used
Checkov v3.3.8, run via `checkov -d .` against `infra/`.

## Vulnerabilities found
- CKV_AWS_23: security group and rules missing descriptions
- CKV_AWS_382: security group allows unrestricted egress (0.0.0.0/0, all ports)
- CKV_AWS_126: EC2 instance detailed monitoring not enabled
- CKV_AWS_135: EC2 instance not EBS-optimized
- CKV2_AWS_41: no IAM role attached to EC2 instance

## Fix applied
- Added a `description` to every ingress rule and the egress rule
- Created a minimal IAM role (`secureapp-backend-role`) and instance profile, attached
  to the EC2 instance, trust policy scoped to `ec2.amazonaws.com` only, no permissions
  attached (satisfies the "role exists" check; can be extended later if the app needs
  AWS API access)
- Set `monitoring = true` on the EC2 instance
- Set `ebs_optimized = true` on the EC2 instance
- Left the unrestricted egress rule (CKV_AWS_382) as **accepted risk**: the app needs
  broad outbound access (package installs, GitHub, Supabase, Groq API in later levels),
  and fully restricting egress would require maintaining an allowlist of every external
  destination the app calls — not proportionate for this project's scope. Documented
  here instead of allowlisted.

## After (re-scan confirming fix)
Checkov re-run: **19 passed, 1 failed** (CKV_AWS_382, accepted risk as above).
All other findings resolved.

## Infrastructure summary
- **Backend**: AWS EC2 (t3.micro), public IP assigned dynamically on each instance
  replacement — current IP tracked via `terraform output backend_public_ip`
- **Frontend**: Cloudflare Pages, connected to GitHub (`rohitghevari30/demo_proj`,
  `frontend/` subdirectory), live at `https://secureapp-frontend.pages.dev`
- **Database**: Supabase-managed Postgres, connection string passed via Terraform
  variable (`sensitive = true`), never committed to git; inbound port 5432 not exposed
  on the EC2 security group
- **IaC scanning**: `.github/workflows/iac-scan.yml` runs Checkov on every push
  touching `infra/**`cd 