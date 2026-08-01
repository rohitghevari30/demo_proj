# TODO: Cloudflare Pages project + proxied subdomain (api.yourdomain.com)
# Level 5 — Cloudflare Pages project (frontend)
# No custom domain: using the free *.pages.dev URL Cloudflare Pages
# assigns automatically. The backend is reached directly via its EC2
# public IP (see infra/outputs.tf) rather than a proxied subdomain.

resource "cloudflare_pages_project" "frontend" {
  account_id        = var.cloudflare_account_id
  name              = "secureapp-frontend"
  production_branch = "main"

  source {
    type = "github"
    config {
      owner             = var.github_owner
      repo_name         = var.github_repo
      production_branch = "main"
      # frontend/ is a subdirectory of the repo — Pages build config
      # (root_dir) is set below to "frontend"
    }
  }

  build_config {
    build_command   = "npm run build"
    destination_dir = "dist"
    root_dir        = "frontend"
  }
}

output "frontend_pages_url" {
  value = "https://${cloudflare_pages_project.frontend.subdomain}"
}