# Define shared variables here (region, project name, tags, etc.)
variable "aws_region"    { default = "us-east-1" }
variable "admin_ip_cidr" { description = "Your IP in CIDR form, e.g. 1.2.3.4/32" }
variable "ubuntu_ami_id" { default = "ami-0b6d9d3d33ba97d99" }
variable "key_pair_name" { default = "secureapp-key" }

variable "cloudflare_account_id" { description = "Cloudflare account ID" }
variable "github_owner"          { default = "rohitghevari30" }
variable "github_repo"           { default = "demo_proj" }