# Export useful outputs here (backend IP, subdomain, etc.)
output "backend_public_ip" {
  value = aws_instance.backend.public_ip
}