variable "keycloak_url" {
  description = "Base URL of Keycloak instance"
  type        = string
  default     = "http://localhost:8080"
}

variable "keycloak_client_id" {
  description = "Admin client ID used by the Keycloak Terraform provider"
  type        = string
  default     = "admin-cli"
}

variable "keycloak_admin_user" {
  description = "Keycloak initial master administrator username"
  type        = string
  default     = "admin"
}

variable "keycloak_admin_password" {
  description = "Keycloak initial master administrator password"
  type        = string
  sensitive   = true
  default     = "admin123"
}

variable "realm_name" {
  description = "Name of the Zero-Trust Realm"
  type        = string
  default     = "zero-trust-realm"
}
