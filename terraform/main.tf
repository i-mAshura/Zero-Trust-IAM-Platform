terraform {
  required_version = ">= 1.5.0"
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "~> 4.4.0"
    }
  }
}

provider "keycloak" {
  client_id     = var.keycloak_client_id
  username      = var.keycloak_admin_user
  password      = var.keycloak_admin_password
  url           = var.keycloak_url
  initial_login = false
}
