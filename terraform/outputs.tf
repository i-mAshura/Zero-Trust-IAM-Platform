output "keycloak_realm_url" {
  description = "Zero-Trust Realm URL"
  value       = "${var.keycloak_url}/realms/${keycloak_realm.zero_trust.realm}"
}

output "oidc_well_known_endpoint" {
  description = "OpenID Connect discovery endpoint"
  value       = "${var.keycloak_url}/realms/${keycloak_realm.zero_trust.realm}/.well-known/openid-configuration"
}

output "saml_descriptor_url" {
  description = "SAML 2.0 Identity Provider metadata descriptor URL"
  value       = "${var.keycloak_url}/realms/${keycloak_realm.zero_trust.realm}/protocol/saml/descriptor"
}

output "react_client_id" {
  description = "Client ID for React SPA"
  value       = keycloak_openid_client.react_app.client_id
}

output "flask_client_id" {
  description = "Client ID for Flask API"
  value       = keycloak_openid_client.flask_api.client_id
}

output "flask_client_secret" {
  description = "Client Secret for Flask API"
  value       = keycloak_openid_client.flask_api.client_secret
  sensitive   = true
}

output "spring_boot_client_id" {
  description = "Client ID for Spring Boot API"
  value       = keycloak_openid_client.spring_boot_api.client_id
}

output "saml_client_id" {
  description = "Client ID for SAML Node.js App"
  value       = keycloak_saml_client.saml_app.client_id
}
