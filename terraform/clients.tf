# ---------------------------------------------------------
# 1. React SPA Client (OIDC with PKCE)
# ---------------------------------------------------------
resource "keycloak_openid_client" "react_app" {
  realm_id                     = keycloak_realm.zero_trust.id
  client_id                    = "react-oidc-portal"
  name                         = "React Zero-Trust User Portal"
  enabled                      = true
  access_type                  = "PUBLIC"
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  pkce_code_challenge_method   = "S256"

  valid_redirect_uris = [
    "http://localhost:5173/*",
    "http://localhost:3000/*",
    "http://127.0.0.1:5173/*"
  ]

  web_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "+"
  ]

  base_url = "http://localhost:5173"
}

resource "keycloak_openid_client_default_scopes" "react_app_default_scopes" {
  realm_id  = keycloak_realm.zero_trust.id
  client_id = keycloak_openid_client.react_app.id

  default_scopes = [
    "profile",
    "email",
    "roles",
    "web-origins",
    keycloak_openid_client_scope.zero_trust_claims.name
  ]
}

# ---------------------------------------------------------
# 2. Flask REST API Client (OIDC Confidential Client)
# ---------------------------------------------------------
resource "keycloak_openid_client" "flask_api" {
  realm_id                     = keycloak_realm.zero_trust.id
  client_id                    = "flask-api-service"
  name                         = "Flask ABAC Enforced REST API"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  client_secret                = "flask_api_super_secret_key_123"
  standard_flow_enabled        = true
  service_accounts_enabled     = true
  direct_access_grants_enabled = false

  valid_redirect_uris = [
    "http://localhost:5000/*",
    "http://127.0.0.1:5000/*"
  ]

  web_origins = ["+"]
}

resource "keycloak_openid_client_default_scopes" "flask_api_default_scopes" {
  realm_id  = keycloak_realm.zero_trust.id
  client_id = keycloak_openid_client.flask_api.id

  default_scopes = [
    "profile",
    "email",
    "roles",
    keycloak_openid_client_scope.zero_trust_claims.name
  ]
}

# ---------------------------------------------------------
# 3. Spring Boot Backend API (OIDC Resource Server)
# ---------------------------------------------------------
resource "keycloak_openid_client" "spring_boot_api" {
  realm_id                     = keycloak_realm.zero_trust.id
  client_id                    = "spring-boot-resource-server"
  name                         = "Spring Boot Zero-Trust Backend"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  client_secret                = "spring_boot_secret_key_456"
  standard_flow_enabled        = true
  service_accounts_enabled     = true
  direct_access_grants_enabled = false

  valid_redirect_uris = [
    "http://localhost:8081/*",
    "http://127.0.0.1:8081/*"
  ]
}

resource "keycloak_openid_client_default_scopes" "spring_boot_default_scopes" {
  realm_id  = keycloak_realm.zero_trust.id
  client_id = keycloak_openid_client.spring_boot_api.id

  default_scopes = [
    "profile",
    "email",
    "roles",
    keycloak_openid_client_scope.zero_trust_claims.name
  ]
}

# ---------------------------------------------------------
# 4. SAML 2.0 Service Provider Application
# ---------------------------------------------------------
resource "keycloak_saml_client" "saml_app" {
  realm_id  = keycloak_realm.zero_trust.id
  client_id = "saml-node-app"
  name      = "SAML 2.0 Enterprise Service Provider"
  enabled   = true

  sign_documents            = true
  sign_assertions           = true
  client_signature_required = false
  force_post_binding        = true

  base_url                        = "http://localhost:4000"
  master_saml_processing_url      = "http://localhost:4000/login/callback"
  valid_redirect_uris             = ["http://localhost:4000/*"]
  assertion_consumer_post_url     = "http://localhost:4000/login/callback"
  assertion_consumer_redirect_url = "http://localhost:4000/login/callback"
  logout_service_post_binding_url = "http://localhost:4000/logout/callback"
}

# SAML Protocol Mapper: Department
resource "keycloak_saml_user_attribute_protocol_mapper" "saml_department" {
  realm_id                   = keycloak_realm.zero_trust.id
  client_id                  = keycloak_saml_client.saml_app.id
  name                       = "saml-department-mapper"
  user_attribute             = "department"
  saml_attribute_name        = "department"
  saml_attribute_name_format = "Basic"
}

# SAML Protocol Mapper: Clearance Level
resource "keycloak_saml_user_attribute_protocol_mapper" "saml_clearance" {
  realm_id                   = keycloak_realm.zero_trust.id
  client_id                  = keycloak_saml_client.saml_app.id
  name                       = "saml-clearance-mapper"
  user_attribute             = "clearance_level"
  saml_attribute_name        = "clearance_level"
  saml_attribute_name_format = "Basic"
}
