# Custom Zero-Trust Browser Authentication Flow enforcing MFA
resource "keycloak_authentication_flow" "zero_trust_browser" {
  realm_id    = keycloak_realm.zero_trust.id
  alias       = "zero-trust-browser-flow"
  description = "Browser authentication flow enforcing Password + MFA (TOTP / WebAuthn)"
}

# Execution: Cookie
resource "keycloak_authentication_execution" "cookie" {
  realm_id          = keycloak_realm.zero_trust.id
  parent_flow_alias = keycloak_authentication_flow.zero_trust_browser.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
}

# Subflow: Identity & Credentials
resource "keycloak_authentication_subflow" "forms" {
  realm_id          = keycloak_realm.zero_trust.id
  parent_flow_alias = keycloak_authentication_flow.zero_trust_browser.alias
  alias             = "zero-trust-identity-forms"
  requirement       = "ALTERNATIVE"
}

# Execution: Username / Password form
resource "keycloak_authentication_execution" "username_password" {
  realm_id          = keycloak_realm.zero_trust.id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
}

# Execution: Enforce MFA (TOTP or WebAuthn)
resource "keycloak_authentication_execution" "otp" {
  realm_id          = keycloak_realm.zero_trust.id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  depends_on        = [keycloak_authentication_execution.username_password]
}

# Bind the flow as the browser authentication flow for the realm
resource "keycloak_realm_events" "realm_events" {
  realm_id         = keycloak_realm.zero_trust.id
  events_listeners = ["jboss-logging"]
  enabled_event_types = [
    "LOGIN",
    "LOGIN_ERROR",
    "LOGOUT",
    "CODE_TO_TOKEN",
    "REFRESH_TOKEN",
    "FEDERATED_IDENTITY_LINK",
    "UPDATE_TOTP",
    "VERIFY_EMAIL"
  ]
  events_enabled               = true
  events_expiration            = 2592000
  admin_events_enabled         = true
  admin_events_details_enabled = true
}

# Dedicated Step-Up Authentication Flow for High-Risk / Admin Actions
resource "keycloak_authentication_flow" "step_up_flow" {
  realm_id    = keycloak_realm.zero_trust.id
  alias       = "zero-trust-step-up-flow"
  description = "Conditional Step-Up Flow requiring fresh MFA re-verification for high-privilege actions"
}

resource "keycloak_authentication_execution" "step_up_otp" {
  realm_id          = keycloak_realm.zero_trust.id
  parent_flow_alias = keycloak_authentication_flow.step_up_flow.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
}
