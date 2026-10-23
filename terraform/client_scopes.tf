# Dedicated client scope for Zero-Trust ABAC claims
resource "keycloak_openid_client_scope" "zero_trust_claims" {
  realm_id               = keycloak_realm.zero_trust.id
  name                   = "zero_trust_claims"
  description            = "Injects department, clearance level, and risk posture into JWT tokens for OPA"
  include_in_token_scope = true
  gui_order              = 1
}

# User attribute mapper: department
resource "keycloak_openid_user_attribute_protocol_mapper" "department" {
  realm_id            = keycloak_realm.zero_trust.id
  client_scope_id     = keycloak_openid_client_scope.zero_trust_claims.id
  name                = "department-mapper"
  user_attribute      = "department"
  claim_name          = "department"
  claim_value_type    = "String"
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# User attribute mapper: clearance_level
resource "keycloak_openid_user_attribute_protocol_mapper" "clearance_level" {
  realm_id            = keycloak_realm.zero_trust.id
  client_scope_id     = keycloak_openid_client_scope.zero_trust_claims.id
  name                = "clearance-level-mapper"
  user_attribute      = "clearance_level"
  claim_name          = "clearance_level"
  claim_value_type    = "int"
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# User attribute mapper: employee_type
resource "keycloak_openid_user_attribute_protocol_mapper" "employee_type" {
  realm_id            = keycloak_realm.zero_trust.id
  client_scope_id     = keycloak_openid_client_scope.zero_trust_claims.id
  name                = "employee-type-mapper"
  user_attribute      = "employee_type"
  claim_name          = "employee_type"
  claim_value_type    = "String"
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Group membership mapper
resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id            = keycloak_realm.zero_trust.id
  client_scope_id     = keycloak_openid_client_scope.zero_trust_claims.id
  name                = "group-membership-mapper"
  claim_name          = "groups"
  full_path           = false
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}
