# Realm Roles
resource "keycloak_role" "admin" {
  realm_id    = keycloak_realm.zero_trust.id
  name        = "admin"
  description = "Privileged administrator with conditional step-up auth requirement"
}

resource "keycloak_role" "sec_ops" {
  realm_id    = keycloak_realm.zero_trust.id
  name        = "sec-ops"
  description = "Security Operations team member with SIEM and audit inspection rights"
}

resource "keycloak_role" "developer" {
  realm_id    = keycloak_realm.zero_trust.id
  name        = "developer"
  description = "Standard engineering personnel"
}

resource "keycloak_role" "contractor" {
  realm_id    = keycloak_realm.zero_trust.id
  name        = "contractor"
  description = "Third-party contractor with restricted scope and low clearance"
}

resource "keycloak_role" "auditor" {
  realm_id    = keycloak_realm.zero_trust.id
  name        = "auditor"
  description = "Compliance auditor with read-only inspection access"
}

# Groups with Zero-Trust attributes
resource "keycloak_group" "engineering" {
  realm_id = keycloak_realm.zero_trust.id
  name     = "Engineering"
  attributes = {
    "department"      = "engineering"
    "clearance_level" = "3"
    "employee_type"   = "full_time"
  }
}

resource "keycloak_group_roles" "engineering_roles" {
  realm_id = keycloak_realm.zero_trust.id
  group_id = keycloak_group.engineering.id
  role_ids = [keycloak_role.developer.id]
}

resource "keycloak_group" "secops" {
  realm_id = keycloak_realm.zero_trust.id
  name     = "SecurityOperations"
  attributes = {
    "department"      = "security-operations"
    "clearance_level" = "4"
    "employee_type"   = "full_time"
  }
}

resource "keycloak_group_roles" "secops_roles" {
  realm_id = keycloak_realm.zero_trust.id
  group_id = keycloak_group.secops.id
  role_ids = [keycloak_role.admin.id, keycloak_role.sec_ops.id]
}

resource "keycloak_group" "contractors" {
  realm_id = keycloak_realm.zero_trust.id
  name     = "Contractors"
  attributes = {
    "department"      = "contractors"
    "clearance_level" = "1"
    "employee_type"   = "contractor"
  }
}

resource "keycloak_group_roles" "contractor_roles" {
  realm_id = keycloak_realm.zero_trust.id
  group_id = keycloak_group.contractors.id
  role_ids = [keycloak_role.contractor.id]
}

# Sample User: Alice (Developer)
resource "keycloak_user" "alice" {
  realm_id       = keycloak_realm.zero_trust.id
  username       = "alice"
  enabled        = true
  email          = "alice@corp.local"
  first_name     = "Alice"
  last_name      = "Developer"
  email_verified = true

  initial_password {
    value     = "SecurePass123!@"
    temporary = false
  }

  attributes = {
    "department"      = "engineering"
    "clearance_level" = "3"
    "employee_type"   = "full_time"
  }
}

resource "keycloak_user_groups" "alice_groups" {
  realm_id  = keycloak_realm.zero_trust.id
  user_id   = keycloak_user.alice.id
  group_ids = [keycloak_group.engineering.id]
}

# Sample User: Dan (SecOps Admin)
resource "keycloak_user" "dan_admin" {
  realm_id       = keycloak_realm.zero_trust.id
  username       = "dan_admin"
  enabled        = true
  email          = "dan.admin@corp.local"
  first_name     = "Dan"
  last_name      = "Security"
  email_verified = true

  initial_password {
    value     = "AdminMaster123!@"
    temporary = false
  }

  attributes = {
    "department"      = "security-operations"
    "clearance_level" = "4"
    "employee_type"   = "full_time"
  }
}

resource "keycloak_user_groups" "dan_groups" {
  realm_id  = keycloak_realm.zero_trust.id
  user_id   = keycloak_user.dan_admin.id
  group_ids = [keycloak_group.secops.id]
}

# Sample User: Bob (External Contractor)
resource "keycloak_user" "bob_contractor" {
  realm_id       = keycloak_realm.zero_trust.id
  username       = "bob"
  enabled        = true
  email          = "bob.contractor@vendor.local"
  first_name     = "Bob"
  last_name      = "Contractor"
  email_verified = true

  initial_password {
    value     = "VendorPass123!@"
    temporary = false
  }

  attributes = {
    "department"      = "contractors"
    "clearance_level" = "1"
    "employee_type"   = "contractor"
  }
}

resource "keycloak_user_groups" "bob_groups" {
  realm_id  = keycloak_realm.zero_trust.id
  user_id   = keycloak_user.bob_contractor.id
  group_ids = [keycloak_group.contractors.id]
}
