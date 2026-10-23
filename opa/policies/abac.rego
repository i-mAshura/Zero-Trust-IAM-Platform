package zero_trust.authorization

import future.keywords.in
import future.keywords.if

default allow = false
default require_step_up = false

# Allowed departments per sensitivity
high_security_departments := ["engineering", "security-operations", "devops"]

# Main evaluation decision
allow if {
    valid_subject
    valid_device
    valid_time_window
    low_risk
    not require_step_up
}

# Allow admin override only if step-up authentication has been fulfilled
allow if {
    "admin" in input.user.roles
    input.auth_context.amr_contains_mfa == true
    valid_device
}

# Condition for step-up authentication
require_step_up if {
    input.action.is_sensitive == true
    not input.auth_context.amr_contains_mfa
}

require_step_up if {
    input.context.risk_score >= 40
    not input.auth_context.amr_contains_mfa
}

# 1. Subject validation (RBAC + Department attribute)
valid_subject if {
    input.user.department in high_security_departments
    has_sufficient_clearance
}

valid_subject if {
    "auditor" in input.user.roles
    input.action.method == "GET"
}

has_sufficient_clearance if {
    required_clearance := object.get(input.resource, "required_clearance", 1)
    user_clearance := object.get(input.user, "clearance_level", 1)
    user_clearance >= required_clearance
}

# 2. Device posture validation (Zero-Trust endpoint compliance)
valid_device if {
    input.device.is_managed == true
    input.device.disk_encrypted == true
    input.device.compromised == false
    input.device.os in ["Windows", "macOS", "Linux", "iOS", "Android"]
}

# 3. Contextual Time-of-day verification (06:00 to 22:00)
valid_time_window if {
    hour := input.context.request_hour_utc
    hour >= 6
    hour <= 22
}

# 4. Risk engine evaluation
low_risk if {
    input.context.risk_score < 40
    input.context.threat_level == "low"
    input.context.impossible_travel == false
}

# Diagnostic response payload for caller
decision := {
    "allow": allow,
    "require_step_up": require_step_up,
    "user_id": input.user.id,
    "evaluated_at_utc_hour": input.context.request_hour_utc,
    "risk_score": input.context.risk_score,
    "reasons": denial_reasons
}

denial_reasons[reason] {
    not valid_subject
    reason := "Subject does not satisfy department or clearance requirements"
}

denial_reasons[reason] {
    not valid_device
    reason := "Device failed zero-trust endpoint compliance (unmanaged, unencrypted, or compromised)"
}

denial_reasons[reason] {
    not valid_time_window
    reason := "Access attempted outside permissible operational hours (06:00 - 22:00 UTC)"
}

denial_reasons[reason] {
    not low_risk
    reason := "Contextual risk score exceeded acceptable threshold or impossible travel detected"
}

denial_reasons[reason] {
    require_step_up
    reason := "Action or risk profile requires step-up MFA authentication"
}
