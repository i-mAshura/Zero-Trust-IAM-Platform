package zero_trust.authorization

import future.keywords.if

# Test 1: Compliant engineer during business hours with clean device -> ALLOW
test_allow_compliant_engineer if {
    allow with input as {
        "user": {
            "id": "eng-alice",
            "roles": ["developer"],
            "department": "engineering",
            "clearance_level": 3
        },
        "device": {
            "is_managed": true,
            "disk_encrypted": true,
            "compromised": false,
            "os": "Windows"
        },
        "context": {
            "request_hour_utc": 14,
            "risk_score": 15,
            "threat_level": "low",
            "impossible_travel": false
        },
        "action": {
            "method": "POST",
            "is_sensitive": false
        },
        "auth_context": {
            "amr_contains_mfa": false
        },
        "resource": {
            "required_clearance": 2
        }
    }
}

# Test 2: Unmanaged device -> DENY
test_deny_unmanaged_device if {
    not allow with input as {
        "user": {
            "id": "eng-bob",
            "roles": ["developer"],
            "department": "engineering",
            "clearance_level": 3
        },
        "device": {
            "is_managed": false,
            "disk_encrypted": true,
            "compromised": false,
            "os": "Windows"
        },
        "context": {
            "request_hour_utc": 14,
            "risk_score": 10,
            "threat_level": "low",
            "impossible_travel": false
        },
        "action": {"method": "GET", "is_sensitive": false},
        "auth_context": {"amr_contains_mfa": false},
        "resource": {"required_clearance": 1}
    }
}

# Test 3: Off-hours access (03:00 UTC) -> DENY
test_deny_off_hours if {
    not allow with input as {
        "user": {
            "id": "eng-alice",
            "roles": ["developer"],
            "department": "engineering",
            "clearance_level": 3
        },
        "device": {
            "is_managed": true,
            "disk_encrypted": true,
            "compromised": false,
            "os": "Linux"
        },
        "context": {
            "request_hour_utc": 3,
            "risk_score": 10,
            "threat_level": "low",
            "impossible_travel": false
        },
        "action": {"method": "GET", "is_sensitive": false},
        "auth_context": {"amr_contains_mfa": false},
        "resource": {"required_clearance": 1}
    }
}

# Test 4: Sensitive admin action without MFA triggers require_step_up
test_require_step_up_for_sensitive_action if {
    require_step_up with input as {
        "user": {"id": "sec-dan", "roles": ["admin"], "department": "security-operations"},
        "device": {"is_managed": true, "disk_encrypted": true, "compromised": false, "os": "macOS"},
        "context": {"request_hour_utc": 11, "risk_score": 20, "threat_level": "low", "impossible_travel": false},
        "action": {"method": "DELETE", "is_sensitive": true},
        "auth_context": {"amr_contains_mfa": false},
        "resource": {"required_clearance": 3}
    }
}

# Test 5: Admin action WITH step-up MFA fulfilled -> ALLOW
test_allow_admin_with_mfa if {
    allow with input as {
        "user": {"id": "sec-dan", "roles": ["admin"], "department": "security-operations"},
        "device": {"is_managed": true, "disk_encrypted": true, "compromised": false, "os": "macOS"},
        "context": {"request_hour_utc": 11, "risk_score": 20, "threat_level": "low", "impossible_travel": false},
        "action": {"method": "DELETE", "is_sensitive": true},
        "auth_context": {"amr_contains_mfa": true},
        "resource": {"required_clearance": 3}
    }
}
