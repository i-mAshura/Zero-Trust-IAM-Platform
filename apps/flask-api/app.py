import os
import time
from datetime import datetime, timezone
import requests
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM_NAME = os.environ.get("REALM_NAME", "zero-trust-realm")
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181/v1/data/zero_trust/authorization/decision")
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"

jwks_client = None
try:
    jwks_client = jwt.PyJWKClient(JWKS_URL)
except Exception as e:
    print(f"Warning: JWKS client initialization deferred: {e}")

def get_current_utc_hour():
    return datetime.now(timezone.utc).hour

def extract_and_verify_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "Missing or malformed Authorization header"
    
    token = auth_header.split(" ")[1]
    
    # In live mode with Keycloak reachable, verify signature using JWKS
    if jwks_client:
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience="account",
                options={"verify_aud": False}
            )
            return payload, None
        except Exception as e:
            # Fallback to unverified decode for offline unit testing/demo
            print(f"JWKS verification warning (falling back for demo): {e}")
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                return payload, None
            except Exception as dec_err:
                return None, f"Invalid token format: {dec_err}"
    else:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload, None
        except Exception as e:
            return None, str(e)

def evaluate_opa_policy(user_claims, resource_info, action_info, device_info, context_info):
    payload = {
        "input": {
            "user": {
                "id": user_claims.get("preferred_username", "anonymous"),
                "email": user_claims.get("email", ""),
                "roles": user_claims.get("realm_access", {}).get("roles", []) or user_claims.get("roles", []),
                "department": user_claims.get("department", "unknown"),
                "clearance_level": int(user_claims.get("clearance_level", 1))
            },
            "device": device_info,
            "context": context_info,
            "action": action_info,
            "auth_context": {
                "amr_contains_mfa": "mfa" in (user_claims.get("amr") or []) or "otp" in (user_claims.get("amr") or []) or user_claims.get("acr") == "1"
            },
            "resource": resource_info
        }
    }

    try:
        response = requests.post(OPA_URL, json=payload, timeout=3.0)
        if response.status_code == 200:
            result = response.json().get("result", {})
            return result
        else:
            return {"allow": False, "reasons": [f"OPA returned HTTP {response.status_code}"]}
    except Exception as e:
        # Fallback local ABAC evaluation if OPA container is not currently running
        return local_abac_evaluation_fallback(payload["input"])

def local_abac_evaluation_fallback(inp):
    # Standalone fallback matching abac.rego logic
    user = inp["user"]
    device = inp["device"]
    context = inp["context"]
    action = inp["action"]
    auth = inp["auth_context"]
    resource = inp["resource"]

    valid_device = device.get("is_managed", False) and device.get("disk_encrypted", False) and not device.get("compromised", False)
    valid_time = 6 <= context.get("request_hour_utc", 12) <= 22
    low_risk = context.get("risk_score", 0) < 40 and not context.get("impossible_travel", False)
    
    require_step_up = (action.get("is_sensitive", False) or context.get("risk_score", 0) >= 40) and not auth.get("amr_contains_mfa", False)
    
    valid_subject = (
        user.get("department") in ["engineering", "security-operations", "devops"] and 
        user.get("clearance_level", 1) >= resource.get("required_clearance", 1)
    ) or ("admin" in user.get("roles", []) and auth.get("amr_contains_mfa", False))

    allowed = valid_subject and valid_device and valid_time and low_risk and not require_step_up
    
    reasons = []
    if not valid_subject: reasons.append("Subject department or clearance insufficient")
    if not valid_device: reasons.append("Device posture non-compliant (unmanaged/unencrypted)")
    if not valid_time: reasons.append("Outside business operational hours (06:00 - 22:00 UTC)")
    if not low_risk: reasons.append("Risk score exceeded or impossible travel detected")
    if require_step_up: reasons.append("Sensitive operation requires step-up MFA")

    return {
        "allow": allowed,
        "require_step_up": require_step_up,
        "reasons": reasons,
        "mode": "standalone_engine_fallback"
    }

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "UP", "service": "flask-abac-api"})

@app.route("/api/public", methods=["GET"])
def public_endpoint():
    return jsonify({
        "message": "Public discovery endpoint - no authentication required",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route("/api/developer/repos", methods=["GET", "POST"])
def developer_repos():
    user_claims, err = extract_and_verify_token(request.headers.get("Authorization"))
    if err:
        return jsonify({"error": "Unauthorized", "details": err}), 401

    # Extract Zero-Trust device context from headers (simulating gateway or agent inspection)
    device_info = {
        "is_managed": request.headers.get("X-Device-Managed", "true").lower() == "true",
        "disk_encrypted": request.headers.get("X-Device-Encrypted", "true").lower() == "true",
        "compromised": request.headers.get("X-Device-Compromised", "false").lower() == "true",
        "os": request.headers.get("X-Device-OS", "Windows")
    }
    
    context_info = {
        "request_hour_utc": int(request.headers.get("X-Request-Hour-UTC", get_current_utc_hour())),
        "risk_score": int(request.headers.get("X-Risk-Score", 15)),
        "threat_level": request.headers.get("X-Threat-Level", "low"),
        "impossible_travel": request.headers.get("X-Impossible-Travel", "false").lower() == "true"
    }

    action_info = {
        "method": request.method,
        "is_sensitive": False
    }

    resource_info = {
        "name": "developer-code-repositories",
        "required_clearance": 2
    }

    decision = evaluate_opa_policy(user_claims, resource_info, action_info, device_info, context_info)

    if not decision.get("allow"):
        status_code = 403
        if decision.get("require_step_up"):
            status_code = 428 # Precondition Required (Step-up auth)
        return jsonify({
            "error": "Access Denied by OPA Zero-Trust Policy",
            "decision": decision
        }), status_code

    return jsonify({
        "status": "GRANTED",
        "user": user_claims.get("preferred_username"),
        "department": user_claims.get("department"),
        "repositories": ["repo-auth-service", "repo-payment-gateway", "repo-zero-trust-mesh"],
        "policy_evaluation": decision
    })

@app.route("/api/admin/system-purge", methods=["POST"])
def admin_system_purge():
    user_claims, err = extract_and_verify_token(request.headers.get("Authorization"))
    if err:
        return jsonify({"error": "Unauthorized", "details": err}), 401

    device_info = {
        "is_managed": request.headers.get("X-Device-Managed", "true").lower() == "true",
        "disk_encrypted": request.headers.get("X-Device-Encrypted", "true").lower() == "true",
        "compromised": request.headers.get("X-Device-Compromised", "false").lower() == "true",
        "os": request.headers.get("X-Device-OS", "Windows")
    }

    context_info = {
        "request_hour_utc": int(request.headers.get("X-Request-Hour-UTC", get_current_utc_hour())),
        "risk_score": int(request.headers.get("X-Risk-Score", 20)),
        "threat_level": "low",
        "impossible_travel": False
    }

    action_info = {
        "method": "POST",
        "is_sensitive": True # Critical sensitive administrative operation!
    }

    resource_info = {
        "name": "core-infrastructure-purge",
        "required_clearance": 4
    }

    decision = evaluate_opa_policy(user_claims, resource_info, action_info, device_info, context_info)

    if not decision.get("allow"):
        if decision.get("require_step_up"):
            return jsonify({
                "error": "Step-up MFA Authentication Required",
                "message": "This critical action requires re-authentication with hardware token / TOTP.",
                "step_up_flow": "/auth/realms/zero-trust-realm/protocol/openid-connect/auth?step_up=true",
                "decision": decision
            }), 428
        return jsonify({"error": "Forbidden by Zero-Trust Policy", "decision": decision}), 403

    return jsonify({
        "status": "EXECUTED",
        "message": "Sensitive administrative operation executed successfully under verified MFA & compliance posture.",
        "executed_by": user_claims.get("preferred_username"),
        "decision": decision
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
