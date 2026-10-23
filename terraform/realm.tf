resource "keycloak_realm" "zero_trust" {
  realm             = var.realm_name
  enabled           = true
  display_name      = "Zero-Trust Identity & Access Platform"
  display_name_html = "<div class='kc-logo-text'><span>Zero-Trust</span> Platform</div>"

  # Security & login constraints
  login_with_email_allowed = true
  duplicate_emails_allowed = false
  reset_password_allowed   = true
  remember_me              = false
  verify_email             = false
  ssl_required             = "external"

  # Session lifespans (Strict Zero-Trust short-lived tokens)
  sso_session_idle_timeout = "1800s"  # 30 mins
  sso_session_max_lifespan = "36000s" # 10 hours
  access_token_lifespan    = "300s"   # 5 minutes for rapid revocation & zero-trust posture validation


  # Password & Security Policy
  password_policy = "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notRecentlyUsed(3)"

  # Internationalization
  internationalization {
    supported_locales = ["en"]
    default_locale    = "en"
  }
}
