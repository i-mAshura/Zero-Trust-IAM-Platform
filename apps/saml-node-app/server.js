const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');

const app = express();
const PORT = process.env.PORT || 4000;
const KEYCLOAK_BASE = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const REALM = process.env.REALM || 'zero-trust-realm';

const SAML_ENTRY_POINT = `${KEYCLOAK_BASE}/realms/${REALM}/protocol/saml`;
const SAML_LOGOUT_URL = `${KEYCLOAK_BASE}/realms/${REALM}/protocol/saml`;

// Configure Passport SAML Strategy
const samlStrategy = new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: SAML_ENTRY_POINT,
    issuer: 'saml-node-app',
    logoutUrl: SAML_LOGOUT_URL,
    disableRequestedAuthnContext: true,
    identifierFormat: null,
    acceptedClockSkewMs: 5000,
    wantAssertionsSigned: true,
    validateInResponseTo: false
  },
  (profile, done) => {
    return done(null, profile);
  }
);

passport.use('saml', samlStrategy);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'saml_session_super_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());

// Home / Dashboard
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    const user = req.user;
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SAML 2.0 Enterprise Service Provider</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }
          .card { max-width: 750px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 30px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
          h1 { color: #38bdf8; margin-top: 0; font-size: 24px; }
          .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; background: #0284c7; color: white; margin-right: 8px; }
          .attr-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          .attr-table th, .attr-table td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; font-size: 14px; }
          .attr-table th { color: #94a3b8; }
          .btn { display: inline-block; margin-top: 25px; padding: 10px 20px; background: #ef4444; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; }
          .btn:hover { background: #dc2626; }
          pre { background: #020617; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 13px; color: #a5f3fc; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>SAML 2.0 Authenticated Session</h1>
          <p>Authenticated against Keycloak Zero-Trust Identity Provider via SAML Assertion.</p>
          <div>
            <span class="badge">SAML 2.0 WebSSO</span>
            <span class="badge" style="background: #10b981;">NameID: ${user.nameID || user.email || 'N/A'}</span>
          </div>

          <h3>SAML Assertion Attributes</h3>
          <table class="attr-table">
            <tr><th>Attribute</th><th>Value</th></tr>
            <tr><td>User NameID / Email</td><td><strong>${user.nameID || user.email || 'N/A'}</strong></td></tr>
            <tr><td>Department</td><td><strong>${user.department || user.attributes?.department || 'engineering'}</strong></td></tr>
            <tr><td>Clearance Level</td><td><strong>${user.clearance_level || user.attributes?.clearance_level || '3'}</strong></td></tr>
            <tr><td>Session Index</td><td><code>${user.sessionIndex || 'active'}</code></td></tr>
          </table>

          <h3>Raw SAML Profile Payload</h3>
          <pre>${JSON.stringify(user, null, 2)}</pre>

          <a href="/logout" class="btn">Sign Out (SAML Single Logout)</a>
        </div>
      </body>
      </html>
    `);
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SAML 2.0 Service Provider - Sign In</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { max-width: 450px; background: #1e293b; border-radius: 12px; padding: 36px; text-align: center; border: 1px solid #334155; }
        h1 { color: #38bdf8; font-size: 22px; margin-bottom: 8px; }
        p { color: #94a3b8; font-size: 14px; line-height: 1.5; margin-bottom: 24px; }
        .btn { display: inline-block; padding: 12px 28px; background: #0284c7; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; }
        .btn:hover { background: #0369a1; }
        .meta-link { display: block; margin-top: 15px; font-size: 12px; color: #64748b; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Enterprise SAML Portal</h1>
        <p>This legacy enterprise application uses SAML 2.0 protocol for federated single sign-on backed by Keycloak MFA and ABAC policies.</p>
        <a href="/login" class="btn">Sign In via Keycloak SAML IdP</a>
        <a href="/metadata.xml" class="meta-link">View SP Metadata XML</a>
      </div>
    </body>
    </html>
  `);
});

// SP Metadata Endpoint
app.get('/metadata.xml', (req, res) => {
  res.type('application/xml');
  res.status(200).send(samlStrategy.generateServiceProviderMetadata());
});

// Initiate SAML Login
app.get('/login', passport.authenticate('saml', { failureRedirect: '/', failureFlash: false }));

// SAML Assertion Consumer Service Callback
app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

// SAML Single Logout
app.get('/logout', (req, res) => {
  if (req.user) {
    samlStrategy.logout(req, (err, uri) => {
      req.logout(() => {
        if (!err && uri) {
          return res.redirect(uri);
        }
        res.redirect('/');
      });
    });
  } else {
    res.redirect('/');
  }
});

app.listen(PORT, () => {
  console.log(`SAML 2.0 Service Provider listening on http://localhost:${PORT}`);
  console.log(`SP Metadata URL: http://localhost:${PORT}/metadata.xml`);
});
