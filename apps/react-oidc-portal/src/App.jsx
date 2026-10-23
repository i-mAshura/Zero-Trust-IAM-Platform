import React, { useState, useEffect } from 'react';
import { UserManager, WebStorageStateStore } from 'oidc-client-ts';
import { Shield, Key, AlertTriangle, CheckCircle, Lock, RefreshCw, Cpu, Layers, ExternalLink, Activity } from 'lucide-react';

const oidcConfig = {
  authority: "http://localhost:8080/realms/zero-trust-realm",
  client_id: "react-oidc-portal",
  redirect_uri: window.location.origin,
  response_type: "code",
  scope: "openid profile email roles zero_trust_claims",
  userStore: new WebStorageStateStore({ store: window.localStorage })
};

const userManager = new UserManager(oidcConfig);

export default function App() {
  const [user, setUser] = useState(null);
  const [simulatedMode, setSimulatedMode] = useState(false);
  const [activePersona, setActivePersona] = useState('alice');

  // ABAC Context Controls
  const [isManaged, setIsManaged] = useState(true);
  const [isEncrypted, setIsEncrypted] = useState(true);
  const [isCompromised, setIsCompromised] = useState(false);
  const [deviceOs, setDeviceOs] = useState('Windows');
  const [riskScore, setRiskScore] = useState(15);
  const [simulatedHour, setSimulatedHour] = useState(14);
  const [impossibleTravel, setImpossibleTravel] = useState(false);

  // API Call Results
  const [loading, setLoading] = useState(false);
  const [apiResponse, setApiResponse] = useState(null);
  const [stepUpChallenge, setStepUpChallenge] = useState(false);

  // Pre-configured Personas for Instant Testing
  const personas = {
    alice: {
      username: "alice",
      department: "engineering",
      clearance_level: 3,
      roles: ["developer"],
      mfa_verified: true,
      email: "alice@corp.local"
    },
    dan_admin: {
      username: "dan_admin",
      department: "security-operations",
      clearance_level: 4,
      roles: ["admin", "sec-ops"],
      mfa_verified: false, // will require step-up for sensitive actions!
      email: "dan.admin@corp.local"
    },
    bob_contractor: {
      username: "bob",
      department: "contractors",
      clearance_level: 1,
      roles: ["contractor"],
      mfa_verified: true,
      email: "bob@vendor.local"
    }
  };

  useEffect(() => {
    // Check if handling OIDC redirect callback
    if (window.location.search.includes("code=")) {
      userManager.signinCallback().then(user => {
        setUser(user);
        window.history.replaceState({}, document.title, window.location.pathname);
      }).catch(err => {
        console.warn("OIDC Callback handling note:", err.message);
      });
    } else {
      userManager.getUser().then(user => {
        if (user && !user.expired) {
          setUser(user);
        } else {
          // Default to simulated mode for quick interactive demonstration
          setSimulatedMode(true);
        }
      });
    }
  }, []);

  const handleLogin = () => {
    userManager.signinRedirect().catch(err => {
      alert("Keycloak is not yet running on http://localhost:8080. You can test immediately using Interactive Simulation Mode below!\nError: " + err.message);
      setSimulatedMode(true);
    });
  };

  const handleLogout = () => {
    if (user) {
      userManager.signoutRedirect().catch(() => setUser(null));
    } else {
      setUser(null);
    }
  };

  const currentUserData = simulatedMode ? personas[activePersona] : {
    username: user?.profile?.preferred_username || "OIDC User",
    email: user?.profile?.email || "user@realm.local",
    department: user?.profile?.department || "engineering",
    clearance_level: user?.profile?.clearance_level || 3,
    roles: user?.profile?.roles || ["developer"],
    mfa_verified: true
  };

  // Execute ABAC request against Flask API or local evaluation
  const callProtectedApi = async (endpoint, isSensitive = false) => {
    setLoading(true);
    setApiResponse(null);
    setStepUpChallenge(false);

    const headers = {
      "Content-Type": "application/json",
      "X-Device-Managed": isManaged.toString(),
      "X-Device-Encrypted": isEncrypted.toString(),
      "X-Device-Compromised": isCompromised.toString(),
      "X-Device-OS": deviceOs,
      "X-Risk-Score": riskScore.toString(),
      "X-Request-Hour-UTC": simulatedHour.toString(),
      "X-Impossible-Travel": impossibleTravel.toString()
    };

    if (user?.access_token) {
      headers["Authorization"] = `Bearer ${user.access_token}`;
    } else {
      // Send simulated token header
      headers["Authorization"] = `Bearer simulated.${btoa(JSON.stringify(currentUserData))}.signature`;
    }

    try {
      const res = await fetch(`http://localhost:5000${endpoint}`, {
        method: isSensitive ? "POST" : "GET",
        headers: headers
      });

      const data = await res.json();
      setApiResponse({ status: res.status, data });

      if (res.status === 428) {
        setStepUpChallenge(true);
      }
    } catch (err) {
      // If Flask container is not running, run client-side ABAC engine calculation for visual verification
      const reasons = [];
      let allow = true;
      let reqStepUp = false;

      if (!isManaged || !isEncrypted || isCompromised) {
        allow = false;
        reasons.push("Device failed zero-trust endpoint compliance (unmanaged/unencrypted/compromised)");
      }
      if (simulatedHour < 6 || simulatedHour > 22) {
        allow = false;
        reasons.push("Access outside operational window (06:00 - 22:00 UTC)");
      }
      if (riskScore >= 40 || impossibleTravel) {
        allow = false;
        reasons.push("Risk score exceeded or impossible travel detected");
      }
      if (isSensitive) {
        if (!currentUserData.mfa_verified) {
          allow = false;
          reqStepUp = true;
          reasons.push("Sensitive action requires step-up MFA verification");
        }
      }
      if (endpoint.includes("developer") && currentUserData.department !== "engineering") {
        allow = false;
        reasons.push(`Department '${currentUserData.department}' unauthorized for engineering repos`);
      }

      setApiResponse({
        status: allow ? 200 : (reqStepUp ? 428 : 403),
        simulated: true,
        data: {
          decision: {
            allow: allow,
            require_step_up: reqStepUp,
            user_id: currentUserData.username,
            reasons: reasons
          },
          note: "Evaluated via local policy emulator (Flask API offline)"
        }
      });

      if (reqStepUp) {
        setStepUpChallenge(true);
      }
    } finally {
      setLoading(false);
    }
  };

  const fulfillStepUp = () => {
    alert("Step-Up Verification Complete! WebAuthn / TOTP security challenge verified.");
    personas[activePersona].mfa_verified = true;
    setStepUpChallenge(false);
    callProtectedApi('/api/admin/system-purge', true);
  };

  return (
    <div className="container">
      {/* Top Header */}
      <header className="header">
        <div className="logo-group">
          <div className="shield-icon">
            <Shield size={22} color="#fff" />
          </div>
          <div className="title-wrap">
            <h1>Zero-Trust IAM Platform</h1>
            <p>Keycloak 24 + OPA Engine + Terraform Declarative Governance</p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {simulatedMode ? (
            <span className="badge badge-purple">
              <Activity size={14} /> Interactive Simulator Mode
            </span>
          ) : (
            <span className="badge badge-emerald">
              <CheckCircle size={14} /> Live Keycloak OIDC Session
            </span>
          )}

          {user ? (
            <button className="btn btn-secondary" onClick={handleLogout}>
              Sign Out ({user.profile?.preferred_username})
            </button>
          ) : (
            <button className="btn btn-primary" onClick={handleLogin}>
              <Key size={16} /> Sign In via Keycloak
            </button>
          )}
        </div>
      </header>

      {/* Main Grid: User Identity & Policy Workbench */}
      <div className="grid-2">
        {/* Left Column: Identity & Token Attributes */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Key size={20} color="var(--accent-cyan)" />
              Active Identity & Token Claims
            </div>
            <button 
              className="btn btn-secondary" 
              style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              onClick={() => setSimulatedMode(!simulatedMode)}
            >
              Toggle Mode
            </button>
          </div>

          {simulatedMode && (
            <div className="control-group">
              <label className="control-label">Select Persona to Test:</label>
              <select 
                className="select" 
                value={activePersona} 
                onChange={(e) => setActivePersona(e.target.value)}
              >
                <option value="alice">Alice (Engineering, Developer, Clearance 3)</option>
                <option value="dan_admin">Dan (SecOps, Admin Role, Clearance 4)</option>
                <option value="bob_contractor">Bob (Contractor, Clearance 1, Restricted)</option>
              </select>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
            <div style={{ background: 'rgba(15,23,42,0.6)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>USERNAME</div>
              <div style={{ fontWeight: 700, color: '#fff' }}>{currentUserData.username}</div>
            </div>
            <div style={{ background: 'rgba(15,23,42,0.6)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>DEPARTMENT</div>
              <div style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>{currentUserData.department}</div>
            </div>
            <div style={{ background: 'rgba(15,23,42,0.6)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CLEARANCE LEVEL</div>
              <div style={{ fontWeight: 700, color: 'var(--accent-emerald)' }}>Level {currentUserData.clearance_level}</div>
            </div>
            <div style={{ background: 'rgba(15,23,42,0.6)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>MFA STATUS</div>
              <div style={{ fontWeight: 700, color: currentUserData.mfa_verified ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                {currentUserData.mfa_verified ? "Enforced (TOTP/WebAuthn)" : "Unverified"}
              </div>
            </div>
          </div>

          <div className="control-label">ROLES & GROUPS</div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
            {currentUserData.roles.map(r => (
              <span key={r} className="badge badge-cyan">{r}</span>
            ))}
          </div>

          <div className="control-label">RAW OIDC CLAIMS (JWT)</div>
          <pre className="code-block">
            {JSON.stringify(currentUserData, null, 2)}
          </pre>
        </div>

        {/* Right Column: Zero-Trust Context Simulator */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={20} color="var(--accent-purple)" />
              Zero-Trust Context Simulator
            </div>
            <span className="badge badge-purple">ABAC Signal Injection</span>
          </div>

          <div className="toggle-switch">
            <span>Corporate Managed Device</span>
            <input 
              type="checkbox" 
              checked={isManaged} 
              onChange={e => setIsManaged(e.target.checked)} 
            />
          </div>

          <div className="toggle-switch">
            <span>Disk BitLocker / FileVault Encrypted</span>
            <input 
              type="checkbox" 
              checked={isEncrypted} 
              onChange={e => setIsEncrypted(e.target.checked)} 
            />
          </div>

          <div className="toggle-switch">
            <span>Compromised / Jailbroken</span>
            <input 
              type="checkbox" 
              checked={isCompromised} 
              onChange={e => setIsCompromised(e.target.checked)} 
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
            <div>
              <label className="control-label">Endpoint OS:</label>
              <select className="select" value={deviceOs} onChange={e => setDeviceOs(e.target.value)}>
                <option value="Windows">Windows 11 Enterprise</option>
                <option value="macOS">macOS Sonoma</option>
                <option value="Linux">Ubuntu Linux</option>
                <option value="Unknown">Unknown / Untrusted OS</option>
              </select>
            </div>
            <div>
              <label className="control-label">Simulated UTC Hour ({simulatedHour}:00):</label>
              <input 
                type="range" 
                min="0" 
                max="23" 
                value={simulatedHour} 
                onChange={e => setSimulatedHour(parseInt(e.target.value))}
                style={{ width: '100%', marginTop: '10px' }}
              />
            </div>
          </div>

          <div className="control-group">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <label className="control-label">Contextual Risk Score ({riskScore}/100):</label>
              <span style={{ fontSize: '0.8rem', color: riskScore >= 40 ? 'var(--accent-rose)' : 'var(--accent-emerald)', fontWeight: 700 }}>
                {riskScore >= 40 ? "HIGH RISK" : "NORMAL RISK"}
              </span>
            </div>
            <input 
              type="range" 
              min="0" 
              max="100" 
              value={riskScore} 
              onChange={e => setRiskScore(parseInt(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>

          {/* Test Buttons */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '20px' }}>
            <button 
              className="btn btn-primary" 
              disabled={loading}
              onClick={() => callProtectedApi('/api/developer/repos')}
            >
              Test Developer Repos (ABAC)
            </button>

            <button 
              className="btn btn-danger" 
              disabled={loading}
              onClick={() => callProtectedApi('/api/admin/system-purge', true)}
            >
              <Lock size={16} /> Admin Purge (Step-Up)
            </button>
          </div>
        </div>
      </div>

      {/* Step-Up Auth Modal / Challenge Alert */}
      {stepUpChallenge && (
        <div className="card" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--accent-rose)', marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <AlertTriangle size={28} color="var(--accent-rose)" />
              <div>
                <h3 style={{ color: '#fff', fontSize: '1.1rem' }}>Conditional Step-Up MFA Challenge Triggered!</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                  Sensitive administrative action detected. Zero-Trust policy requires immediate cryptographic hardware token re-verification.
                </p>
              </div>
            </div>
            <button className="btn btn-primary" onClick={fulfillStepUp}>
              Verify Hardware Token (WebAuthn)
            </button>
          </div>
        </div>
      )}

      {/* Live Policy Decision Output */}
      {apiResponse && (
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <div className="card-title">
              <Layers size={20} color="var(--accent-cyan)" />
              OPA Policy Engine Evaluation Result
            </div>
            <span className={`badge ${apiResponse.status === 200 ? 'badge-emerald' : apiResponse.status === 428 ? 'badge-rose' : 'badge-rose'}`}>
              HTTP {apiResponse.status} - {apiResponse.status === 200 ? 'ACCESS GRANTED' : apiResponse.status === 428 ? 'STEP-UP REQUIRED' : 'ACCESS DENIED'}
            </span>
          </div>

          <pre className="code-block">
            {JSON.stringify(apiResponse, null, 2)}
          </pre>
        </div>
      )}

      {/* Enterprise Architecture Map */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Layers size={20} color="var(--accent-cyan)" />
            Zero-Trust IAM Ecosystem Connected Apps
          </div>
        </div>

        <div className="grid-3">
          <div style={{ background: 'rgba(15,23,42,0.7)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <strong>Flask REST API</strong>
              <span className="badge badge-cyan">OIDC Bearer</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              Enforces OPA Rego ABAC policies on department, clearance, device posture, and UTC work hours.
            </p>
            <code style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>http://localhost:5000</code>
          </div>

          <div style={{ background: 'rgba(15,23,42,0.7)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <strong>Spring Boot API</strong>
              <span className="badge badge-emerald">Resource Server</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              Spring Security 6 with custom Keycloak JWT converter mapping roles and claims to GrantedAuthorities.
            </p>
            <code style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)' }}>http://localhost:8081</code>
          </div>

          <div style={{ background: 'rgba(15,23,42,0.7)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <strong>SAML 2.0 Portal</strong>
              <span className="badge badge-purple">SAML WebSSO</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              Enterprise Service Provider handling signed XML SAML assertions with attribute mapping from Keycloak.
            </p>
            <code style={{ fontSize: '0.75rem', color: 'var(--accent-purple)' }}>http://localhost:4000</code>
          </div>
        </div>
      </div>
    </div>
  );
}
