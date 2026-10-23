# Zero-Trust IAM Platform - Operational Runbook

This runbook guides you through deploying, verifying, and testing the entire Zero-Trust IAM Platform.

---

## Prerequisites

- **Terraform**: v1.16+ (installed and verified)
- **Node.js**: v20+ / v24+ (installed and verified)
- **Python**: 3.11+ (installed and verified)
- **Java**: JDK 17+ or 23 (installed and verified)
- **Docker Desktop**: Running on Windows or WSL2

---

## Step 1: Start the Infrastructure Stack

Launch PostgreSQL 16, Keycloak 24, Open Policy Agent, and Fluent Bit:

```powershell
# From project root
docker-compose up -d
```

### Health Check Endpoints
- **Keycloak Admin Console**: [http://localhost:8080](http://localhost:8080) (Credentials: `admin` / `admin123`)
- **Open Policy Agent (OPA)**: [http://localhost:8181/health](http://localhost:8181/health)
- **Postgres Database**: `localhost:5432` (`keycloak` / `keycloak_secret_pass`)

---

## Step 2: Provision Identity & Access Infrastructure with Terraform

Once Keycloak is responding at `http://localhost:8080`:

```powershell
cd terraform

# Refresh environment variables to ensure terraform is in path
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Apply declarative IAM state
terraform init
terraform apply -auto-approve
```

### What Terraform Provisions:
1. `zero-trust-realm`: Strict timeouts, password complexity, and event logging.
2. `authentication_flows`: Enforces Password + MFA (TOTP/WebAuthn) and Step-Up challenge.
3. `roles_groups`: `admin`, `sec-ops`, `developer`, `contractor`, `auditor`, and department groups.
4. `sample_users`: `alice` (Engineering), `dan_admin` (SecOps Admin), `bob` (Contractor).
5. `clients`:
   - `react-oidc-portal`: Public client with PKCE (`S256`).
   - `flask-api-service`: Confidential client with client secret.
   - `spring-boot-resource-server`: Confidential resource server.
   - `saml-node-app`: SAML 2.0 Service Provider.

---

## Step 3: Run the Sample Applications

### A. React User Portal (OIDC PKCE + ABAC Console)
```powershell
cd apps\react-oidc-portal
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173). You can immediately test live login or use the interactive Zero-Trust Context Simulator to test device posture, risk scores, and step-up challenges.

### B. Flask REST API (OPA ABAC Middleware)
```powershell
cd apps\flask-api
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Listens on [http://localhost:5000](http://localhost:5000).

### C. Spring Boot Backend API (OAuth2 Resource Server)
```powershell
cd apps\spring-boot-api
# Build and run
mvn spring-boot:run
```
Listens on [http://localhost:8081](http://localhost:8081).

### D. SAML 2.0 Enterprise Service Provider
```powershell
cd apps\saml-node-app
npm install
npm start
```
Listens on [http://localhost:4000](http://localhost:4000). Provides SAML SP metadata at [http://localhost:4000/metadata.xml](http://localhost:4000/metadata.xml).

---

## Step 4: Audit Logging & Wazuh / ARGUS Forwarding

1. Check local audit event stream captured by Fluent Bit:
   ```powershell
   Get-Content .\logging\audit-output\keycloak-audit-events.json -Tail 20
   ```
2. To forward live to your remote Wazuh Manager, configure `.env`:
   ```ini
   WAZUH_MANAGER_IP=192.168.1.100 # Your Wazuh Manager IP
   WAZUH_SYSLOG_PORT=514
   ```
3. Copy `logging/wazuh_rule_sample.xml` to your Wazuh Manager's `/var/ossec/etc/rules/local_rules.xml` and restart Wazuh:
   ```bash
   systemctl restart wazuh-manager
   ```

---

## Step 5: Benchmark Application Onboarding

Run the automated onboarding benchmark:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark-onboarding.ps1
```
View the results and analysis in `docs/metrics_record.md`.
