# Authentik Identity Provider (IdP) Integration Guide

ForenZX MCP Hub v5 supports enterprise OpenID Connect (OIDC) authentication using **Authentik** as an on-premise, self-hosted Identity and Access Management (IAM) provider.

---

## 1. Architektúra a princíp fungovania

```text
[ AI Agent / Používateľ ] 
         │
         ▼
[ Authentik IdP (Port 9000) ] ────► Vystaví OIDC JWT (RS256) so skupinami
         │
         ▼ (Authorization: Bearer <JWT>)
[ ForenZX MCP Hub (Port 8000) ]
         │
         ├──► Overí podpis cez JWKS endpoint (http://authentik-server:9000/...)
         ├──► Namapuje skupiny na TokenUser(roles, organization)
         └──► Vykoná forenzný príkaz v sandboxe a podpíše výsledok (Ed25519)
```

### Kľúčové výhody:
* **Žiadne mesačné poplatky ani závislosť na cudzom cloude** (100 % open-source, on-premise).
* **Automatický setup cez Blueprinty (IaC)** – žiadne manuálne preklikávanie nastavení.
* **Podpora pre M2M Service Accounts** – trvalé tokeny pre AI agentov (Claude, Cursor, IDE).
* **Enterprise SSO federácia** – možnosť pripojiť firemné Google Workspace, Microsoft Entra ID (Azure AD) alebo Okta cez SAML/OIDC.

---

## 2. Rýchly štart

### Krok 1: Inicializácia a vygenerovanie kľúčov
Skript automaticky vygeneruje kryptograficky bezpečné heslá a vytvorí konfiguračný súbor `.env.authentik`:

* **Na Windows (PowerShell):**
  ```powershell
  pwsh scripts/setup_authentik.ps1
  ```
* **Na Linuxe / VPS (Bash):**
  ```bash
  chmod +x scripts/setup_authentik.sh
  ./scripts/setup_authentik.sh
  ```

### Krok 2: Spustenie kontajnerov cez Docker Compose
Spustite ForenZX MCP Hub spolu so stackom Authentik (PostgreSQL + Redis + Server + Worker):

```bash
docker compose -f docker-compose.yml -f docker-compose.authentik.yml --env-file .env --env-file .env.authentik up -d
```

---

## 3. Prvé prihlásenie a administrácia Authentiku

1. Otvorte prehliadač na adrese prvotného nastavenia administrátora:
   ```text
   http://localhost:9000/if/flow/initial-setup/
   ```
2. Nastavte heslo pre používateľa `akadmin`.
3. Prejdite do **Admin Interface** (`http://localhost:9000/if/admin/`).

---

## 4. Automaticky aplikovaný Blueprint

Pri štarte Authentik automaticky načíta náš deklaratívny blueprint `authentik/blueprints/forenzx-mcp.yaml`. Tento blueprint automaticky vytvorí:

1. **Skupiny (User Groups):**
   * `forenzx_admins` – prístup k správe MCP serverov, údržbe a všetkým prípadom.
   * `forenzx_analysts` – spúšťanie forenzných analýz a prehliadanie výsledkov.
   * `forenzx_auditors` – read-only kontrola digitálne podpísaných záznamov.
2. **Scope Mapping (`ForenZX Role Claims`):**
   * Automaticky do JWT tokenu pridá pole `roles: ["admin", "analyst"]` a `organization`.
3. **OIDC Provider & Application:**
   * Klientské ID: `forenzx-mcp-hub`
   * Redirect URI: `http://localhost:8000/auth/callback`

---

## 5. Vytvorenie M2M tokenu pre AI agentov (Claude / Cursor / IDE)

Pre pripojenie AI agentov do MCP Hubu nepotrebujete prehliadač:

1. V Authentik Admin rozhraní otvorte: **Directory** ➔ **Service Accounts**.
2. Kliknite na **Create**:
   * Username: `mcp-ai-agent`
   * Vytvoriť service account a priradiť do skupiny `forenzx_analysts` (alebo `forenzx_admins`).
3. Skopírujte vygenerovaný **User Token**.
4. Tento token použijete v konfigurácii MCP klienta (`claude_desktop_config.json` alebo Cursor):
   ```json
   {
     "mcpServers": {
       "forenzx": {
         "url": "http://localhost:8000/mcp",
         "headers": {
           "Authorization": "Bearer <VYGENEROVANY_TOKEN_Z_AUTHENTIKU>"
         }
       }
     }
   }
   ```

---

## 6. Zapnutie OIDC overovania vo ForenZX MCP Hube

V súbore `.env` (alebo v produkčnom prostredí) nastavte:

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER_URL=http://authentik-server:9000/application/o/forenzx-mcp-hub/
OIDC_JWKS_URL=http://authentik-server:9000/application/o/forenzx-mcp-hub/jwks/
OIDC_AUDIENCE=forenzx-mcp-hub
```

> **Poznámka:** Ak je `OIDC_ENABLED=true`, ForenZX automaticky overuje RS256/ES256 tokeny z Authentiku. Lokálne HS256 JWT kľúče a API kľúče (`X-API-Key`) naďalej fungujú ako záložný kanál.
