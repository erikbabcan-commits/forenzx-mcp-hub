#!/usr/bin/env bash
# ForenZX MCP Hub - Authentik Automated Setup (Bash)
# Generates high-entropy secrets and initializes Authentik environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

echo -e "\033[1;36m==========================================================\033[0m"
echo -e "\033[1;36m  ForenZX MCP Hub - Authentik IdP Provisioning Assistant  \033[0m"
echo -e "\033[1;36m==========================================================\033[0m"

ENV_FILE=".env.authentik"

mkdir -p authentik/media authentik/custom-templates authentik/blueprints

if [ ! -f "${ENV_FILE}" ]; then
    echo -e "\033[1;33m[*] Generating high-entropy cryptographic secrets...\033[0m"
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    CLIENT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

    cat > "${ENV_FILE}" <<EOF
# ForenZX MCP Hub - Auto-generated Authentik Configuration
AUTHENTIK_SECRET_KEY=${SECRET_KEY}
AUTHENTIK_POSTGRESQL_USER=authentik
AUTHENTIK_POSTGRESQL_NAME=authentik
AUTHENTIK_POSTGRESQL_PASSWORD=${DB_PASSWORD}
AUTHENTIK_FORENZX_CLIENT_SECRET=${CLIENT_SECRET}
AUTHENTIK_PORT_HTTP=9000
AUTHENTIK_PORT_HTTPS=9443
EOF
    chmod 600 "${ENV_FILE}"
    echo -e "\033[1;32m[+] Generated ${ENV_FILE} with 0600 permissions.\033[0m"
else
    echo -e "\033[0;37m[i] Existing ${ENV_FILE} found. Skipping generation.\033[0m"
fi

echo -e "\n\033[1;32m[+] Setup completed successfully!\033[0m"
echo -e "To start ForenZX MCP Hub with Authentik, run:"
echo -e "  \033[1;33mdocker compose -f docker-compose.yml -f docker-compose.authentik.yml --env-file .env --env-file .env.authentik up -d\033[0m"
echo -e "\nInitial Authentik Admin Setup URL:"
echo -e "  \033[1;36mhttp://localhost:9000/if/flow/initial-setup/\033[0m"
echo -e "\033[1;36m==========================================================\033[0m"
