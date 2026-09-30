#!/usr/bin/env sh
set -eu
[ -f .env ] || cp .env.example .env
python - <<'PY'
from pathlib import Path
import secrets, re
p=Path('.env')
s=p.read_text()
s=s.replace('CHANGE_ME_WITH_AT_LEAST_32_RANDOM_CHARACTERS', secrets.token_urlsafe(48), 1)
s=s.replace('CHANGE_ME_WITH_AT_LEAST_32_RANDOM_CHARACTERS', secrets.token_urlsafe(48), 1)
s=s.replace('CHANGE_ME_ANALYST_KEY', secrets.token_urlsafe(32))
s=s.replace('CHANGE_ME_ADMIN_KEY', secrets.token_urlsafe(32))
p.write_text(s)
print('Created .env with random secrets. Review ALLOWED_ORIGINS before production.')
PY
chmod 600 .env || true
