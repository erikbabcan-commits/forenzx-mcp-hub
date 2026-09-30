# ForenZX MCP Hub — task runner
# `make verify` is the local equivalent of CI (same commands as .github/workflows/ci.yml)

POETRY ?= poetry
PY := $(shell $(POETRY) run which python 2>/dev/null || echo python3)

.PHONY: help install lock lint format format-check typecheck test security verify run docker-build docker-up docker-down compose-check backup db-check clean

help:
	@echo "install        poetry install (requires poetry.lock; run 'make lock' first)"
	@echo "lock           poetry lock && poetry check --lock (reproducible dependencies)"
	@echo "lint           ruff check ."
	@echo "format         ruff format ."
	@echo "format-check    ruff format --check ."
	@echo "typecheck       mypy core"
	@echo "test            pytest -q"
	@echo "security        scripts/security_scan.py (must report 0 findings)"
	@echo "verify          compileall + lint + format-check + typecheck + test + security (CI gate)"
	@echo "run             uvicorn core.main:app (development)"
	@echo "docker-build    docker compose build"
	@echo "compose-check   docker compose config (validate compose file)"
	@echo "backup          WAL-consistent SQLite backup into BACKUPS_DIR"
	@echo "db-check        PRAGMA quick_check + schema version on the live DB"
	@echo "clean           caches and local scratch"

lock:
	$(POETRY) lock
	$(POETRY) check --lock

install:
	$(POETRY) install

lint:
	$(POETRY) run ruff check .

format:
	$(POETRY) run ruff format .

format-check:
	$(POETRY) run ruff format --check .

typecheck:
	$(POETRY) run mypy core

test:
	$(POETRY) run pytest -q

security:
	$(POETRY) run python scripts/security_scan.py
	@find core packs workers -name '*.py' | xargs grep -l 'CHANGE_ME' >/dev/null 2>&1 \
		&& { echo 'SECURITY FAIL: CHANGE_ME placeholder in production code'; exit 1; } || true

compile:
	$(PY) -m compileall -q core packs workers

# Full local CI gate. Must be green before every push.
verify: compile lint format-check typecheck test security
	@echo "verify: ALL CHECKS PASSED"

run:
	$(POETRY) run uvicorn core.main:app --host 0.0.0.0 --port 8000 --reload

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

compose-check:
	docker compose config -q && echo "compose config: OK"

backup:
	$(PY) -c "from core.maintenance import backup_database, verify_backup, read_backup_manifest; p = backup_database(); print('backup:', p); print(read_backup_manifest(p)); print(verify_backup(p))"

db-check:
	$(PY) -c "from core.db import db; from core.maintenance import database_integrity_check; print('schema_version:', db.schema_version(), '/ expected:', db.expected_schema_version()); print(database_integrity_check())"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
