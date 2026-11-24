"""Local operator workflow for scoped reporter credentials; no public minting API."""

from __future__ import annotations

import argparse
import hashlib
import os
import time
import uuid
from pathlib import Path

import jwt

from core.acl import TokenUser, case_access_provider
from core.config import config
from core.db import db, utcnow


def credential_digest(token: str) -> str:
    # Hash the authenticated signing input, not the textual signature. Equivalent
    # base64url spellings of the signature must not bypass a revocation.
    header, payload, _signature = token.split(".")
    return hashlib.sha256(f"{header}.{payload}".encode("ascii")).hexdigest()


def is_revoked(token: str) -> bool:
    """Called only after JWT signature/expiry validation; DB errors propagate."""
    return (
        db.fetchone("SELECT 1 FROM revoked_reporter_tokens WHERE token_sha256=?", (credential_digest(token),))
        is not None
    )


def issue_reporter(*, subject: str, organization: str, case_id: str, job_ids: list[str], ttl: int = 900) -> str:
    if not subject.strip() or not organization.strip() or not case_id.strip() or not job_ids or not 1 <= ttl <= 3600:
        raise ValueError("Invalid reporter scope or TTL (1..3600 seconds)")
    user = TokenUser(
        user_id=subject,
        organization=organization,
        roles=["reporter"],
        report_case_ids=[case_id],
        report_job_ids=job_ids,
    )
    if not all(case_access_provider.can_access_job(user, job, case_id) for job in job_ids):
        raise ValueError("Reporter scope is not registered for this organization and case")
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "organization": organization,
            "roles": ["reporter"],
            "report_case_ids": [case_id],
            "report_job_ids": sorted(set(job_ids)),
            "iat": now,
            "exp": now + ttl,
            "jti": str(uuid.uuid4()),
        },
        config.jwt_secret_key,
        algorithm="HS256",
    )


def revoke_reporter(token: str) -> None:
    # Allow an operator to record revocation of an already-expired credential.
    claims = jwt.decode(
        token, config.jwt_secret_key, algorithms=["HS256"], options={"require": ["exp"], "verify_exp": False}
    )
    roles = claims.get("roles")
    if isinstance(roles, str):
        roles = [roles]
    if not isinstance(roles, list) or "reporter" not in roles:
        raise ValueError("Only reporter credentials may be revoked here")
    db.execute(
        "INSERT OR IGNORE INTO revoked_reporter_tokens(token_sha256,revoked_at) VALUES (?,?)",
        (credential_digest(token), utcnow()),
    )


def write_private_token(path: Path, token: str) -> None:
    # O_EXCL rejects existing files and symlinks. Never print bearer credentials.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as output:
        output.write(token + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    register = commands.add_parser("register-case")
    register.add_argument("--case-id", required=True)
    register.add_argument("--owner", required=True)
    register.add_argument("--organization", required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("--subject", required=True)
    issue.add_argument("--organization", required=True)
    issue.add_argument("--case-id", required=True)
    issue.add_argument("--job-id", action="append", required=True)
    issue.add_argument("--ttl", type=int, default=900)
    issue.add_argument("--output", type=Path, required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "register-case":
            if not all(value.strip() for value in (args.case_id, args.owner, args.organization)):
                raise ValueError("Empty case registration")
            case_access_provider.register_case(args.case_id, args.owner, args.organization)
        elif args.action == "issue":
            token = issue_reporter(
                subject=args.subject,
                organization=args.organization,
                case_id=args.case_id,
                job_ids=args.job_id,
                ttl=args.ttl,
            )
            write_private_token(args.output, token)
        else:
            revoke_reporter(args.token_file.read_text(encoding="ascii").strip())
    except Exception:
        # Library exceptions may embed input. Keep operator output content-free.
        print("REPORTER_OPERATION_FAILED")
        return 1
    print("REPORTER_OPERATION_COMPLETED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
