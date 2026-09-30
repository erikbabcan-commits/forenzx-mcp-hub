"""Docker sandbox hardening with canonical RepoDigest verification."""

from __future__ import annotations

import hmac
import re
from typing import Any, Dict, List

try:
    import docker  # type: ignore
except ImportError:  # Allows control-plane/dashboard tests without Docker SDK installed.
    docker = None  # type: ignore

from core.utils.logger import get_logger

logger = get_logger(__name__)
DIGEST_RE = re.compile(r"sha256:[a-fA-F0-9]{64}")


class DockerDigestVerificationError(Exception):
    pass


def canonical_digest(value: str) -> str:
    match = DIGEST_RE.search(value or "")
    if not match:
        raise DockerDigestVerificationError(f"No canonical sha256 RepoDigest found in: {value!r}")
    return match.group(0).lower()


class SandboxSecurityManager:
    @staticmethod
    def verify_image_digest(image: str, pinned_digest: str, client: Any = None) -> str:
        pinned = canonical_digest(pinned_digest)
        if docker is None and client is None:
            raise DockerDigestVerificationError("Docker SDK is not installed")
        try:
            client = client or docker.from_env()
            image_obj = client.images.get(image)
            repo_digests = image_obj.attrs.get("RepoDigests", []) or []
            if not repo_digests:
                raise DockerDigestVerificationError(
                    f"Image {image} has no trustworthy RepoDigests; short image IDs are not accepted"
                )
            candidates = [canonical_digest(x) for x in repo_digests]
            for actual in candidates:
                if hmac.compare_digest(actual, pinned):
                    logger.info(f"Docker image digest verified: {image} @ {actual}")
                    return actual
            raise DockerDigestVerificationError(
                f"IMAGE_DIGEST_MISMATCH: expected {pinned}, got {', '.join(candidates)}"
            )
        except DockerDigestVerificationError:
            raise
        except Exception as exc:
            raise DockerDigestVerificationError(f"Failed to verify image digest: {exc}") from exc

    @staticmethod
    def get_config(
        image: str,
        mounts: List[Dict[str, Any]],
        cmd: List[str],
        mem_mb: int,
        cpu_cores: float,
        net: bool,
        pinned_digest: str,
        client: Any = None,
    ) -> Dict[str, Any]:
        SandboxSecurityManager.verify_image_digest(image, pinned_digest, client=client)
        cfg: Dict[str, Any] = {
            "image": image,
            "command": list(cmd),
            "network_mode": "none" if not net else "bridge",
            "read_only": True,
            "mem_limit": f"{mem_mb}m",
            "memswap_limit": f"{mem_mb}m",
            "cpu_period": 100000,
            "cpu_quota": int(cpu_cores * 100000),
            "pids_limit": 128,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": {"/tmp": "size=512m,noexec,nosuid,nodev"},
            "stdin_open": False,
            "tty": False,
            "detach": True,
            "volumes": {},
        }
        for m in mounts:
            cfg["volumes"][str(m["host_path"])] = {"bind": str(m["container_path"]), "mode": m.get("mode", "ro")}
        return cfg
