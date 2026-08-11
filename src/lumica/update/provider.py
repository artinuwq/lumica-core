"""Thin subprocess wrapper around git. No third-party git libraries."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _run(repo_dir: Path, *args: str, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args)} timed out") from exc

    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def current_sha(repo_dir: Path) -> str:
    return _run(repo_dir, "rev-parse", "HEAD")


def current_branch(repo_dir: Path) -> str:
    return _run(repo_dir, "rev-parse", "--abbrev-ref", "HEAD")


def is_dirty(repo_dir: Path) -> bool:
    return bool(_run(repo_dir, "status", "--porcelain"))


def fetch(repo_dir: Path, remote: str) -> None:
    _run(repo_dir, "fetch", "--prune", remote, timeout=120)


def remote_sha(repo_dir: Path, remote: str, branch: str) -> str:
    fetch(repo_dir, remote)
    return _run(repo_dir, "rev-parse", f"{remote}/{branch}")


def checkout_remote(repo_dir: Path, remote: str, branch: str) -> None:
    """fetch -> checkout branch (creating it from remote if needed) -> hard reset to remote."""
    fetch(repo_dir, remote)

    local_branches = _run(repo_dir, "branch", "--list", branch)
    current = current_branch(repo_dir)
    if local_branches:
        if current != branch:
            _run(repo_dir, "checkout", branch)
    else:
        _run(repo_dir, "checkout", "-b", branch, f"{remote}/{branch}")

    _run(repo_dir, "reset", "--hard", f"{remote}/{branch}")


__all__ = [
    "GitError",
    "current_sha",
    "current_branch",
    "is_dirty",
    "fetch",
    "remote_sha",
    "checkout_remote",
]
