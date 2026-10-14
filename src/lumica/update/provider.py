"""Thin subprocess wrapper around git. No third-party git libraries."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


class NetworkError(GitError):
    """git could not reach the remote (no internet, DNS, GitHub down)."""


_NETWORK_MARKERS = (
    "could not resolve host",
    "unable to access",
    "failed to connect",
    "connection timed out",
    "connection refused",
    "network is unreachable",
    "temporary failure in name resolution",
    "could not read from remote repository",
    "the remote end hung up",
    "ssl",
    "early eof",
)


def _run(repo_dir: Path, *args: str, timeout: int = 60) -> str:
    # Never block on an interactive credential prompt when running as a service.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        raise GitError("git не установлен") from exc
    except subprocess.TimeoutExpired as exc:
        if args and args[0] in {"fetch", "ls-remote"}:
            raise NetworkError(f"git {args[0]}: превышено время ожидания (нет связи с GitHub?)") from exc
        raise GitError(f"git {' '.join(args)}: превышено время ожидания") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        message = f"git {' '.join(args)} завершился с ошибкой: {detail}"
        if args and args[0] in {"fetch", "ls-remote"} and any(m in detail.lower() for m in _NETWORK_MARKERS):
            raise NetworkError(f"нет доступа к репозиторию (проверьте интернет/GitHub): {detail[-300:]}")
        raise GitError(message)
    return result.stdout.strip()


def current_sha(repo_dir: Path) -> str:
    return _run(repo_dir, "rev-parse", "HEAD")


def current_branch(repo_dir: Path) -> str:
    return _run(repo_dir, "rev-parse", "--abbrev-ref", "HEAD")


def is_dirty(repo_dir: Path) -> bool:
    """True only for modified *tracked* files (ignored/untracked files such as
    .env and database/ never count)."""
    return bool(_run(repo_dir, "status", "--porcelain", "--untracked-files=no"))


def fetch(repo_dir: Path, remote: str) -> None:
    _run(repo_dir, "fetch", "--prune", "--tags", remote, timeout=120)


def remote_sha(repo_dir: Path, remote: str, branch: str) -> str:
    fetch(repo_dir, remote)
    try:
        return _run(repo_dir, "rev-parse", f"{remote}/{branch}")
    except GitError as exc:
        raise GitError(f"ветка {branch} не найдена в {remote}") from exc


def describe(repo_dir: Path, sha: str) -> str:
    """Human-friendly version label: `<tag-or-sha> (<commit date>)`."""
    if not sha:
        return "неизвестно"
    try:
        label = _run(repo_dir, "describe", "--tags", "--always", sha)
    except GitError:
        label = sha[:8]
    try:
        date = _run(repo_dir, "show", "-s", "--format=%cs", sha)
    except GitError:
        date = ""
    return f"{label} ({date})" if date else label


def subject(repo_dir: Path, sha: str) -> str:
    try:
        return _run(repo_dir, "show", "-s", "--format=%s", sha)
    except GitError:
        return ""


def paths_changed(repo_dir: Path, old_sha: str, new_sha: str, *paths: str) -> bool:
    """True if any of `paths` differ between two commits (unknown -> True)."""
    try:
        return bool(_run(repo_dir, "diff", "--name-only", old_sha, new_sha, "--", *paths))
    except GitError:
        return True


def stash_local_changes(repo_dir: Path, label: str) -> None:
    _run(repo_dir, "stash", "push", "-m", label)


def reset_hard(repo_dir: Path, sha: str) -> None:
    _run(repo_dir, "reset", "--hard", sha)


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
    "NetworkError",
    "current_sha",
    "current_branch",
    "is_dirty",
    "fetch",
    "remote_sha",
    "describe",
    "subject",
    "paths_changed",
    "stash_local_changes",
    "reset_hard",
    "checkout_remote",
]
