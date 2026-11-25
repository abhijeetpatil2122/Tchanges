#!/usr/bin/env python3
"""Replay Telegram notifications for data commits whose original send failed."""

import argparse
import asyncio
import os
import subprocess
from pathlib import Path

import main


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_changes(repo: Path, sha: str):
    git(repo, "cat-file", "-e", f"{sha}^{{commit}}")
    output = git(repo, "show", "--format=", "--name-status", "--no-renames", sha)
    new_files, updated_files, removed_files = [], [], []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if status == "A":
            new_files.append(path)
        elif status == "D":
            removed_files.append(path)
        else:
            updated_files.append(path)
    subject = git(repo, "log", "-1", "--format=%s", sha)
    return subject, sorted(new_files), sorted(updated_files), sorted(removed_files)


async def replay(env: str, sha: str, repo: Path, repo_url: str):
    subject, new_files, updated_files, removed_files = commit_changes(repo, sha)
    if not (new_files or updated_files or removed_files):
        print(f"[replay:{env}] Commit {sha[:12]} has no file changes; skipping")
        return

    base_url = repo_url.removesuffix(".git").replace(
        "git@github.com:", "https://github.com/"
    )
    extra_sections = []
    if removed_files:
        extra_sections.extend([
            main._rich_heading("🗑 Removed Files", 3),
            main._rich_file_list([f"`{name}`" for name in removed_files[:35]]),
        ])

    blocks = main._rich_notification_blocks(
        title="📬 Recovered Change Notification",
        environment="production" if env == "prod" else "test",
        updated_names=updated_files,
        new_names=new_files,
        ai_text=(
            f"Notification replay for an existing data commit. "
            f"Original commit: {subject}. No new data was committed by this replay."
        ),
        commit_url=f"{base_url}/commit/{sha}",
        extra_sections=extra_sections,
    )
    print(
        f"[replay:{env}] Replaying {sha[:12]} "
        f"(new={len(new_files)}, updated={len(updated_files)}, removed={len(removed_files)})"
    )
    delivered = await main.send_telegram_notification(blocks, f"replay-{env}")
    if not delivered:
        raise RuntimeError(f"Telegram rejected replay notification for {env} commit {sha}")


async def run(args):
    repo = Path(os.getenv("DATA_REPOSITORY_DIR", "data-repository")).resolve()
    repo_url = os.getenv("DATA_REPOSITORY_URL", "").strip()
    if not repo_url:
        raise RuntimeError("DATA_REPOSITORY_URL is required")
    if not main.CONFIG["telegram"].get("token"):
        raise RuntimeError("TG_BOT_TOKEN_PROD is missing")

    targets = (("prod", args.prod_commit), ("test", args.test_commit))
    for env, sha in targets:
        if sha:
            await replay(env, sha, repo, repo_url)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay missed Telegram notifications for existing data commits."
    )
    parser.add_argument("--prod-commit", default="")
    parser.add_argument("--test-commit", default="")
    args = parser.parse_args()
    if not args.prod_commit and not args.test_commit:
        parser.error("Provide at least one of --prod-commit or --test-commit")
    return args


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
