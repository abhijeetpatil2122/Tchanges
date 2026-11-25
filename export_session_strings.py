#!/usr/bin/env python3
"""Export existing Pyrogram SQLite sessions as compact session strings.

This does not request login codes or create new authorizations. It reads the
existing production/test .session files in the current directory.
"""
import argparse
import asyncio
import os
from pathlib import Path

from pyrogram import Client

WORKDIR = Path.cwd()
SESSION_PREFIX = ".telegram-method-checker"
OUTPUT = WORKDIR / "sessions.env"


async def export_one(env: str, api_id: int, api_hash: str):
    name = f"{SESSION_PREFIX}-{env}"
    path = WORKDIR / f"{name}.session"

    if not path.is_file() or path.stat().st_size == 0:
        print(f"[SKIP] {env}: session file not found: {path.name}")
        return None

    app = Client(
        name,
        api_id,
        api_hash,
        test_mode=(env == "test"),
        workdir=str(WORKDIR),
        no_updates=True,
    )

    try:
        await app.connect()
        me = await app.get_me()
        session_string = await app.export_session_string()
        print(
            f"[OK] {env}: exported authorized session "
            f"for user ID {me.id} ({len(session_string)} characters)"
        )
        return f"TELEGRAM_SESSION_{env.upper()}={session_string}"
    finally:
        if app.is_connected:
            await app.disconnect()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--env", choices=("prod", "test", "both"), default="both"
    )
    args = parser.parse_args()

    api_id = int(input("Telegram API ID: ").strip())
    api_hash = input("Telegram API Hash: ").strip()

    envs = ("prod", "test") if args.env == "both" else (args.env,)
    lines = []

    for env in envs:
        line = await export_one(env, api_id, api_hash)
        if line:
            lines.append(line)

    if not lines:
        raise SystemExit("No authorized session files were exported.")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        OUTPUT.chmod(0o600)
    except OSError:
        pass

    print(f"\nSaved {len(lines)} session string(s) to: {OUTPUT}")
    print("Do not share this file or commit it to Git.")


if __name__ == "__main__":
    asyncio.run(main())
