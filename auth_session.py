#!/usr/bin/env python3
import argparse
import asyncio
import pyrogram
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    PasswordHashInvalid,
)

from secret_loader import secret

API_ID = int(secret("TELEGRAM_API_ID", "0"))
API_HASH = secret("TELEGRAM_API_HASH")
SESSION_PREFIX = ".telegram-method-checker"
WORKDIR = "/root/github"


def build_client(env: str) -> Client:
    return Client(
        f"{SESSION_PREFIX}-{env}",
        API_ID,
        API_HASH,
        test_mode=env == "test",
        workdir=WORKDIR,
        no_updates=True,
    )


async def authorize_env(env: str, phone: str | None) -> None:
    label = "TEST DC" if env == "test" else "PROD"
    app = build_client(env)

    await app.connect()
    print(f"[{env}] Connected to {label}")

    try:
        me = await app.get_me()
        print(f"[{env}] Already authorized: {me.first_name} (id={me.id})")
        await app.disconnect()
        return
    except pyrogram.errors.RPCError:
        print(f"[{env}] Need to authorize")

    if not phone:
        phone = input(f"[{env}] Phone: ").strip()

    sent = await app.send_code(phone)
    print(f"[{env}] Code sent via {type(sent.type).__name__}")

    signed_in = False
    while not signed_in:
        code = input(f"[{env}] Code: ").strip()
        try:
            await app.sign_in(phone, sent.phone_code_hash, code)
            signed_in = True
        except SessionPasswordNeeded:
            while True:
                pwd = input(f"[{env}] 2FA password: ").strip()
                try:
                    await app.check_password(pwd)
                    signed_in = True
                    break
                except PasswordHashInvalid:
                    print(f"[{env}] Wrong 2FA password, try again")
        except PhoneCodeInvalid:
            print(f"[{env}] Invalid code, try again")
        except PhoneCodeExpired:
            print(f"[{env}] Code expired, requesting new one...")
            sent = await app.send_code(phone)

    me = await app.get_me()
    print(f"[{env}] Authorized: {me.first_name} ({me.phone_number}) id={me.id}")
    await app.disconnect()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=["prod", "test", "both"], default="both")
    parser.add_argument("--phone", default=None)
    args = parser.parse_args()

    envs = ["test", "prod"] if args.env == "both" else [args.env]
    phone = args.phone if args.env != "both" else None

    async def run():
        for env in envs:
            await authorize_env(env, phone)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nCancelled.")


if __name__ == "__main__":
    main()
