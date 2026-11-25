#!/usr/bin/env python3
"""
Authorize Pyrogram sessions for main.py on production and test.

main.py использует pyrogram и создаёт клиент с настройками из
CONFIG["telegram_api"]: api_id/api_hash, имя сессии f"{prefix}-{env}"
(.telegram-method-checker-<env>), test_mode=(env=="test"), workdir=BASE_DIR.

Этот скрипт логинит соответствующую сессию интерактивно (телефон → код → 2FA)
и сохраняет её в тот же .session файл, что использует main.py.

Примеры:
    python3 authorize.py --env test     # тестовый DC
    python3 authorize.py --env prod     # production network
    python3 authorize.py --env both     # обе по очереди

    # сразу передать номер (иначе спросит интерактивно)
    python3 authorize.py --env prod --phone +7XXXXXXXXXX
"""

import argparse
import asyncio
import os

import pyrogram
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    PhoneNumberInvalid,
    PasswordHashInvalid,
    FloodWait,
)

# Load configuration и хелперы прямо из main.py, чтобы клиент совпадал 1-в-1.
from main import CONFIG, BASE_DIR, get_telegram_method_proxy


# Telegram application credentials (my.telegram.org) — env > local_secrets.py.
from secret_loader import secret

API_ID = int(secret("TELEGRAM_API_ID", "0"))
API_HASH = secret("TELEGRAM_API_HASH")


def build_client(env: str) -> Client:
    """Собирает pyrogram.Client под выбранное окружение."""
    tg_api_config = CONFIG["telegram_api"]

    test_mode = env == "test"
    session_prefix = os.getenv(
        "TELEGRAM_METHOD_SESSION_PREFIX", tg_api_config["session_prefix"]
    )
    session_name = os.getenv("TELEGRAM_METHOD_SESSION", f"{session_prefix}-{env}")

    return Client(
        session_name,
        API_ID,
        API_HASH,
        test_mode=test_mode,
        proxy=get_telegram_method_proxy(),
        workdir=BASE_DIR,
        no_updates=True,
    )


async def authorize_env(env: str, phone: str | None) -> None:
    env_label = "TEST DC" if env == "test" else "PROD"
    client = build_client(env)

    print(f"\n=== Authorizing session '{client.name}' ({env_label}) ===")

    await client.connect()

    # Уже авторизованы? Тогда ничего не делаем.
    try:
        me = await client.get_me()
        print(
            f"[+] Session is already authorized: {me.first_name} "
            f"(id={me.id}, @{me.username})"
        )
        await client.disconnect()
        return
    except pyrogram.errors.RPCError:
        pass  # не авторизованы → логинимся

    if not phone:
        phone = input(f"[{env}] Phone number (+7XXXXXXXXXX): ").strip()

    try:
        sent = await client.send_code(phone)
    except PhoneNumberInvalid:
        print(f"[{env}] [-] Invalid phone number.")
        await client.disconnect()
        return
    except FloodWait as e:
        print(
            f"[{env}] [-] FloodWait: Telegram requires waiting {e.value} seconds. "
            f"Try again later."
        )
        await client.disconnect()
        return

    print(f"[{env}] [*] Code sent (type: {sent.type}). Check Telegram/SMS.")

    signed_in = False
    while not signed_in:
        code = input(f"[{env}] Verification code: ").strip()
        try:
            await client.sign_in(phone, sent.phone_code_hash, code)
            signed_in = True
        except SessionPasswordNeeded:
            while True:
                password = input(f"[{env}] 2FA password: ").strip()
                try:
                    await client.check_password(password)
                    signed_in = True
                    break
                except PasswordHashInvalid:
                    print(f"[{env}] [-] Invalid 2FA password. Try again.")
        except PhoneCodeInvalid:
            print(f"[{env}] [-] Invalid code. Try again.")
        except PhoneCodeExpired:
            print(f"[{env}] [-] Code expired; requesting a new code...")
            sent = await client.send_code(phone)

    me = await client.get_me()
    print(
        f"[{env}] [+] Done! {env_label}: {me.first_name} "
        f"(id={me.id}, @{me.username})\n"
        f"[{env}] Session file: {client.name}.session (workdir={BASE_DIR})"
    )

    await client.disconnect()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Авторизация Pyrogram-сессий main.py на проде и тесте."
    )
    parser.add_argument(
        "--env",
        choices=["prod", "test", "both"],
        default="both",
        help="Which session to authorize (by default both).",
    )
    parser.add_argument(
        "--phone",
        default=None,
        help="Phone number. Если не указан — спросит интерактивно.",
    )
    return parser.parse_args()


async def run(args) -> None:
    envs = ["test", "prod"] if args.env == "both" else [args.env]
    for env in envs:
        phone = args.phone if args.env != "both" else None
        await authorize_env(env, phone)


def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nCancelled by user.")


if __name__ == "__main__":
    main()
