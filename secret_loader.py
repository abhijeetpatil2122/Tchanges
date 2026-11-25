#!/usr/bin/env python3
"""Secret loading: process environment (.env / process environment) > local_secrets.py > default.

Priority order:
  1. process environment variables (не затираются .env);
  2. the .env file (loaded automatically);
  3. local local_secrets.py fallback (not committed);
  4. default.

.env не коммитится — см. .gitignore; в git попадает только .env.example.
"""
import os
from pathlib import Path
from typing import Any

_BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Минимальный .env-парсер: KEY=VALUE, без внешних зависимостей.

    Уже заданные переменные окружения не перезаписываются — реальные
    env-переменные процесса всегда имеют приоритет над файлом.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(_BASE_DIR / ".env")

try:
    import local_secrets as _local  # type: ignore
except ImportError:
    _local = None


def secret(name: str, default: Any = "") -> Any:
    """Secret value order: env > .env > local_secrets.py > default."""
    value = os.getenv(name)
    if value:
        return value
    if _local is not None:
        value = getattr(_local, name, None)
        if value:
            return value
    return default
