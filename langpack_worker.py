#!/usr/bin/env python3
import asyncio
import hashlib
import json
import logging
import sys
import time
from pathlib import Path

logging.getLogger("pyrogram").setLevel(logging.ERROR)


def _patch_pyrogram_crypto_executor():
    """Shut down Pyrogram's crypto executor without changing TCP.close's sync API."""
    import functools
    import inspect

    from pyrogram.connection.transport.tcp.tcp import TCP

    if getattr(TCP.close, "_arena_fix", False):
        return

    original_close = TCP.close

    @functools.wraps(original_close)
    def close(self):
        result = original_close(self)

        if inspect.isawaitable(result):
            async def finish_close():
                try:
                    await result
                finally:
                    executor = getattr(self, "crypto_executor", None)
                    if executor is not None:
                        try:
                            executor.shutdown(wait=False)
                        except Exception:
                            pass

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                asyncio.run(finish_close())
            else:
                loop.create_task(finish_close())
            return None

        executor = getattr(self, "crypto_executor", None)
        if executor is not None:
            try:
                executor.shutdown(wait=False)
            except Exception:
                pass

        return result

    close._arena_fix = True
    TCP.close = close


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pyrogram_raw_to_dict(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [pyrogram_raw_to_dict(v) for v in value]
    if isinstance(value, dict):
        return {str(k): pyrogram_raw_to_dict(v) for k, v in value.items()}
    try:
        rendered = str(value).strip()
        if rendered.startswith(("{", "[")):
            return json.loads(rendered)
    except (TypeError, json.JSONDecodeError):
        pass
    if hasattr(value, "__dict__"):
        result = {"_": value.__class__.__name__}
        for key, item in sorted(vars(value).items()):
            if not key.startswith("_"):
                result[key] = pyrogram_raw_to_dict(item)
        return result
    if hasattr(value, "__slots__"):
        result = {"_": value.__class__.__name__}
        for key in sorted(value.__slots__):
            if not key.startswith("_") and hasattr(value, key):
                result[key] = pyrogram_raw_to_dict(getattr(value, key))
        return result
    return str(value)


def _scrub_personal(value):
    if isinstance(value, list):
        cleaned = []
        for item in value:
            if (
                isinstance(item, dict)
                and item.get("_") == "types.User"
                and item.get("is_self")
            ):
                continue
            cleaned.append(_scrub_personal(item))
        return cleaned
    if isinstance(value, dict):
        if value.get("_") == "types.Config":
            value = {
                k: v
                for k, v in value.items()
                if k not in ("autologin_token", "this_dc")
            }
        if value.get("_") == "types.User":
            value = {k: v for k, v in value.items() if k != "phone"}
        if value.get("_") == "types.help.PremiumPromo":
            value = dict(value)
            value["status_text"] = "[not tracked by checker for security]"
            value["status_entities"] = []
        return {k: _scrub_personal(v) for k, v in value.items()}
    return value


def sanitize_payload(payload):
    return _scrub_personal(payload)


def apply_langpack_difference(base_payload, diff_payload):
    if not isinstance(base_payload, dict):
        base_payload = {}
    if not isinstance(diff_payload, dict):
        diff_payload = {}

    index = {}
    for s in base_payload.get("strings") or []:
        if isinstance(s, dict) and "key" in s:
            index[s["key"]] = s

    for s in diff_payload.get("strings") or []:
        if not isinstance(s, dict) or "key" not in s:
            continue
        key = s["key"]
        if s.get("_") == "types.LangPackStringDeleted":
            index.pop(key, None)
        else:
            index[key] = s

    merged = sorted(index.values(), key=lambda x: x.get("key", ""))

    new_payload = dict(base_payload)
    new_payload["strings"] = merged
    if diff_payload.get("version") is not None:
        new_payload["version"] = diff_payload["version"]
    if diff_payload.get("lang_code"):
        new_payload["lang_code"] = diff_payload["lang_code"]
    new_payload.setdefault("from_version", 0)
    return new_payload


async def process_lang_code(tg_client, lang_pack, lang_code, prev, local_path, workdir):
    from pyrogram.raw.functions.langpack import GetDifference, GetLangPack

    entry = {"method": "langpack.getLangPack", "lang_code": lang_code}
    prev_version = prev.get("version")

    base_payload = None
    diff_payload = None

    if prev_version is not None:
         # First request only the difference: the response is small. The local pack (~2 MB
         # JSON) is parsed only when the difference contains strings; previously it was read
         # for every language on every cycle, which saturated CPU (7 platforms ×
        # ~30 языков × 2 МБ на каждом проходе).
        result = await tg_client.invoke(
            GetDifference(
                lang_pack=lang_pack,
                lang_code=lang_code,
                from_version=int(prev_version),
            )
        )
        diff_payload = sanitize_payload(pyrogram_raw_to_dict(result))
        diff_strings = (
            diff_payload.get("strings") if isinstance(diff_payload, dict) else None
        ) or []
        new_version = (
            diff_payload.get("version") if isinstance(diff_payload, dict) else None
        )

        if not diff_strings and (new_version is None or new_version == prev_version):
            entry["status"] = "identical"
            return entry, None, None

        if local_path.exists():
            try:
                loaded = json.loads(local_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and loaded.get("strings") is not None:
                    base_payload = loaded
            except Exception:
                base_payload = None

        if base_payload is not None:
            payload = apply_langpack_difference(base_payload, diff_payload)
             # Number of strings added/changed in this difference; shown
            # in the notification as the change volume.
            entry["changed_strings"] = len(diff_strings)
            entry["from_version"] = int(prev_version)
            entry["mode"] = "difference"

    if base_payload is None:
        # Initial download, missing state, or invalid local file:
        # download the full language pack.
        result = await tg_client.invoke(
            GetLangPack(lang_pack=lang_pack, lang_code=lang_code)
        )
        payload = sanitize_payload(pyrogram_raw_to_dict(result))
        entry["mode"] = "full"

    content = (
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    size = len(content)
    content_hash = compute_hash(content)

    prev_hash = prev.get("hash")
    prev_size = prev.get("size")
    is_new = not local_path.exists()

    if not is_new and prev_hash == content_hash and prev_size == size:
        entry["status"] = "identical"
        return entry, None, None

    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)

    entry["status"] = "saved"
    entry["size"] = size
    entry["hash"] = content_hash
    if isinstance(payload, dict) and "version" in payload:
        entry["version"] = payload["version"]

    state_entry = {
        "hash": content_hash,
        "size": size,
        "filename": str(local_path.relative_to(workdir)),
        "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if isinstance(payload, dict) and "version" in payload:
        state_entry["version"] = payload["version"]

    return entry, state_entry, str(local_path)


async def main():
    config = json.loads(sys.stdin.buffer.read())

    api_id = config["api_id"]
    api_hash = config["api_hash"]
    test_mode = config["test_mode"]
    proxy_cfg = config.get("proxy")
    session_name = config["session_name"]
    session_string = config["session_string"]
    workdir = Path(config.get("workdir", "/root/github"))
    watch_dir = Path(config["watch_dir"])
    lang_pack = config["lang_pack"]
    lang_codes = config["lang_codes"]
    state_file_str = config.get("state_file")
     # main.py owns .remote_state.json; with parallel platforms, seven
     # workers must not write the same file. The worker only reads state
     # (needed for getDifference) and writes it only in manual mode.
    write_state = config.get("write_state", True)
    concurrency = config.get("concurrency", 3)
    max_retries = config.get("max_retries", 2)
    retry_delay = config.get("retry_delay", 1.0)

    state = {}
    if state_file_str:
        state_path = Path(state_file_str)
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except Exception:
                state = {}

    proxy = None
    if proxy_cfg:
        proxy = {
            "scheme": proxy_cfg.get("scheme", "socks5"),
            "hostname": proxy_cfg.get("hostname", "127.0.0.1"),
            "port": proxy_cfg.get("port", 9050),
        }
        if proxy_cfg.get("username"):
            proxy["username"] = proxy_cfg["username"]
        if proxy_cfg.get("password"):
            proxy["password"] = proxy_cfg["password"]

    from pyrogram import Client

    # pyrogram импортируется лениво — патчим после появления модуля transport.
    _patch_pyrogram_crypto_executor()

    tg_client = Client(
        session_name,
        int(api_id),
        api_hash,
        test_mode=test_mode,
        session_string=session_string,
        proxy=proxy,
        no_updates=True,
    )

    await tg_client.connect()

    results = []
    state_updated = {}
    changed_files = []
    # Delta from the previous language list: newly added languages and languages
    # with increased translated_count (new translations).
    languages_delta = {"added": [], "progress": []}

    # Fetch getLanguages first — keep file in sync and use fresh lang_codes
    from pyrogram.raw.functions.langpack import GetLanguages

    try:
        gl_payload = sanitize_payload(
            pyrogram_raw_to_dict(
                await tg_client.invoke(GetLanguages(lang_pack=lang_pack))
            )
        )
        if isinstance(gl_payload, list):
            gl_payload = sorted(
                gl_payload,
                key=lambda x: x.get("lang_code", "") if isinstance(x, dict) else "",
            )
            gl_content = (
                json.dumps(gl_payload, indent=2, ensure_ascii=False, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            gl_hash = compute_hash(gl_content)
            gl_filename = f"langpack/{lang_pack}/getLanguages.json"
            gl_local_path = watch_dir / gl_filename
            gl_url_key = f"method:langpack.getLanguages@{lang_pack}"

            gl_prev = state.get(gl_url_key, {})
            gl_needs_save = not gl_local_path.exists()
            if not gl_needs_save:
                try:
                    gl_needs_save = gl_prev.get("hash") != gl_hash or gl_prev.get(
                        "size"
                    ) != len(gl_content)
                except Exception:
                    gl_needs_save = True

            if gl_needs_save:
                # Read the old list BEFORE replacing it so we can calculate
                # which languages appeared and which gained translations.
                old_by_code = {}
                if gl_local_path.exists():
                    try:
                        old_list = json.loads(
                            gl_local_path.read_text(encoding="utf-8")
                        )
                        if isinstance(old_list, list):
                            old_by_code = {
                                x.get("lang_code"): x
                                for x in old_list
                                if isinstance(x, dict) and x.get("lang_code")
                            }
                    except Exception:
                        old_by_code = {}

                if old_by_code:
                    languages_delta["added"] = sorted(
                        x.get("lang_code")
                        for x in gl_payload
                        if isinstance(x, dict)
                        and x.get("lang_code")
                        and x.get("lang_code") not in old_by_code
                    )
                    for item in gl_payload:
                        if not isinstance(item, dict):
                            continue
                        code = item.get("lang_code")
                        old = old_by_code.get(code)
                        if not old:
                            continue
                        old_tr = old.get("translated_count") or 0
                        new_tr = item.get("translated_count") or 0
                        if new_tr > old_tr:
                            languages_delta["progress"].append(
                                {
                                    "lang": code,
                                    "from": old_tr,
                                    "to": new_tr,
                                    "strings_count": item.get("strings_count"),
                                }
                            )
                    languages_delta["progress"].sort(key=lambda x: x["lang"])

                gl_local_path.parent.mkdir(parents=True, exist_ok=True)
                gl_local_path.write_bytes(gl_content)
                gl_size = len(gl_content)
                state_updated[gl_url_key] = {
                    "hash": gl_hash,
                    "size": gl_size,
                    "filename": str(gl_local_path.relative_to(workdir)),
                    "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                changed_files.append(str(gl_local_path))
                results.append(
                    {
                        "method": "langpack.getLanguages",
                        "lang_pack": lang_pack,
                        "status": "saved",
                        "size": gl_size,
                        "hash": gl_hash,
                        "filename": gl_filename,
                    }
                )

            fresh_codes = sorted(
                set(l.get("lang_code") for l in gl_payload if isinstance(l, dict))
            )
            lang_codes = list(dict.fromkeys([*lang_codes, *fresh_codes]))
    except Exception as e:
        print(
            f"[getLanguages {lang_pack}] error: {type(e).__name__}: {e}",
            file=sys.stderr,
        )

    sem = asyncio.Semaphore(concurrency)

    async def process_with_retry(lang_code):
        url_key = f"method:langpack.getLangPack@{lang_pack}/{lang_code}"
        filename = f"langpack/{lang_pack}/lang/{lang_code}/getLangPack.json"
        local_path = watch_dir / filename
        prev = state.get(url_key, {})

        attempt = 0
        last_error = None
        while attempt <= max_retries:
            try:
                async with sem:
                    return await process_lang_code(
                        tg_client,
                        lang_pack,
                        lang_code,
                        prev,
                        local_path,
                        workdir,
                    )
            except Exception as e:
                last_error = e
                # A language code that is no longer available will not succeed with retries.
                if "LANG_CODE_NOT_SUPPORTED" in str(e):
                    return (
                        {
                            "method": "langpack.getLangPack",
                            "lang_code": lang_code,
                            "status": "unsupported",
                        },
                        None,
                        None,
                    )
                attempt += 1
                if attempt <= max_retries:
                    await asyncio.sleep(retry_delay * (2 ** (attempt - 1)))
                continue

        entry = {
            "method": "langpack.getLangPack",
            "lang_code": lang_code,
            "status": "error",
            "error": f"{type(last_error).__name__}: {last_error}",
        }
        return entry, None, None

    try:
        tasks = [process_with_retry(lc) for lc in lang_codes]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for lang_code, outcome in zip(lang_codes, completed):
            if isinstance(outcome, Exception):
                entry = {
                    "method": "langpack.getLangPack",
                    "lang_code": lang_code,
                    "status": "error",
                    "error": f"{type(outcome).__name__}: {outcome}",
                }
                results.append(entry)
            else:
                entry, state_entry, local_path_str = outcome
                results.append(entry)
                if state_entry is not None:
                    url_key = f"method:langpack.getLangPack@{lang_pack}/{lang_code}"
                    state_updated[url_key] = state_entry
                    changed_files.append(local_path_str)
    finally:
        try:
            await asyncio.wait_for(tg_client.disconnect(), timeout=10)
        except Exception:
            pass

    if state_updated and state_file_str and write_state:
        state.update(state_updated)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

    summary = {
        "lang_pack": lang_pack,
        "results": results,
        "changed": changed_files,
        "languages_delta": languages_delta,
    }
    json.dump(summary, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
