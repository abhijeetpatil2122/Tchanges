import json

import main


def test_config_date_is_reported_but_expiry_rotation_is_ignored():
    before = {
        "_": "types.Config",
        "date": 100,
        "expires": 200,
        "chat_size_max": 50,
    }
    changed_date = {**before, "date": 101, "expires": 201}
    changed_expiry_only = {**before, "expires": 202}

    encode = lambda value: json.dumps(value, sort_keys=True).encode("utf-8")

    assert main.normalize_telegram_method_for_compare(encode(before)) != (
        main.normalize_telegram_method_for_compare(encode(changed_date))
    )
    assert main.normalize_telegram_method_for_compare(encode(before)) == (
        main.normalize_telegram_method_for_compare(encode(changed_expiry_only))
    )
