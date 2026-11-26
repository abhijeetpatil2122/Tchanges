import json
import unittest
from pathlib import Path

import main


class ConfigChangeDetectionTests(unittest.TestCase):
    def test_config_date_and_expiry_rotation_are_ignored(self):
        before = {
            "_": "types.Config",
            "date": 100,
            "expires": 200,
            "chat_size_max": 50,
        }
        changed_date = {**before, "date": 101, "expires": 201}
        changed_expiry_only = {**before, "expires": 202}

        encode = lambda value: json.dumps(value, sort_keys=True).encode("utf-8")

        normalized_before = main.normalize_telegram_method_for_compare(encode(before))
        normalized_date = main.normalize_telegram_method_for_compare(encode(changed_date))
        normalized_expiry = main.normalize_telegram_method_for_compare(encode(changed_expiry_only))

        self.assertEqual(normalized_before, normalized_date)
        self.assertEqual(normalized_before, normalized_expiry)


class ResourcePathTests(unittest.TestCase):
    def test_production_telegram_method_uses_canonical_json_path(self):
        watch_dir = Path("/tmp/production")

        path = main.telegram_method_local_path(
            watch_dir, "prod", "messages.getTranscriptionModels.json"
        )

        self.assertEqual(
            path,
            watch_dir / "json" / "messages.getTranscriptionModels.json",
        )

    def test_test_telegram_method_keeps_existing_root_path(self):
        watch_dir = Path("/tmp/test")

        path = main.telegram_method_local_path(
            watch_dir, "test", "messages.getTranscriptionModels.json"
        )

        self.assertEqual(path, watch_dir / "messages.getTranscriptionModels.json")


if __name__ == "__main__":
    unittest.main()
