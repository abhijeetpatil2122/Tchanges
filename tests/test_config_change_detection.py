import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        self.assertEqual(path, watch_dir / "json" / "messages.getTranscriptionModels.json")

    def test_test_telegram_method_uses_canonical_json_path(self):
        watch_dir = Path("/tmp/test")
        path = main.telegram_method_local_path(
            watch_dir, "test", "messages.getTranscriptionModels.json"
        )
        self.assertEqual(path, watch_dir / "json" / "messages.getTranscriptionModels.json")

    def test_legacy_transcription_duplicates_are_removed_but_canonical_is_kept(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            watch_dir = Path(temp_dir) / "production"
            canonical = watch_dir / "json" / "messages.getTranscriptionModels.json"
            root_copy = watch_dir / "messages.getTranscriptionModels.json"
            legacy_copy = watch_dir / "legacy" / "messages.getTranscriptionModels.old.json"
            canonical.parent.mkdir(parents=True)
            legacy_copy.parent.mkdir(parents=True)

            stable_model = {
                "_": "types.TranscriptionModel",
                "version": 1,
                "languages": ["en"],
                "document": {
                    "_": "types.Document",
                    "id": 123,
                    "access_hash": 456,
                    "file_reference": "rotating-a",
                },
            }
            rotated_model = {
                **stable_model,
                "document": {
                    **stable_model["document"],
                    "access_hash": 789,
                    "file_reference": "rotating-b",
                },
            }
            canonical.write_text(json.dumps([stable_model]), encoding="utf-8")
            root_copy.write_text(json.dumps([rotated_model]), encoding="utf-8")
            legacy_copy.write_text(json.dumps([rotated_model]), encoding="utf-8")

            with patch.object(main, "get_env_paths", return_value=(watch_dir, watch_dir / ".state")):
                main.migrate_legacy_resource_layout("prod")

            self.assertTrue(canonical.is_file())
            self.assertFalse(root_copy.exists())
            self.assertFalse(legacy_copy.exists())
            self.assertFalse(legacy_copy.parent.exists())

    def test_legacy_test_method_file_moves_into_json_category(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            watch_dir = Path(temp_dir) / "test"
            root_copy = watch_dir / "messages.getTranscriptionModels.json"
            root_copy.parent.mkdir(parents=True)
            root_copy.write_text("[]", encoding="utf-8")

            with patch.object(main, "get_env_paths", return_value=(watch_dir, watch_dir / ".state")):
                main.migrate_legacy_resource_layout("test")

            self.assertFalse(root_copy.exists())
            self.assertEqual(
                (watch_dir / "json" / "messages.getTranscriptionModels.json").read_text(encoding="utf-8"),
                "[]",
            )


if __name__ == "__main__":
    unittest.main()
