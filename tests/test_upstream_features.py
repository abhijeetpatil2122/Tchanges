import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main


class TelegramMethodSafetyTests(unittest.TestCase):
    def test_file_list_uses_current_nested_expandable_blockquote_schema(self):
        block = main._rich_file_list(["`main.py`", "`config.json`"])
        self.assertEqual(block["type"], "expandable_blockquote")
        self.assertNotIn("text", block)
        self.assertEqual(len(block["blocks"]), 1)
        nested_list = block["blocks"][0]
        self.assertEqual(nested_list["type"], "list")
        self.assertEqual(len(nested_list["items"]), 2)
        first = nested_list["items"][0]["blocks"][0]
        self.assertEqual(first["type"], "paragraph")
        self.assertEqual(first["text"], {"type": "code", "text": "main.py"})

    def test_file_list_includes_every_filename_without_more_placeholder(self):
        names = [f"file_{index}.json" for index in range(75)]
        blocks = main._rich_notification_blocks(
            title="Update",
            updated_names=names,
            ai_text="Summary",
        )
        expandable = next(
            block for block in blocks if block["type"] == "expandable_blockquote"
        )
        items = expandable["blocks"][0]["items"]
        self.assertEqual(len(items), 75)
        self.assertIn("file_74.json", str(items))
        self.assertNotIn("and 40 more files", str(blocks))

    def test_rich_message_documented_limits_are_checked(self):
        blocks = main._rich_notification_blocks(
            title="Update",
            updated_names=[f"file_{index}.json" for index in range(40)],
            ai_text="A <b>formatted</b> summary with <code>code</code>.",
        )
        characters, block_count = main._validate_rich_message_limits(blocks)
        self.assertGreater(characters, 0)
        self.assertLessEqual(characters, 32768)
        self.assertLessEqual(block_count, 500)

        too_many_chars = [{"type": "paragraph", "text": "x" * 32769}]
        with self.assertRaisesRegex(ValueError, "32,768-character"):
            main._validate_rich_message_limits(too_many_chars)

        too_many_blocks = [
            {"type": "paragraph", "text": "x"} for _ in range(501)
        ]
        with self.assertRaisesRegex(ValueError, "500-block"):
            main._validate_rich_message_limits(too_many_blocks)

    def test_legacy_conflicting_snapshot_is_archived_not_fatal(self):
        with tempfile.TemporaryDirectory() as temp:
            watch_dir = Path(temp) / "production"
            watch_dir.mkdir()
            legacy = watch_dir / "aicompose.getTones.json"
            canonical = watch_dir / "json" / "aicompose.getTones.json"
            canonical.parent.mkdir()
            legacy.write_text('{"tones":["old","extra"]}', encoding="utf-8")
            canonical.write_text('{"tones":["current"]}', encoding="utf-8")

            with patch.object(
                main, "get_env_paths", return_value=(watch_dir, Path(temp) / "state")
            ):
                moved = main.migrate_legacy_resource_layout("prod")

            archive = watch_dir / "legacy" / "aicompose.getTones.json"
            self.assertEqual(moved, 1)
            self.assertFalse(legacy.exists())
            self.assertEqual(canonical.read_text(encoding="utf-8"), '{"tones":["current"]}')
            self.assertEqual(
                archive.read_text(encoding="utf-8"), '{"tones":["old","extra"]}'
            )

    def test_ai_summary_keeps_supported_inline_rich_text_inside_details(self):
        blocks = main._rich_notification_blocks(
            title="Update",
            ai_text="<b>Core changed</b> in <code>send()</code>",
        )
        details = next(block for block in blocks if block["type"] == "details")
        self.assertEqual(details["blocks"][0]["type"], "paragraph")
        self.assertEqual(
            details["blocks"][0]["text"],
            [
                "• ",
                {"type": "bold", "text": "Core changed"},
                " in ",
                {"type": "code", "text": "send()"},
            ],
        )

    def test_scrub_tones_keeps_only_system_defaults(self):
        payload = {
            "_": "types.aicompose.Tones",
            "hash": 999,
            "tones": [
                {"_": "types.AiComposeToneDefault", "id": 1, "title": "Default"},
                {"_": "types.AiComposeTone", "id": 2, "title": "Personal"},
            ],
            "users": [{"_": "types.User", "id": 10}],
        }
        cleaned = main.sanitize_telegram_method_payload(payload)
        self.assertEqual(
            [tone["_"] for tone in cleaned["tones"]],
            ["types.AiComposeToneDefault"],
        )
        self.assertNotIn("hash", cleaned)
        self.assertNotIn("users", cleaned)

    def test_scrub_feed_selected_account_preferences(self):
        payload = {
            "_": "types.feed.InterestCategories",
            "categories": [{"id": 1, "title": "Tech"}],
            "selected": [{"id": 1}],
        }
        cleaned = main.sanitize_telegram_method_payload(payload)
        self.assertIn("categories", cleaned)
        self.assertNotIn("selected", cleaned)

    def test_scrub_self_user_and_phone(self):
        payload = [
            {"_": "types.User", "is_self": True, "id": 1, "phone": "123"},
            {"_": "types.User", "is_self": False, "id": 2, "phone": "456"},
        ]
        cleaned = main.sanitize_telegram_method_payload(payload)
        self.assertEqual(len(cleaned), 1)
        self.assertNotIn("phone", cleaned[0])

    def test_supported_method_builders(self):
        names = (
            "help.getAppConfig",
            "help.getConfig",
            "help.getCountriesList",
            "help.getInviteText",
            "help.getCdnConfig",
            "help.getPassportConfig",
            "help.getTimezonesList",
            "help.getPremiumPromo",
            "help.getPromoData",
            "aicompose.getTones",
            "langpack.getLanguages",
            "langpack.getLangPack",
            "langpack.getDifference",
        )
        for name in names:
            with self.subTest(method=name):
                self.assertIsNotNone(main.build_telegram_method_request(name))

    def test_wallet_mutations_are_rejected(self):
        for name in ("wallet.sendTransfer", "wallet.exportSecretPhrase"):
            with self.subTest(method=name), self.assertRaises(ValueError):
                main.build_telegram_method_request(name)

    def test_unsupported_newer_methods_fail_closed(self):
        names = (
            "messages.getShareThemeBackdrops",
            "feed.getInterestCategories",
            "messages.getTranscriptionModels",
            "agent.getProviders",
            "payments.getCurrencyRates",
            "wallet.getBackupHolderDcs",
            "payments.getOnrampProviders",
        )
        for name in names:
            with self.subTest(method=name), self.assertRaises(ValueError):
                main.build_telegram_method_request(name)

    def test_diff_compressor_keeps_code_and_reduces_generated_assets(self):
        diff = (
            "diff --git a/source.js.map b/source.js.map\n"
            "+++ b/source.js.map\n+" + ("x" * 10000) + "\n"
            "diff --git a/app.min.js b/app.min.js\n"
            "+++ b/app.min.js\n+" + ("y" * 1200) + "\n"
            "diff --git a/config.py b/config.py\n+++ b/config.py\n+value = 42\n"
        )
        compact = main._compress_diff_for_ai(diff)
        self.assertIn("sourcemap", compact)
        self.assertIn("minified", compact)
        self.assertIn("value = 42", compact)

    def test_diff_compressor_groups_custom_readable_test_variants(self):
        diff = (
            "diff --git a/test/variant-a/config.json b/test/variant-a/config.json\n"
            "--- a/test/variant-a/config.json\n"
            "+++ b/test/variant-a/config.json\n"
            "+{\"feature\": true}\n"
            "diff --git a/test/variant-b/config.json b/test/variant-b/config.json\n"
            "--- a/test/variant-b/config.json\n"
            "+++ b/test/variant-b/config.json\n"
            "+{\"feature\": true}\n"
        )
        compact = main._compress_diff_for_ai(diff)
        self.assertIn("variant-a", compact)
        self.assertIn("variant-b", compact)


if __name__ == "__main__":
    unittest.main()
