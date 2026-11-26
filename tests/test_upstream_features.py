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
        self.assertEqual(len(nested_list["items"]), 1)
        first = nested_list["items"][0]["blocks"][0]
        self.assertEqual(first["type"], "paragraph")
        self.assertEqual(first["text"][0], {"type": "code", "text": "main.py"})
        self.assertEqual(first["text"][2], {"type": "code", "text": "config.json"})

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
        self.assertEqual(len(items), 19)
        self.assertIn("file_74.json", str(items))
        self.assertIn("file_0.json", str(items))
        self.assertNotIn("and 40 more files", str(blocks))

    def test_new_and_updated_files_are_separate_notification_batches(self):
        batches = main._change_notification_batches(
            new_names=["new-a.json", "new-b.json"],
            updated_names=["changed-a.json"],
        )
        self.assertEqual(
            batches,
            [
                ("🆕 New Files", "new", ["new-a.json", "new-b.json"]),
                ("🔄 Updated Files", "updated", ["changed-a.json"]),
            ],
        )

        new_blocks = main._rich_notification_blocks(
            title=batches[0][0],
            new_names=batches[0][2],
            ai_text="Summary",
        )
        updated_blocks = main._rich_notification_blocks(
            title=batches[1][0],
            updated_names=batches[1][2],
            ai_text="Summary",
        )
        self.assertIn("new-a.json", str(new_blocks))
        self.assertNotIn("changed-a.json", str(new_blocks))
        self.assertIn("changed-a.json", str(updated_blocks))
        self.assertNotIn("new-a.json", str(updated_blocks))

    def test_ai_rich_text_supports_clean_semantic_emphasis(self):
        parsed = main._rich_markup(
            "<b>Behaviour change</b> with <i>context</i>, "
            "<mark>important value</mark>, and <s>removed option</s>"
        )
        self.assertEqual(
            parsed,
            [
                {"type": "bold", "text": "Behaviour change"},
                " with ",
                {"type": "italic", "text": "context"},
                ", ",
                {"type": "marked", "text": "important value"},
                ", and ",
                {"type": "strikethrough", "text": "removed option"},
            ],
        )

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

    def test_config_json_resources_use_config_category(self):
        names = (
            "help.getAppConfig.json",
            "help.getCdnConfig.json",
            "help.getConfig.json",
            "help.getCountriesList.json",
            "help.getInviteText.json",
            "help.getPassportConfig.json",
            "help.getPremiumPromo.json",
            "help.getPromoData.json",
            "help.getTimezonesList.json",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(main.classify_resource_category(name), "config")
        self.assertEqual(
            main.classify_resource_category("aicompose.getTones.json"), "json"
        )

    def test_misplaced_config_duplicates_are_removed_after_normalization(self):
        with tempfile.TemporaryDirectory() as temp:
            watch_dir = Path(temp) / "production"
            canonical = watch_dir / "config" / "help.getConfig.json"
            misplaced = watch_dir / "json" / "help.getConfig.json"
            canonical.parent.mkdir(parents=True)
            misplaced.parent.mkdir(parents=True)
            canonical.write_text(
                '{"_":"types.Config","date":1,"expires":10,"feature":true}',
                encoding="utf-8",
            )
            misplaced.write_text(
                '{"_":"types.Config","date":2,"expires":20,"feature":true}',
                encoding="utf-8",
            )

            with patch.object(
                main, "get_env_paths", return_value=(watch_dir, Path(temp) / "state")
            ):
                moved = main.migrate_legacy_resource_layout("prod")

            self.assertEqual(moved, 1)
            self.assertTrue(canonical.is_file())
            self.assertFalse(misplaced.exists())

    def test_misplaced_config_with_real_difference_is_archived(self):
        with tempfile.TemporaryDirectory() as temp:
            watch_dir = Path(temp) / "production"
            canonical = watch_dir / "config" / "help.getConfig.json"
            misplaced = watch_dir / "json" / "help.getConfig.json"
            canonical.parent.mkdir(parents=True)
            misplaced.parent.mkdir(parents=True)
            canonical.write_text(
                '{"_":"types.Config","date":1,"expires":10,"feature":true}',
                encoding="utf-8",
            )
            misplaced.write_text(
                '{"_":"types.Config","date":2,"expires":20,"feature":false}',
                encoding="utf-8",
            )

            with patch.object(
                main, "get_env_paths", return_value=(watch_dir, Path(temp) / "state")
            ):
                moved = main.migrate_legacy_resource_layout("prod")

            self.assertEqual(moved, 1)
            self.assertTrue(canonical.is_file())
            self.assertFalse(misplaced.exists())
            self.assertEqual(
                (watch_dir / "legacy" / "help.getConfig.json").read_text(
                    encoding="utf-8"
                ),
                '{"_":"types.Config","date":2,"expires":20,"feature":false}',
            )

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
        self.assertEqual(details["blocks"][0]["type"], "list")
        self.assertEqual(details["blocks"][0]["items"][0]["type"], "1")
        self.assertEqual(details["blocks"][0]["items"][0]["value"], 1)
        self.assertEqual(
            details["blocks"][0]["items"][0]["blocks"][0]["text"],
            [
                {"type": "bold", "text": "Core changed"},
                " in ",
                {"type": "code", "text": "send()"},
            ],
        )
        self.assertEqual(
            details["blocks"][0]["items"][0]["blocks"][0]["type"],
            "paragraph",
        )

    def test_ai_summary_uses_native_numbered_rich_list(self):
        blocks = main._rich_notification_blocks(
            title="Update",
            ai_text="<b>First change</b>\nSecond change\nThird change",
        )
        details = next(block for block in blocks if block["type"] == "details")
        numbered = details["blocks"][0]
        self.assertEqual(numbered["type"], "list")
        self.assertEqual([item["type"] for item in numbered["items"]], ["1", "1", "1"])
        self.assertEqual([item["value"] for item in numbered["items"]], [1, 2, 3])
        self.assertEqual(
            numbered["items"][0]["blocks"][0]["text"],
            {"type": "bold", "text": "First change"},
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

    def test_fragment_html_dynamic_ton_rate_and_proof_are_normalized(self):
        first = (
            '<script>const state = {"tonRate":0.99050236166832, '
            '"ton_proof":"086fdfaddaaeae204e"};</script>'
        )
        second = (
            '<script>const state = {"tonRate": 0.991234, '
            '"ton_proof":"226110bc6387e52bb9"};</script>'
        )

        normalized_first, changed_first = main.normalize_content(first, True)
        normalized_second, changed_second = main.normalize_content(second, True)

        self.assertTrue(changed_first)
        self.assertTrue(changed_second)
        self.assertEqual(normalized_first, normalized_second)
        self.assertIn('"tonRate":"xieworld_vf"', normalized_first)
        self.assertIn('"ton_proof":"xieworld_vf"', normalized_first)

    def test_fragment_ton_rate_string_value_is_normalized(self):
        html = '<script>{"tonRate":"0.99050236166832"}</script>'
        normalized, changed = main.normalize_content(html, True)
        self.assertTrue(changed)
        self.assertIn('"tonRate":"xieworld_vf"', normalized)
