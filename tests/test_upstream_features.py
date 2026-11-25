import unittest

import main


class TelegramMethodSafetyTests(unittest.TestCase):
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
