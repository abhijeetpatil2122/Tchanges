import json
import unittest

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


    def test_synced_read_only_method_requests_are_constructible(self):
        methods = (
            "messages.getShareThemeBackdrops",
            "feed.getInterestCategories",
            "messages.getTranscriptionModels",
            "agent.getProviders",
            "aicompose.getTones",
            "wallet.getCurrencyRates",
            "payments.getOnrampProviders",
            "wallet.getBackupHolderDcs",
        )
        for method_name in methods:
            with self.subTest(method=method_name):
                self.assertIsNotNone(main.build_telegram_method_request(method_name))

    def test_currency_rate_value_rotation_is_ignored(self):
        before = {
            "_": "types.CurrencyRates",
            "rates": [
                {"currency": "USD", "rate": 1.2},
                {"currency": "EUR", "rate": 1.1},
            ],
        }
        after = {
            "_": "types.CurrencyRates",
            "rates": [
                {"currency": "USD", "rate": 1.3},
                {"currency": "EUR", "rate": 1.0},
            ],
        }
        encode = lambda value: json.dumps(value, sort_keys=True).encode("utf-8")
        self.assertEqual(
            main.normalize_telegram_method_for_compare(encode(before)),
            main.normalize_telegram_method_for_compare(encode(after)),
        )


if __name__ == "__main__":
    unittest.main()
