import json
import unittest

import main


class ConfigChangeDetectionTests(unittest.TestCase):
    def test_config_date_is_reported_but_expiry_rotation_is_ignored(self):
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

        self.assertNotEqual(normalized_before, normalized_date)
        self.assertEqual(normalized_before, normalized_expiry)


if __name__ == "__main__":
    unittest.main()
