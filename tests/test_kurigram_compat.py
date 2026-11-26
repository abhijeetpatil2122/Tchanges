import inspect
import unittest

import langpack_worker
import main
import pyrogram.raw.all as raw_all
import pyrogram.session.session as session_module
from pyrogram.connection.transport.tcp.tcp import TCP
from pyrogram.raw.functions.messages import GetTranscriptionModels


class KurigramCompatibilityTests(unittest.TestCase):
    def test_layer_pin_is_applied_to_both_raw_and_session_modules(self):
        self.assertEqual(raw_all.layer, 239)
        self.assertEqual(session_module.layer, 239)

    def test_main_transport_patch_preserves_async_close(self):
        main._patch_pyrogram_crypto_executor()
        self.assertTrue(inspect.iscoroutinefunction(TCP.close))
        self.assertTrue(getattr(TCP.close, "_arena_fix", False))

    def test_transcription_models_method_is_available_and_registered(self):
        request = main.build_telegram_method_request(
            "messages.getTranscriptionModels"
        )
        self.assertIsInstance(request, GetTranscriptionModels)
        self.assertEqual(request.version, 1)

    def test_langpack_worker_uses_async_close_patch(self):
        source = inspect.getsource(langpack_worker._patch_pyrogram_crypto_executor)
        self.assertIn("async def close(self)", source)
        self.assertIn("await original_close(self)", source)
