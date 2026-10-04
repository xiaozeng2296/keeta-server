import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from farm.env import AccountEnv
from farm.tasks import ShopTask
from farm.worker import crawl_account


class FarmMenuFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = AccountEnv("test", self.temp.name)
        self.env.ensure_dirs()
        self.env.identity_path.write_text('{}')
        self.env.sample_path.write_text('{}')
        self.task = ShopTask("1", "-23.5", "-46.6")
        self.addCleanup(patch.stopall)
        patch("crawl_keeta.OfflineReSigner").start()
        patch("farm.worker.time.sleep").start()

    @staticmethod
    def response(signer, path, *args, **kwargs):
        if path.endswith("productList"):
            return {"code": 403}
        return {"code": 0, "data": {}}

    def test_menu_failure_is_not_done_and_is_retried(self):
        with patch("crawl_keeta.call", side_effect=self.response) as call:
            for _ in range(2):
                result = crawl_account(self.env, [self.task], delay=0)
                self.assertEqual((result["ok"], result["fail"], result["skip"]), (0, 1, 0))
                self.assertEqual(self.env.done_ids(), set())
            self.assertEqual(call.call_count, 4)
        self.assertEqual(json.loads(self.env.raw_path("1").read_text())["productList"]["code"], 403)

    def test_previous_false_done_does_not_hide_failed_menu(self):
        self.env.raw_path("1").write_text(json.dumps({
            "shopInfo": {"code": 0}, "productList": {"code": 403}}))
        self.env.mark_done("1")
        with patch("crawl_keeta.call", return_value={"code": 0, "data": {}}) as call:
            result = crawl_account(self.env, [self.task], delay=0)
            self.assertEqual((result["ok"], result["skip"]), (1, 0))
            self.assertEqual(call.call_count, 2)
            again = crawl_account(self.env, [self.task], delay=0)
            self.assertEqual(again["skip"], 1)
            self.assertEqual(call.call_count, 2)

    def test_menu_403_degrades_and_persists_full_signer(self):
        self.env.sample_path.unlink()
        self.env.device_id_path.write_text('{}')
        self.assertTrue(self.env.is_ready())
        with patch("farm.fullsign.FullSigner") as signer, patch(
                "crawl_keeta.call", side_effect=self.response):
            result = crawl_account(self.env, [self.task, ShopTask("2", "1", "2")],
                                   delay=0, degrade_after=2)
            self.assertTrue(result["degraded"])
            self.assertEqual(result["fail"], 2)
            self.assertEqual(result["ok"], 0)
            self.assertEqual(self.env.done_ids(), set())
            signer.return_value.persist_counter.assert_called_once_with()

    def test_shop_403_is_counted_on_early_return(self):
        with patch("crawl_keeta.call", return_value={"code": 403}):
            result = crawl_account(self.env, [self.task], delay=0, degrade_after=1)
        self.assertEqual(result["fail"], 1)
        self.assertTrue(result["degraded"])

    def test_interrupted_worker_persists_counter(self):
        self.env.device_id_path.write_text('{}')
        with patch("farm.fullsign.FullSigner") as signer, patch(
                "crawl_keeta.call", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                crawl_account(self.env, [self.task], delay=0)
            signer.return_value.persist_counter.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
