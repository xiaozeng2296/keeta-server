import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from farm.env import AccountEnv
from farm.tasks import ShopTask
from farm.worker import crawl_account, product_ids


class FullProductCrawlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = AccountEnv('test', self.temp.name)
        self.env.ensure_dirs()
        self.env.identity_path.write_text('{}')
        self.env.sample_path.write_text('{}')
        self.addCleanup(patch.stopall)
        patch('crawl_keeta.OfflineReSigner').start()
        patch('farm.worker.time.sleep').start()
        self.menu = {'code': 0, 'data': {'shopCategoryList': [
            {'spuIdList': [11, 12], 'spuList': [{'spuId': 11, 'name': 'inline'}]},
            {'spuIdList': [11]}]}}
        self.tasks = [ShopTask('1', '0', '0')]
        patch('crawl_keeta.call', side_effect=lambda signer, path, *a, **k:
              self.menu if path.endswith('productList') else {'code': 0, 'data': {}}).start()

    def test_failed_product_keeps_shop_incomplete_and_resume_reuses_only_success(self):
        def detail(signer, shop, product, *args, **kwargs):
            return {'code': 403} if product == '12' else {'code': 0, 'data': {'spuId': product, 'name': 'Dish'}}
        with patch('crawl_keeta.call_specifics', side_effect=detail) as call:
            first = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0)
            self.assertEqual((first['ok'], first['fail'], first['detail_ok'], first['detail_fail']), (0, 1, 1, 1))
            self.assertEqual(call.call_count, 2)
            self.assertEqual(self.env.done_ids(), set())
        with patch('crawl_keeta.call_specifics', return_value={'code': 0, 'data': {'spuId': '12', 'name': 'Dish'}}) as call:
            second = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0)
            self.assertEqual((second['ok'], second['detail_cached'], second['detail_ok']), (1, 1, 1))
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args[2], '12')
        self.assertTrue(json.loads(self.env.raw_path('1').read_text())['specs_complete'])
        self.assertEqual(self.env.done_ids(), {'1'})

    def test_repeated_rate_limits_stop_without_false_completion(self):
        self.menu['data']['shopCategoryList'][0]['spuIdList'] = [11, 12, 13, 14, 15, 16]
        with patch('crawl_keeta.call_specifics', return_value={'code': 429}) as call:
            result = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0, degrade_after=3)
        self.assertTrue(result['degraded'])
        self.assertEqual(call.call_count, 3)
        self.assertEqual(self.env.done_ids(), set())
        self.assertFalse(json.loads(self.env.raw_path('1').read_text())['specs_complete'])

    def test_wrong_product_response_is_not_a_success(self):
        with patch('crawl_keeta.call_specifics', return_value={'code': 0, 'data': {'spuId': '999', 'name': 'Wrong'}}):
            result = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0)
        self.assertEqual((result['ok'], result['detail_fail']), (0, 2))

    def test_closed_store_stays_incomplete_and_later_run_retries(self):
        with patch('crawl_keeta.call_specifics', return_value={
                'code': 201003202, '_http_status': 200,
                'message': 'This store is currently closed.'}) as call:
            result = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0)
        self.assertEqual(call.call_count, 1)
        self.assertEqual((result['unavailable_shops'], result['detail_unattempted']), (1, 1))
        raw = json.loads(self.env.raw_path('1').read_text())
        self.assertEqual(raw['specs_blocked_reason'], 'store_closed')
        self.assertEqual(raw['specs_unattempted'], ['12'])
        self.assertFalse(raw['specs_complete'])
        self.assertEqual(self.env.done_ids(), set())
        with patch('crawl_keeta.call_specifics', side_effect=lambda signer, shop, product, *a, **kw:
                   {'code': 0, 'data': {'spuId': product, 'name': 'Dish'}}) as call:
            resumed = crawl_account(self.env, self.tasks, delay=0, fetch_specs=True, detail_delay=0)
        self.assertEqual(call.call_count, 2)
        self.assertEqual(resumed['ok'], 1)

    def test_ids_include_inline_and_lazy_but_reject_paths(self):
        self.assertEqual(product_ids(self.menu), ['11', '12'])
        self.menu['data']['shopCategoryList'][0]['spuIdList'].append('../outside')
        with self.assertRaises(ValueError):
            product_ids(self.menu)

    def test_capacity_mode_continues_menus_and_probes_detail_recovery(self):
        tasks = [ShopTask(str(i), '0', '0') for i in range(1, 5)]
        def detail(signer, shop, product, *args, **kwargs):
            if shop in ('1', '2'):
                return {'code': 403, '_http_status': 403}
            return {'code': 0, 'data': {'spuId': product, 'name': 'Dish'}}
        with patch('crawl_keeta.call_specifics', side_effect=detail) as call:
            result = crawl_account(self.env, tasks, delay=0, fetch_specs=True, detail_delay=0,
                                   degrade_after=2, detail_probe_interval=2)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['degraded'])
        self.assertEqual(result['endpoint_stats']['productList']['success'], 4)
        self.assertEqual([c.args[1] for c in call.call_args_list], ['1', '1', '3', '3', '4', '4'])
        self.assertEqual(result['detail_ok'], 4)
        self.assertFalse(json.loads(self.env.raw_path('2').read_text())['specs_complete'])
        self.assertEqual(self.env.done_ids(), {'3', '4'})
        events = [json.loads(line) for line in (self.env.root / 'requests.jsonl').read_text().splitlines()]
        self.assertEqual(len(events), result['requests'])

    def test_capacity_mode_still_stops_on_repeated_menu_rejection(self):
        tasks = [ShopTask(str(i), '0', '0') for i in range(1, 5)]
        def main_response(signer, path, shop, *args, **kwargs):
            if path.endswith('productList'):
                return self.menu if shop == '1' else {'code': 403, '_http_status': 403}
            return {'code': 0, 'data': {}}
        with patch('crawl_keeta.call', side_effect=main_response), \
                patch('crawl_keeta.call_specifics', return_value={'code': 403, '_http_status': 403}):
            result = crawl_account(self.env, tasks, delay=0, fetch_specs=True, detail_delay=0,
                                   degrade_after=2, detail_probe_interval=20)
        self.assertTrue(result['degraded'])
        self.assertEqual(result['attempted_shops'], 3)
        self.assertEqual(result['endpoint_stats']['productList']['rejected'], 2)
        self.assertEqual(self.env.done_ids(), set())

    def test_shop_list_uses_worker_signer_and_stops_at_empty_page(self):
        context = Mock()
        context.build_shop_list.return_value = ('https://example.test/list', {}, '{}')
        tasks = [ShopTask(str(i), '0', '0') for i in range(1, 6)]
        with patch.object(self.env, 'request_context', return_value=context), \
                patch('crawl_keeta._post_signed', side_effect=[
                    {'code': 0, '_http_status': 200, 'data': {'module_body': {'component_list': [{}]}}},
                    {'code': 0, '_http_status': 200, 'data': {'module_body': {'component_list': []}}},
                ]) as send:
            result = crawl_account(self.env, tasks, delay=0, shop_list_interval=2)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['requests'], 12)
        self.assertEqual(result['endpoint_stats']['homeShopList']['success'], 2)
        self.assertEqual([c.args[0] for c in context.build_shop_list.call_args_list], [0, 1])
        self.assertIs(send.call_args_list[0].args[0], send.call_args_list[1].args[0])
        events = [json.loads(line) for line in (self.env.root / 'requests.jsonl').read_text().splitlines()]
        listing_events = [e for e in events if e['endpoint'] == 'homeShopList']
        self.assertEqual([e['page'] for e in listing_events], [0, 1])
        self.assertTrue(all(e['shop_id'] is None for e in listing_events))
        self.assertTrue(result['shop_list_finished'])

    def test_rejected_shop_list_stops_without_advancing_page(self):
        context = Mock()
        context.build_shop_list.return_value = ('https://example.test/list', {}, '{}')
        tasks = [ShopTask(str(i), '0', '0') for i in range(1, 5)]
        with patch.object(self.env, 'request_context', return_value=context), \
                patch('crawl_keeta._post_signed', return_value={'code': 403, '_http_status': 403}):
            result = crawl_account(self.env, tasks, delay=0, shop_list_interval=1, degrade_after=2)
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(result['shop_list_next_page'], 0)
        self.assertEqual(result['endpoint_stats']['homeShopList']['rejected'], 2)
        self.assertFalse(result['shop_list_finished'])

    def test_shop_info_rejection_does_not_hide_successful_product_details(self):
        tasks = [ShopTask(str(i), '0', '0') for i in range(1, 5)]
        def main_response(signer, path, shop, *args, **kwargs):
            if path.endswith('productList'):
                return self.menu
            return {'code': 0, 'data': {}} if shop == '4' else {'code': 403, '_http_status': 403}
        with patch('crawl_keeta.call', side_effect=main_response) as main_call, \
                patch('crawl_keeta.call_specifics', side_effect=lambda signer, shop, product, *a, **kw:
                      {'code': 0, 'data': {'spuId': product, 'name': 'Dish'}}):
            result = crawl_account(self.env, tasks, delay=0, fetch_specs=True,
                                   detail_delay=0, degrade_after=2, shop_info_probe_interval=2)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['detail_ok'], 8)
        self.assertEqual(result['endpoint_stats']['shopInfo']['attempts'], 3)
        self.assertEqual(result['endpoint_stats']['shopInfo']['success'], 1)
        self.assertEqual(self.env.done_ids(), {'4'})
        skipped = json.loads(self.env.raw_path('3').read_text())
        self.assertTrue(skipped['shopInfo']['_deferred'])
        self.assertTrue(skipped['specs_complete'])


if __name__ == '__main__':
    unittest.main()
