"""Explicit reporting outer fields, independent of captured body defaults."""
from copy import deepcopy
import unittest

from mtgsig.registration_reporting import build_reporting_outer


class ReportingOuterTests(unittest.TestCase):
    def test_device_timestamp_uses_explicit_offset_across_calendar_boundary(self):
        inputs = dict(timezone_offset_seconds=-3600, sdk_version='5.21.10', ext=3)
        value = build_reporting_outer('device_info', inputs, timestamp_ms=0)
        self.assertEqual(value, {'dfpVersion': '5.21.10', 'os': 'iOS', 'mtgVersion': '5.21.10',
                                 'time': '1969-12-31 23:00:00', 'ext': '3'})
        inputs['timezone_offset_seconds'] = 8*3600
        self.assertEqual(build_reporting_outer('device_info', inputs, timestamp_ms=999)['time'],
                         '1970-01-01 08:00:00')

    def test_bio_history_preserves_order_revisits_and_values(self):
        inputs = dict(index=2, region_events=[{'GG': 100}, {'HK': '200'}, {'GG': 301}])
        original = deepcopy(inputs)
        self.assertEqual(build_reporting_outer('bio_report', inputs, timestamp_ms=999999),
                         {'index': '2', 'encryptVersion': '1', 'src': '1',
                          'regionPath': '[{"GG":"100"},{"HK":"200"},{"GG":"301"}]'})
        self.assertEqual(inputs, original)

    def test_missing_inputs_do_not_fall_back_to_capture(self):
        for name in ('device_info', 'bio_report'):
            for inputs in (None, {}, {'regionPath': 'old-captured-history'}, {'time': 'old-captured-time'}):
                with self.subTest(name=name, inputs=inputs), self.assertRaises(ValueError):
                    build_reporting_outer(name, inputs, timestamp_ms=0)

    def test_bio_index_uses_native_signed_int32_wire_format(self):
        for index, expected in ((0x7fffffff, '2147483647'),
                                (0x80000000, '-2147483648'),
                                (0xffffffff, '-1'),
                                ('4294967295', '-1')):
            with self.subTest(index=index):
                value = build_reporting_outer('bio_report',
                    dict(index=index, region_events=[{'HK': 1}]), timestamp_ms=0)
                self.assertEqual(value['index'], expected)

    def test_invalid_bio_index_or_history_is_rejected(self):
        for index in (0, -1, True, '01', 1 << 32):
            with self.subTest(index=index), self.assertRaises(ValueError):
                build_reporting_outer('bio_report', dict(index=index, region_events=[{'HK': 1}]), timestamp_ms=0)
        for events in ([], [{'HK': True}], [{'hk': 1}], [{'HK': 1, 'GG': 2}], [{'HK': -1}], [{'HK': '01'}]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                build_reporting_outer('bio_report', dict(index=1, region_events=events), timestamp_ms=0)

    def test_device_rejects_inferred_or_invalid_timezone_and_version(self):
        for offset in (None, True, 61, 15*3600):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                build_reporting_outer('device_info', dict(timezone_offset_seconds=offset,
                    sdk_version='5.21.10', ext=3), timestamp_ms=0)
        with self.assertRaises(ValueError):
            build_reporting_outer('device_info', dict(timezone_offset_seconds=0,
                sdk_version='unknown', ext=3), timestamp_ms=0)


if __name__ == '__main__':
    unittest.main()
