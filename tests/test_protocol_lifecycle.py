"""Configuration observation must distinguish traffic, writes and activation."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from tools.protocol_watch import NativeOperationError, lifecycle_summary, observe_configuration


def event(kind, thread=1, **fields):
    return dict(kind=kind, thread=thread, **fields)


def callback(thread=1, success=True):
    return [event('callback_enter', thread, type='production', success=success),
            event('storage_write_enter', thread), event('storage_write_leave', thread),
            event('callback_leave', thread, type='production')]


def observation(events):
    state = {'provider_present': True, 'parameter': 25, 'salt_sha256': 'salt-hash', 'a6': 0}
    return {'trace': {'events': events, 'state': state, 'dropped': 0},
            'initial_trace': {'state': deepcopy(state)}, 'seconds': 2,
            'final_configuration': {'decode_status': 'decoded', 'parameter': 25, 'salt_sha256': 'salt-hash'}}


class LifecycleSummaryTests(unittest.TestCase):
    def test_equal_state_or_http_304_does_not_prove_callback(self):
        for events in ([], [event('horn_result', http_status=304, load_source=4, error_code=None)]):
            summary = lifecycle_summary(observation(events))
            self.assertEqual(summary['status'], 'no_complete_callback_write_observed')
            self.assertEqual(summary['linked_callback_writes'], 0)
            self.assertTrue(summary['stored_configuration_matches_provider'])
        self.assertEqual(summary['horn_results'], [{'http_status': 304, 'load_source': 4, 'error_code': None}])

    def test_completed_callback_write_does_not_imply_provider_reload(self):
        summary = lifecycle_summary(observation(callback()))
        self.assertEqual(summary['status'], 'callback_and_storage_observed')
        self.assertEqual(summary['linked_callback_writes'], 1)
        self.assertEqual(summary['active_provider_load_count'], 0)

    def test_cross_thread_write_and_failed_callback_are_not_linked(self):
        events = callback()
        events[1]['thread'] = events[2]['thread'] = 2
        for values in (events, callback(success=False)):
            summary = lifecycle_summary(observation(values))
            self.assertEqual(summary['linked_callback_writes'], 0)
            self.assertEqual(summary['status'], 'no_complete_callback_write_observed')

    def test_nested_callbacks_and_reentrant_writes_keep_ownership(self):
        nested = callback(); nested[0]['type'] = nested[-1]['type'] = 'test'
        events = [callback()[0], event('storage_write_enter'), *nested,
                  event('storage_write_enter'), event('storage_write_leave'),
                  event('storage_write_leave'), callback()[-1]]
        summary = lifecycle_summary(observation(events))
        self.assertEqual(summary['status'], 'callback_and_storage_observed')
        self.assertEqual(summary['linked_callback_writes'], 3)

    def test_incomplete_or_mismatched_invocations_cannot_pass(self):
        for extra in (callback()[:-1], [event('storage_write_leave')],
                      [event('provider_configure_leave', active_provider=True, result=1)],
                      [event('provider_configure_enter')],
                      [event('provider_initialize_enter')],
                      [event('provider_initialize_enter'), event('provider_configure_leave')],
                      [callback()[0], event('callback_leave', type='wrong')],
                      [event('storage_write_enter', thread=None)]):
            with self.subTest(extra=extra):
                summary = lifecycle_summary(observation(callback() + extra))
                self.assertEqual(summary['status'], 'incomplete_observation')
        summary = lifecycle_summary(observation(callback()[:-1]))
        self.assertEqual(summary['linked_callback_writes'], 0)

    def test_only_completed_successful_active_provider_load_is_counted(self):
        events = []
        for active, result in ((False, 1), (True, 0), (True, 1)):
            events.extend([event('provider_configure_enter'),
                           event('provider_configure_leave', active_provider=active, result=result)])
        summary = lifecycle_summary(observation(events))
        self.assertEqual(summary['active_provider_load_count'], 1)
        self.assertEqual(summary['status'], 'no_complete_callback_write_observed')

    def test_parameter_and_salt_are_both_required_for_state_match(self):
        for field, value in (('parameter', 20), ('salt_sha256', 'different-salt')):
            data = observation(callback()); data['final_configuration'][field] = value
            self.assertFalse(lifecycle_summary(data)['stored_configuration_matches_provider'])
        data['final_configuration']['decode_status'] = 'unsupported_configuration'
        self.assertIsNone(lifecycle_summary(data)['stored_configuration_matches_provider'])
        data = observation([]); data['final_configuration']['decode_status'] = 'default'
        self.assertTrue(lifecycle_summary(data)['stored_configuration_matches_provider'])

    def test_event_loss_or_observer_error_invalidates_positive_window(self):
        data = observation(callback()); data['trace']['dropped'] = 1
        self.assertEqual(lifecycle_summary(data)['status'], 'incomplete_observation')
        data['trace']['dropped'] = 0
        data['trace']['events'].append(event('observer_error'))
        self.assertEqual(lifecycle_summary(data)['status'], 'incomplete_observation')


class LifecycleCaptureTests(unittest.TestCase):
    def setup_capture(self, output):
        args = SimpleNamespace(pid=123, timeout=2, seconds=0, refresh=False, out=output)
        device = MagicMock(); script = device.attach.return_value.create_script.return_value
        rpc = script.exports_sync
        rpc.metadata.return_value = {'bundle_id': 'com.sankuai.sailor.ifooddelivery'}
        rpc.configuration.return_value = {'available': True, 'value': None}
        rpc.start_lifecycle.return_value = observation([])['initial_trace']
        rpc.lifecycle_snapshot.return_value = observation([])['trace']
        return args, device, script

    def test_default_is_passive_and_refresh_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            for refresh in (False, True):
                args, device, script = self.setup_capture(Path(directory) / 'capture.json')
                args.refresh = refresh
                script.exports_sync.refresh_configuration.return_value = {'requested': True}
                with patch('tools.protocol_watch.connect_device', return_value=device), \
                     patch('tools.protocol_watch.native_call', side_effect=lambda op, fn, timeout: fn()):
                    summary = observe_configuration(args)
                self.assertEqual(summary['refresh_requested'], refresh)
                self.assertEqual(script.exports_sync.refresh_configuration.call_count, int(refresh))
                device.attach.return_value.detach.assert_called_once()

    def test_interruption_preserves_stream_and_primary_error_despite_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'capture.json'
            args, device, script = self.setup_capture(output)
            streamed = event('callback_enter', type='production', success=True)
            def start():
                script.on.call_args.args[1]({'type': 'send', 'payload':
                    {'kind': 'config_lifecycle_event', 'event': streamed}}, None)
                return observation([])['initial_trace']
            script.exports_sync.start_lifecycle.side_effect = start
            script.exports_sync.lifecycle_snapshot.side_effect = NativeOperationError('lifecycle_snapshot', RuntimeError())
            script.exports_sync.stop_lifecycle.side_effect = NativeOperationError('stop_lifecycle', RuntimeError())
            device.attach.return_value.detach.side_effect = NativeOperationError('detach', RuntimeError())
            with patch('tools.protocol_watch.connect_device', return_value=device), \
                 patch('tools.protocol_watch.native_call', side_effect=lambda op, fn, timeout: fn()):
                with self.assertRaises(NativeOperationError) as caught:
                    observe_configuration(args)
            self.assertEqual(caught.exception.operation, 'lifecycle_snapshot')
            self.assertEqual(caught.exception.saved, str(output))
            saved = json.loads(output.read_text())
            self.assertEqual(saved['status'], 'interrupted_observation')
            self.assertEqual(saved['streamed_events'], [streamed])
            self.assertFalse(saved['final_state_observed'])
            self.assertNotIn('final_configuration', saved)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
