"""Bounded XID maintenance; callers already own account/installation locks.

Reports use the same proxy as the next business request. They are recorded in
local usage ledgers and never clear quotas, cooldowns, or start collection.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import fcntl
from farm.local_files import atomic_json
import time
import uuid

import requests
from farm.fullsign import compute_a2, decode_a5
from farm.mysql_store import compact
from mtgsig.fingerprint_refresh import (PATH, STATE, CONFIG, begin_report, build_report,
                                       finish_report, refresh_status)

ROOT = Path(__file__).resolve().parents[1]


class FingerprintRefreshBlocked(RuntimeError):
    pass


def iso(timestamp_ms):
    return datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat()


class ReportJournal:
    """Small file journal, locked across reserve/send/finish and process restarts."""
    def __init__(self, account_id, session_id, root=None):
        self.account_id = account_id
        self.session_id = session_id
        folder = Path(root or ROOT / '.private/account-checks/fingerprint-maintenance') / str(account_id)
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = folder / 'usage.json'
        self.lock = (folder / 'usage.lock').open('a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.rows = json.loads(self.path.read_text()) if self.path.exists() else []
            if not isinstance(self.rows, list):
                raise ValueError('invalid_fingerprint_journal')
        except BaseException:
            self.lock.close()
            raise

    def reserve(self, timestamp_ms):
        since = iso(timestamp_ms - 86400000)
        count = sum(r['account'] == self.account_id and r['started'] >= since
                    and (r['sent'] or r['outcome'] in ('reserved', 'uncertain')) for r in self.rows)
        if count >= 96:
            raise FingerprintRefreshBlocked('fingerprint_daily_limit')
        event = uuid.uuid4().hex
        self.rows.append(dict(account=self.account_id, session_id=self.session_id,
                              endpoint='fingerprintInfo', started=iso(timestamp_ms),
                              finished=None, http=None, sent=0, outcome='reserved',
                              event_id=event, error_type=None))
        atomic_json(self.path, self.rows)
        return event

    def _row(self, event):
        rows = [r for r in self.rows if r['event_id'] == event]
        if len(rows) != 1:
            raise RuntimeError('fingerprint reservation missing')
        return rows[0]

    def sent(self, event):
        row = self._row(event)
        if row['outcome'] != 'reserved':
            raise RuntimeError('fingerprint reservation missing')
        row.update(sent=1, outcome='uncertain')
        atomic_json(self.path, self.rows)

    def finish(self, event, timestamp_ms, status, outcome, error_type=None):
        self._row(event).update(finished=iso(timestamp_ms), http=status,
                                outcome=outcome, error_type=error_type)
        atomic_json(self.path, self.rows)

    def close(self):
        self.lock.close()


def ensure_fingerprint(signer, bundle, *, account_id, session_id, persist, send,
                       journal_root=None, clock=time.time):
    """Refresh at most once if enabled and due; return a redacted result.

    persist(device) must durably save the authoritative account before send.
    send(prepared_request) uses the caller's already selected proxy and timeout.
    A failed/pending refresh blocks this business attempt without an inline loop.
    """
    now = int(clock() * 1000)
    status = refresh_status(signer.dev, now)
    if status in ('disabled', 'fresh'):
        return {'status': status, 'sent': False}
    if status != 'due':
        raise FingerprintRefreshBlocked('fingerprint_' + status)
    # Missing inputs fail before reserving usage or recording an invocation.
    url, headers, body = build_report(bundle, signer, timestamp_ms=now)
    requests.Request('POST', url, headers=headers, data=body.encode()).prepare()
    journal = ReportJournal(account_id, session_id, root=journal_root)
    event = None
    dispatched = False
    completed = False
    response_status = None
    try:
        event = journal.reserve(now)
        begin_report(signer.dev, event, now)
        headers['mtgsig'] = signer.sign('POST', url, body)
        wire = requests.Request('POST', url, headers=headers, data=body.encode()).prepare()
        mt = json.loads(wire.headers['mtgsig'])
        col = json.loads(decode_a5(mt['a5'], mt['a1'], mt['a3'], mt['a4'], profile=signer.signing_profile)[0])
        expected = compute_a2(wire.method, wire.url, wire.body.decode(),
            compact({k: v for k, v in mt.items() if k != 'a2'}), mt['a1'], signer.signature_counter,
            signing_profile=signer.signing_profile, sign_sequence=col['b2'])
        if mt['a2'] != expected:
            raise ValueError('fingerprint prepared signature mismatch')
        persist(signer.persist_counter())
        journal.sent(event)
        dispatched = True
        response = send(wire)
        response_status = response.status_code
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        finished = int(clock() * 1000)
        accepted = finish_report(signer, event, payload, response.status_code, finished)
        persist(signer.persist_counter())
        outcome = 'success' if accepted else 'rejected' if response.status_code == 403 else 'business_error'
        journal.finish(event, finished, response.status_code, outcome)
        completed = True
        if not accepted:
            raise FingerprintRefreshBlocked('fingerprint_report_' + outcome)
        return {'status': 'refreshed', 'sent': True, 'http': response.status_code,
                'interval_minutes': signer.dev[STATE].get('interval_minutes'),
                'expires_at_ms': signer.dev[STATE].get('expires_at_ms')}
    except Exception as exc:
        if event and not completed:
            finished = int(clock() * 1000)
            # Persist errors must remain explicit. No falsely successful result.
            if signer.dev.get(STATE, {}).get('pending_event') == event:
                finish_report(signer, event, {}, None, finished)
                persist(signer.persist_counter())
            outcome = 'persistence_error' if response_status is not None else 'transport_error' if dispatched else 'local_error'
            journal.finish(event, finished, response_status, outcome, type(exc).__name__)
        raise
    finally:
        journal.close()


def before_business(signer, bundle, *, account_id, session_id, persist, proxy, front_proxy=None):
    """Use the worker's route; account/install ownership stays with the caller."""
    from farm.proxy import ProxyRoute
    def send(wire):
        with ProxyRoute(proxy, front_proxy) as route, requests.Session() as session:
            session.trust_env = False
            return session.send(wire, proxies={'http': route, 'https': route} if route else None,
                                timeout=(30, 45), allow_redirects=False)
    return ensure_fingerprint(signer, bundle, account_id=account_id, session_id=session_id,
                              persist=persist, send=send)


def retry_at(device, now=None):
    """Maintenance waits are separate from business rejection and network state."""
    now = time.time() if now is None else now
    state = device.get(STATE) or {}
    if state.get('pending_event') or (state.get('accepted') and state.get('expires_at_ms') is None):
        return now + 3600
    return max(now + 60, state.get('not_before_ms', 0) / 1000)
