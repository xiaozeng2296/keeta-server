"""Bounded XID maintenance; callers already own account/installation locks.

Reports use the same proxy as the next business request. They are recorded in
local usage ledgers and never clear quotas, cooldowns, or start collection.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
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
    def __init__(self, account_id, session_id, root=None):
        self.account_id = account_id
        self.session_id = session_id
        folder = Path(root or ROOT / '.private/account-checks/fingerprint-maintenance') / str(account_id)
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest = folder / 'manifest.json'
        if not manifest.exists():
            manifest.write_text(compact({'account_ids': [account_id], 'account_session_ids': {},
                                         'purpose': 'fingerprint_refresh'}))
            manifest.chmod(0o600)
        self.db = sqlite3.connect(folder / 'local.sqlite3', timeout=5)
        (folder / 'local.sqlite3').chmod(0o600)
        self.db.execute('''CREATE TABLE IF NOT EXISTS attempts(
            id INTEGER PRIMARY KEY, account INTEGER, session_id INTEGER, endpoint TEXT,
            started TEXT, finished TEXT, outcome TEXT, sent INTEGER DEFAULT 0,
            http INTEGER, event_id TEXT UNIQUE, error_type TEXT)''')
        self.db.commit()

    def reserve(self, timestamp_ms):
        since = iso(timestamp_ms - 86400000)
        # Persisted sliding cap across process restarts and active-session changes.
        count = self.db.execute("SELECT COUNT(*) FROM attempts WHERE account=? AND started>=? AND (sent=1 OR outcome IN ('reserved','uncertain'))",
                                (self.account_id, since)).fetchone()[0]
        if count >= 96:
            raise FingerprintRefreshBlocked('fingerprint_daily_limit')
        event = uuid.uuid4().hex
        with self.db:
            self.db.execute("INSERT INTO attempts(account,session_id,endpoint,started,outcome,event_id) VALUES(?,?,'fingerprintInfo',?,'reserved',?)",
                            (self.account_id, self.session_id, iso(timestamp_ms), event))
        return event

    def sent(self, event):
        with self.db:
            changed = self.db.execute("UPDATE attempts SET sent=1,outcome='uncertain' WHERE event_id=? AND outcome='reserved'", (event,))
            if changed.rowcount != 1:
                raise RuntimeError('fingerprint reservation missing')

    def finish(self, event, timestamp_ms, status, outcome, error_type=None):
        with self.db:
            self.db.execute('UPDATE attempts SET finished=?,http=?,outcome=?,error_type=? WHERE event_id=?',
                            (iso(timestamp_ms), status, outcome, error_type, event))

    def close(self):
        self.db.close()


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
