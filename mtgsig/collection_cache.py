"""Continue observed collection caches, without inventing device measurements.

Periodic mode continues the observed 60-second timer from its captured anchor.
It does not reproduce native scheduling jitter or remeasure sensors. Original
snapshots remain untouched; the advanced cache is persisted with the sequence.
"""
from copy import deepcopy
import hashlib
import json
import zlib


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def rebase_detection_timestamp(observed, timestamp_ms):
    """Update only 58 and its observed CRC delta in 55 (equal-width timestamps).

    Capture vectors establish a CRC difference with one trailing byte. NUL is
    a convenient equal suffix for computing that difference, not a recovered
    literal suffix or the complete checksum preimage. Other fields are copied.
    """
    previous, checksum = observed.get('58'), observed.get('55')
    if (not isinstance(previous, str) or not previous.isascii() or not previous.isdigit()
            or not isinstance(checksum, str) or not checksum.isascii() or not checksum.isdigit()
            or not 0 <= int(checksum) <= 0xffffffff):
        raise ValueError('detection cache requires observed decimal-string 55/58')
    if type(timestamp_ms) is not int or timestamp_ms < 0 or len(str(timestamp_ms)) != len(previous):
        raise ValueError('detection timestamp must retain its observed decimal width')
    current = str(timestamp_ms)
    result = deepcopy(observed)
    result['55'] = str(int(checksum) ^ zlib.crc32((previous+'\0').encode('ascii'))
                       ^ zlib.crc32((current+'\0').encode('ascii')))
    result['58'] = current
    return result


def _validate(collect, siua):
    if any(type(collect.get(k)) is not int or collect[k] < 0 for k in ('b8', 'b9', 'b13')):
        raise ValueError('periodic cache requires observed integer b8/b9/b13')
    # Native b8 reads siuaCollectTime; b9 reads envCheckTime. Real imports
    # include a one-second boundary between these independent collections.
    if collect['b9'] - collect['b8'] not in (0, 1):
        raise ValueError('periodic cache requires an observed zero/one-second b8/b9 gap')
    try:
        detection = json.loads(collect['b1'])
        slots = siua['2']
        same_detection = json.loads(slots[3]) == detection
        sampled_ms = int(slots[9])
        valid_clock = isinstance(slots[9], str) and slots[9].isdigit() and sampled_ms > 0
        valid_xid = isinstance(slots[15], str) and slots[15].isdigit()
    except (KeyError, ValueError, TypeError, IndexError):
        raise ValueError('periodic cache requires a decoded SIUA with collection clocks') from None
    if not same_detection or not valid_clock or not valid_xid:
        raise ValueError('a5/a9 detection caches or observed clocks disagree')
    rebase_detection_timestamp(detection, int(detection['58']))
    if int(detection['58']) // 1000 != collect['b9']:
        raise ValueError('detection timestamp and collection epoch disagree')
    return detection


class CollectionCache:
    def __init__(self, storage):
        self.storage = storage
        original = {'collect': storage['base_collect'], 'siua': json.loads(storage['base_siua'])}
        _validate(original['collect'], original['siua'])
        self.source_hash = hashlib.sha256(compact(original).encode()).hexdigest()
        saved = storage.get('collection_cache')
        if saved is not None:
            if saved.get('version') != 1 or saved.get('source_hash') != self.source_hash:
                raise ValueError('persisted collection cache belongs to a different snapshot')
            _validate(saved['collect'], saved['siua'])
        self.state = deepcopy(saved or dict(original, version=1, source_hash=self.source_hash))
        self.serialized_siua = compact(self.state['siua']) if saved else storage['base_siua']

    def refresh(self, timestamp_ms):
        if type(timestamp_ms) is not int or timestamp_ms < 0:
            raise ValueError('collection timestamp must be nonnegative integer milliseconds')
        col, siua = self.state['collect'], self.state['siua']
        previous_ms = int(json.loads(col['b1'])['58'])
        if timestamp_ms < previous_ms:
            raise ValueError('collection clock moved backwards; a new observation is required')
        if timestamp_ms - previous_ms < 60000:
            return deepcopy(col), self.serialized_siua
        periods = (timestamp_ms - previous_ms) // 60000
        timestamp_ms = previous_ms + periods * 60000
        new_col, new_siua = deepcopy(col), deepcopy(siua)
        detection = rebase_detection_timestamp(json.loads(col['b1']), timestamp_ms)
        new_col['b1'] = compact(detection)
        elapsed_ms = periods * 60000
        new_col['b8'] += elapsed_ms // 1000
        new_col['b9'] += elapsed_ms // 1000
        # Explicit continuous-timer model; native suspend/resume requires a
        # new observation. Never derive the count from b7/startup heuristics.
        new_col['b13'] += periods
        slots = new_siua['2']
        slots[3] = new_col['b1']
        # Carry a nonzero server-clock observation forward by elapsed time.
        # Zero means no calibration was observed and must remain zero.
        if int(slots[15]):
            slots[15] = str(int(slots[15]) + elapsed_ms)
        # SIUA m150 and b1.58 are distinct samples; retain their observed
        # subsecond offset, including samples that cross a second boundary.
        slots[9] = str(int(slots[9]) + elapsed_ms)
        self.state = dict(version=1, source_hash=self.source_hash, collect=new_col, siua=new_siua)
        self.storage['collection_cache'] = deepcopy(self.state)
        self.serialized_siua = compact(new_siua)
        return deepcopy(new_col), self.serialized_siua
