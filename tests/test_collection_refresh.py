"""Counter/cache regressions, using independently observed CRC vectors."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from farm import fullsign as fs
from mtgsig.collection_cache import CollectionCache, rebase_detection_timestamp
from tests import test_signing_profiles as profiles

# Only public clock/checksum pairs; no identity, credentials or cipher keys.
VECTORS = [(1790732174300, 3040635815), (1790732234348, 3499430392),
           (1790732294311, 2785495868), (1790732354339, 3169836693),
           (1790732414311, 696581227), (1790732474339, 880820496)]


def identity():
    sample = profiles.SigningProfileTests().sample('legacy')
    dev = {k: sample[k] for k in ('a0','a1','a3','a6','a7','a8','a9','x0')}
    det = json.dumps({'33': 'observed', '55': str(VECTORS[0][1]), '58': str(VECTORS[0][0])}, separators=(',', ':'))
    col = dict(profiles.COLLECT, b1=det, b2=46, b17=45, b18=0, b8=1790732174, b9=1790732174, b13=2)
    slots = [''] * 23
    slots[3], slots[9], slots[15] = det, '1790732174270', '1790732174615'
    siua = {'0':12, '1':['sensor-observation'], '2':slots, '3':'{}'}
    dev.update(base_collect=col, base_siua=json.dumps(siua, separators=(',', ':')), a9_profile='default', a9_mode='twofish',
               signing_profile='legacy', sign_sequence=46, signature_counter=168, collection_clock_mode='periodic')
    return dev


class CollectionRefreshTests(unittest.TestCase):
    def test_crc_matches_independent_capture_vectors_and_is_composable(self):
        source = {'55': str(VECTORS[0][1]), '58': str(VECTORS[0][0]), 'physical':'observed'}
        for timestamp, checksum in VECTORS:
            out = rebase_detection_timestamp(source, timestamp)
            self.assertEqual(out['55'], str(checksum))
            self.assertEqual(out['physical'], 'observed')
            self.assertEqual(rebase_detection_timestamp(out, VECTORS[0][0]), source)
        self.assertEqual(source['58'], str(VECTORS[0][0]))

    def test_crc_rejects_unsupported_width_and_missing_seed(self):
        for seed, timestamp in (({'55':'1','58':'999'},1000), ({'58':'1790732174300'},1790732174301),
                                ({'55':'4294967296','58':'1790732174300'},1790732174301)):
            with self.assertRaises(ValueError): rebase_detection_timestamp(seed,timestamp)

    def test_cache_expiry_catchup_and_reload_preserve_observations(self):
        dev = identity(); original = deepcopy(dev); cache = CollectionCache(dev)
        for timestamp in (1790732174300,1790732234299):
            col, raw = cache.refresh(timestamp)
            self.assertEqual(col, dev['base_collect']); self.assertEqual(raw, dev['base_siua'])
        col, raw = cache.refresh(1790732234300)
        self.assertEqual((col['b8'],col['b9'],col['b13']), (1790732234,1790732234,3))
        siua = json.loads(raw)
        self.assertEqual(siua['2'][3], col['b1'])
        self.assertEqual(siua['2'][9], '1790732234270')
        self.assertEqual(siua['2'][15], '1790732234615')
        self.assertEqual(siua['1'], json.loads(original['base_siua'])['1'])
        restored = CollectionCache(json.loads(json.dumps(dev)))
        self.assertEqual(restored.refresh(1790732234400), (col,raw))
        col,_ = restored.refresh(1790732474400)
        self.assertEqual(col['b13'],7)
        self.assertEqual(dev['base_collect'],original['base_collect'])
        self.assertEqual(dev['base_siua'],original['base_siua'])
        with self.assertRaises(ValueError): restored.refresh(1790732174300)

    def test_cross_second_native_cache_preserves_all_clock_offsets_on_reload(self):
        # Observed imports: SIUA starts in the preceding second, then env check
        # and m150 finish in the next second. These are public timing deltas.
        for detection_ms, sampled_ms in ((1022, 1043), (1012, 1053)):
            dev = identity(); col = dev['base_collect']; base = 1790760359000
            col.update(b8=base//1000, b9=base//1000+1)
            det = rebase_detection_timestamp(json.loads(col['b1']), base+detection_ms)
            col['b1'] = json.dumps(det,separators=(',',':'))
            siua = json.loads(dev['base_siua'])
            siua['2'][3],siua['2'][9],siua['2'][15] = col['b1'],str(base+sampled_ms),'0'
            dev['base_siua'] = json.dumps(siua,separators=(',',':'))
            original = deepcopy(dev)
            cache = CollectionCache(dev)
            for periods in (1, 5):
                new_col, raw = cache.refresh(base+detection_ms+periods*60000)
                new_siua = json.loads(raw)
                self.assertEqual(new_col['b9']-new_col['b8'],1)
                self.assertEqual(int(json.loads(new_col['b1'])['58'])-int(new_siua['2'][9]),detection_ms-sampled_ms)
                self.assertEqual(new_siua['2'][15],'0')
                self.assertEqual(new_col['b13'],original['base_collect']['b13']+periods)
                cache = CollectionCache(json.loads(json.dumps(dev)))
                self.assertEqual(cache.refresh(base+detection_ms+periods*60000),(new_col,raw))
            self.assertEqual(dev['base_collect'],original['base_collect'])
            self.assertEqual(dev['base_siua'],original['base_siua'])

    def test_unknown_clock_gaps_remain_rejected(self):
        for gap in (-1,2,60):
            dev=identity();dev['base_collect']['b8']=dev['base_collect']['b9']-gap
            with self.assertRaises(ValueError):CollectionCache(dev)

    def test_cache_rejects_mismatch_and_keeps_uncalibrated_xid_zero(self):
        dev = identity(); s=json.loads(dev['base_siua']);s['2'][15]='0';dev['base_siua']=json.dumps(s)
        _,raw = CollectionCache(dev).refresh(1790732234300)
        self.assertEqual(json.loads(raw)['2'][15],'0')
        dev['base_collect']['b13']+=1
        with self.assertRaises(ValueError): CollectionCache(dev)
        dev = identity(); dev['base_collect']['b1']='{}'
        with self.assertRaises(ValueError): CollectionCache(dev)

    def test_signer_updates_linked_payload_and_survives_reload(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'identity.json'; dev = identity();path.write_text(json.dumps(dev));signer=fs.FullSigner(path)
            for ordinal,now in enumerate((1790732175.0,1790732234.4,1790732235.0),1):
                with patch('farm.fullsign.time.time',return_value=now):
                    mt=json.loads(signer.sign('POST','https://example.test/detail','{}'))
                a5=json.loads(fs.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])
                a9=json.loads(fs._detect_a9_codec(mt['a9'],mt['a1'])['plain'])
                self.assertEqual((a5['b2'],a5['b17'],a5['b18']),(46+ordinal,45+ordinal,0))
                self.assertEqual(json.loads(a5['b1']),json.loads(a9['2'][3]))
                self.assertEqual(a5['b13'],2 if ordinal==1 else 3)
                expected=mt.pop('a2')
                self.assertEqual(expected,fs.compute_a2('POST','https://example.test/detail','{}',json.dumps(mt,separators=(',',':')),
                                                      mt['a1'],168,sign_sequence=a5['b2']))
                signer.persist_counter(); signer=fs.FullSigner(path)
                self.assertEqual(signer.dev['base_collect'],dev['base_collect'])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_post_advances_b17_even_when_sequence_gap_is_large(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'id.json';dev=identity();dev['collection_clock_mode']='captured';dev['base_collect']['b17']=7
            path.write_text(json.dumps(dev));signer=fs.FullSigner(path)
            mt=json.loads(signer.sign('POST','https://example.test/detail','{}'))
            col=json.loads(fs.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])
            self.assertEqual(col['b17'],8)

    def test_zero_b18_remains_zero_at_startup(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'id.json';dev=identity();dev['collection_clock_mode']='captured'
            dev['sign_sequence']=0;dev['base_collect'].update(b2=0,b17=0,b18=0)
            path.write_text(json.dumps(dev));signer=fs.FullSigner(path)
            mt=json.loads(signer.sign('POST','https://example.test/detail','{}'))
            col=json.loads(fs.decode_a5(mt['a5'],mt['a1'],mt['a3'],mt['a4'])[0])
            self.assertEqual((col['b2'],col['b17'],col['b18']),(1,1,0))


if __name__=='__main__':unittest.main()
