import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
import zlib
import openpyxl
from farm.storage import responses as R
from farm.storage.mysql import Store
from farm.delivery.export import write_workbook
from farm.delivery.audit import audit


class LocalResponseTests(unittest.TestCase):
    def test_sql_receives_only_hash_reference_and_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(R,'ROOT',Path(tmp)):
            cursor=Mock();body={'data':{'name':'BODY-STAYS-ON-THIS-HOST'}}
            Store.result(Mock(),cursor,1,2,'shopInfo',body,None)
            params=cursor.execute.call_args.args[1];reference=params[-2]
            self.assertTrue(reference.startswith(R.MAGIC));self.assertNotIn(b'BODY-STAYS',reference)
            self.assertEqual(R.load_response(reference),body)
            sha=reference[len(R.MAGIC):].decode();path=Path(tmp)/sha[:2]/(sha+'.json.z')
            path.write_bytes(zlib.compress(b'{"tampered":true}'))
            with self.assertRaisesRegex(ValueError,'hash_mismatch'):R.load_response(reference)
            path.unlink()
            with self.assertRaises(FileNotFoundError):R.load_response(reference)
            with self.assertRaises(ValueError):R.load_response(R.MAGIC+b'../../private')

    def test_existing_server_blob_is_localized_when_copying_a_run(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(R,'ROOT',Path(tmp)):
            original={'data':'historical'}
            reference=R.local_reference(zlib.compress(json.dumps(original).encode()))
            self.assertTrue(reference.startswith(R.MAGIC));self.assertEqual(R.load_response(reference),original)

    def test_long_unicode_values_are_complete_inside_excel_and_zip_has_only_excel(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp);value='=not_a_formula '+('🍜中文"\n'*9000)
            check={'shop_id':'7','complete':True}
            result=write_workbook(output/'delivery.xlsx',[{'shop_id':'7'}],[{'shop_id':'7','item_id':'9','sub_item_json':value}],[check],{})
            self.assertEqual(result['overflow_cells'],1);self.assertFalse((output/'delivery.overflow').exists())
            wb=openpyxl.load_workbook(output/'delivery.xlsx',read_only=True)
            chunks=list(wb['长字段内容'].iter_rows(min_row=2,values_only=True));wb.close()
            self.assertEqual(''.join(r[6] for r in chunks),value)
            self.assertTrue(all(len(r[6].encode('utf-16-le'))//2<=30000 for r in chunks))
            with zipfile.ZipFile(output/'delivery.zip','w') as archive:archive.write(output/'delivery.xlsx','delivery.xlsx')
            self.assertTrue(audit(output,['7'])['ok'])
