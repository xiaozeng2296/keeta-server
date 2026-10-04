"""Read-only acceptance of the actual workbook, coverage, overflow, and ledger."""
from collections import Counter
from datetime import datetime,timezone
import hashlib,json,sqlite3,zipfile
from pathlib import Path
import openpyxl

def audit(folder,output):
    errors=[]
    paths=[output/'delivery.xlsx',output/'delivery.coverage.json']
    before=[p.stat().st_mtime_ns for p in paths]
    manifest=json.loads((folder/'manifest.json').read_text())
    expected={str(s['shop_id']) for s in manifest['shops']}
    coverage=json.loads(paths[1].read_text())
    shops=coverage['shops'];by_id={str(s['shop_id']):s for s in shops}
    if not expected or len(shops)!=len(expected) or set(by_id)!=expected:
        errors.append('shop_scope_mismatch')
    with paths[0].open('rb') as stream:
        wb=openpyxl.load_workbook(stream,read_only=True,data_only=False)
        try:
            if wb.sheetnames!=['店铺信息','菜品信息']:errors.append('sheet_schema_mismatch')
            actual_counts=[];workbook_shops=set();workbook_items=set()
            for sheet in wb:
                rows=sheet.iter_rows();headers=[c.value for c in next(rows)]
                if 'shop_id' not in headers:errors.append('shop_id_column_missing');continue
                index=headers.index('shop_id');count=0
                for row in rows:
                    count+=1;identifier=str(row[index].value)
                    if identifier not in expected:errors.append('unexpected_workbook_shop')
                    if sheet.title=='店铺信息':workbook_shops.add(identifier)
                    if sheet.title=='菜品信息':workbook_items.add((identifier,str(row[headers.index('item_id')].value)))
                    if any(c.data_type=='f' for c in row):errors.append('unexpected_formula')
                actual_counts.append(count)
            if workbook_shops!=expected:errors.append('workbook_shop_rows_missing')
            if actual_counts!=[coverage['shop_rows'],coverage['item_rows']]:errors.append('row_counts_mismatch')
        finally:wb.close()
    overflow_files=set()
    for entry in coverage.get('overflow',[]):
        rel=Path(entry['file']);p=output/rel
        if p.resolve().parent!=(output/'delivery.overflow').resolve():
            errors.append('invalid_overflow_path');continue
        overflow_files.add(str(rel))
        if not p.is_file():errors.append('overflow_missing');continue
        # The exporter hashes compact JSON encoding of the original string,
        # rather than the raw UTF-8 bytes stored in the overflow file.
        encoded=json.dumps(p.read_text(),ensure_ascii=False,separators=(',',':')).encode()
        if hashlib.sha256(encoded).hexdigest()!=p.stem:errors.append('overflow_hash_mismatch')
    after=[p.stat().st_mtime_ns for p in paths]
    if before!=after:errors.append('export_changed_during_audit')
    with sqlite3.connect('file:'+str(folder/'local.sqlite3')+'?mode=ro',uri=True) as db:
        db.execute('BEGIN')
        state=db.execute("SELECT value FROM meta WHERE key='state'").fetchone()[0]
        task_counts=dict(db.execute('SELECT state,COUNT(*) FROM tasks GROUP BY state'))
        unfinished_requests=db.execute("SELECT COUNT(*) FROM attempts WHERE outcome IN ('reserved','sent')").fetchone()[0]
        skipped_tasks=db.execute("SELECT COUNT(*) FROM tasks WHERE state='skipped_closed'").fetchone()[0]
        unavailable_tasks=db.execute("SELECT COUNT(*) FROM tasks WHERE state='skipped_unavailable'").fetchone()[0]
        menu_products={}
        for shop,endpoint,payload in db.execute("SELECT shop,endpoint,payload FROM results WHERE endpoint IN ('productList','productRender') ORDER BY observed,task"):
            for cat in json.loads(payload)['data'].get('shopCategoryList') or []:
                for p in cat.get('spuList') or []:
                    if p.get('spuId') is not None:menu_products[(shop,str(p['spuId']))]=p
        shop_ids={row[0]:str(json.loads(row[1])['shop_id']) for row in db.execute('SELECT id,data FROM shops')}
        allowed_unavailable={(shop_ids[shop],target) for (shop,target),p in menu_products.items()
                             if p.get('name') and type(p.get('availableStatus')) in (int,str) and p['availableStatus'] in (0,'0')}
        for task,shop,target,reason,data in db.execute("SELECT t.id,t.shop,t.target,t.reason,s.data FROM tasks t JOIN shops s ON s.id=t.shop WHERE t.state='skipped_unavailable'"):
            product=menu_products.get((shop,target),{});sid=str(json.loads(data)['shop_id'])
            confirmed=(reason=='product_unavailable_menu' and type(product.get('availableStatus')) in (int,str) and product['availableStatus'] in (0,'0'))
            if reason=='product_unavailable_response':
                last=db.execute('SELECT http,code FROM attempts WHERE task=? ORDER BY id DESC LIMIT 1',(task,)).fetchone()
                confirmed=last is not None and tuple(last)==(200,'201003212')
            if not confirmed or not product.get('name') or (sid,target) not in workbook_items:
                errors.append('unavailable_skip_without_recorded_evidence')
            elif confirmed:allowed_unavailable.add((sid,target))
        for s in shops:
            for target in s.get('unavailable_detail_ids',[]):
                key=(str(s['shop_id']),target)
                if key not in workbook_items or key not in allowed_unavailable:errors.append('unavailable_coverage_without_evidence')
            if s.get('complete') and s.get('details_required'):
                missing=set(s['missing_detail_ids'])|set(s['nested_unresolved_ids'])
                if missing-set(s.get('unavailable_detail_ids',[])):errors.append('unwaived_details_missing')
            if s.get('complete') and s.get('missing_main_ids'):errors.append('main_items_missing')
            if s.get('complete') and (s.get('required_missing_detail_ids') or s.get('required_nested_unresolved_ids')):
                errors.append('required_details_missing')
    incomplete=[dict(shop_id=s['shop_id'],missing_menu=s.get('missing_main_ids',[]),
                     missing_details=s.get('missing_detail_ids',[]),nested_unresolved=s.get('nested_unresolved_ids',[]))
                for s in shops if not s.get('complete')]
    zip_path=output/'delivery.zip';zip_ok=False
    if zip_path.is_file():
        try:
            with zipfile.ZipFile(zip_path) as archive:
                required={'delivery.xlsx','delivery.coverage.json','summary.json'}|overflow_files
                zip_ok=required<=set(archive.namelist()) and archive.testzip() is None
                if zip_ok:
                    for p in paths:
                        if hashlib.sha256(archive.read(p.name)).digest()!=hashlib.sha256(p.read_bytes()).digest():zip_ok=False
        except (OSError,zipfile.BadZipFile):zip_ok=False
    counts=Counter({key:sum(bool(s.get(key)) for s in shops) for key in
                    ['shop_info_complete','menu_complete','custom_details_complete','full_data_complete','complete']})
    result=dict(checked_at=datetime.now(timezone.utc).isoformat(),state=state,scope_shops=len(expected),
                acceptance_passed=bool(not errors and state=='complete' and counts['complete']==len(expected)
                    and not unfinished_requests and not any(n for k,n in task_counts.items() if k not in ('succeeded','skipped_closed','skipped_unavailable')) and zip_ok),
                workbook_rows=actual_counts,coverage_counts=dict(counts),closed_shops=sum(not s['details_required'] for s in shops),
                closed_skipped_tasks=skipped_tasks,unavailable_skipped_tasks=unavailable_tasks,
                unavailable_skipped_details=sum(len(s.get('unavailable_detail_ids',[])) for s in shops),
                overflow_files=len(overflow_files),artifact_errors=sorted(set(errors)),
                zip_verified=zip_ok,tasks=task_counts,in_flight=unfinished_requests,incomplete_shops=incomplete)
    path=output/'delivery.audit.json';temp=path.with_suffix('.tmp')
    temp.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');temp.replace(path)
    return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
    a=p.parse_args(); manifest=json.loads((a.folder/'manifest.json').read_text())
    result=audit(a.folder,Path(manifest['output']))
    print(json.dumps(result,ensure_ascii=False))
    raise SystemExit(0 if result['acceptance_passed'] else 1)
