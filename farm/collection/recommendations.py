"""Fetch bounded recommendation pages with the current session and persisted usage."""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import uuid

from farm.accounts.checks import DatabaseProbe
from farm.accounts.maintenance import account_lock
from farm.storage.files import atomic_json
from farm.storage.mysql import Store


def open_candidates(data, location, page, observed):
    shops=[]
    for component in (data or {}).get('data',{}).get('module_body',{}).get('component_list',[]):
        card=component.get('json_data',{}); status=card.get('shopStatus',{})
        if status.get('shopStatusCode')!=3 or status.get('hasOutOfRange')!=0: continue
        name=next((part.get('data',{}).get('name') for line in card.get('content',[]) for part in line if part.get('type')=='shopName'),None)
        if card.get('shopId') and name:
            shops.append(dict(location,shop_id=str(card['shopId']),shop_name=name,recommendation_page=page,
                              recommendation_observed_at=observed,recommendation_status=3))
    return shops


def discover(store, aid, location, output, pages):
    output=Path(output)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    active=store.rows('SELECT active_session_id FROM accounts WHERE id=%s',(aid,))
    if not active: raise ValueError('account_has_no_active_session')
    found={};trace=None;records=[]
    for page in range(pages):
        page_output=output/('recommend-%03d-%s'%(page,uuid.uuid4().hex[:12]));page_output.mkdir(mode=0o700)
        probe=DatabaseProbe(store,aid,dict(location,shop_id='0'),clear_verified=False)
        complete=False
        try:
            payload={'page':page}
            if trace: payload['bizTraceId']=trace
            row,data=probe.send('homeShopList',payload,'')
            complete=True
        finally: probe.close(complete)
        observed=datetime.now(timezone.utc).isoformat()
        records.append(dict(page=page,checked_at=observed,result=row))
        atomic_json(page_output/'report.json',records[-1])
        if not data: break
        for shop in open_candidates(data,location,page,observed): found.setdefault(shop['shop_id'],shop)
        body=data['data']['module_body']
        trace=body.get('extra_data',{}).get('bizTraceId')
        if not body.get('module_data',{}).get('pagination',{}).get('has_more_page'): break
    result=dict(account_id=aid,pages=records,candidate_count=len(found),shops=list(found.values()),
                note='Recommendation status is a candidate filter; verify shopInfo before assuming opening.')
    atomic_json(output/'candidate-pool.json',result)
    return result


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--account',type=int,required=True);p.add_argument('--latitude',required=True)
    p.add_argument('--longitude',required=True);p.add_argument('--city-id',required=True)
    p.add_argument('--pages',type=int,default=6);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--execute',action='store_true');a=p.parse_args()
    if not 1<=a.pages<=50:p.error('pages must be 1..50')
    if not -90<=float(a.latitude)<=90 or not -180<=float(a.longitude)<=180:p.error('invalid location')
    location=dict(latitude=a.latitude,longitude=a.longitude,city_id=a.city_id)
    if not a.execute: print(json.dumps(dict(preview=True,account=a.account,max_pages=a.pages,location=location)));return
    result=discover(Store(),a.account,location,a.output,a.pages)
    print(json.dumps({k:v for k,v in result.items() if k!='shops'}))

if __name__=='__main__':main()
