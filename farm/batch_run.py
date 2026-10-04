"""Verify opening before releasing menus; keep timing across both phases."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import argparse,fcntl,json,os,signal,sys,time
from pathlib import Path
from farm.local_batch import LocalBatch,atomic_json,acknowledge_resume

def main():
 os.umask(0o077)
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--resume',action='store_true')
 args=p.parse_args();folder=args.folder
 with (folder/'runner.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.resume:acknowledge_resume(folder)
  r=LocalBatch(folder)
  if r.db.execute("SELECT value FROM meta WHERE key='state'").fetchone()[0] in ('blocked','stopped') and not args.resume:raise ValueError('explicit_resume_required')
  (folder/'runner.pid').write_text(str(os.getpid())+'\n')
  def stop(*_):r.fatal='user_stop';r.stop.set()
  signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
  baseline=folder/'benchmark-start.json'
  phase_started=time.monotonic()
  if baseline.exists():
   start=json.loads(baseline.read_text());r.started_at=start['started_at'];r.start_attempt_id=start['baseline_attempt_id']
   r.started=time.monotonic()-(time.time()-datetime.fromisoformat(r.started_at).timestamp())
  else:
   atomic_json(baseline,dict(started_at=r.started_at,baseline_attempt_id=r.start_attempt_id,
      includes_shop_verification=True,includes_fingerprint_refresh=True,concurrency=r.manifest['concurrency'],per_route_concurrency=r.manifest['per_route_concurrency']))
  # Resume the existing menu queue without repeating opening verification or
  # resetting the benchmark. run() reconciles interrupted sends conservatively.
  if r.manifest.get('collection_started_at') or not r.manifest.get('verify_open',False):
   if not r.manifest.get('collection_started_at'):
    r.manifest['collection_started_at']=datetime.now(timezone.utc).isoformat()
    atomic_json(folder/'manifest.json',r.manifest);atomic_json(r.output/'manifest.json',r.manifest)
   r.run();return
  r.recover()
  with r.db:r.db.execute("UPDATE meta SET value='running' WHERE key='state'")
  def validate(lane):
   while not r.stop.is_set():
    claim=r.pick(lane)
    if claim:
     assert claim[0]['endpoint']=='shopInfo';r.finish(*claim,*r.send(*claim));continue
    with r.lock:waiting=r.waiting()
    if not waiting:return
    if waiting['retry_at']>time.time()+30:return
    r.stop.wait(.5)
  with ThreadPoolExecutor(max_workers=r.manifest['concurrency']) as pool:
   futures=[pool.submit(validate,i) for i in range(r.manifest['concurrency'])]
   while not all(f.done() for f in futures):
    r.stop.wait(1);r.status()
   for f in futures:f.result()
  rows=r.db.execute("SELECT r.shop,r.payload,r.observed FROM results r WHERE endpoint='shopInfo'").fetchall()
  open_ids=[x['shop'] for x in rows if json.loads(x['payload']).get('data',{}).get('status') in (3,'3')]
  prior=r.manifest.get('selection_active_seconds',0)
  result=dict(checked_at=datetime.now(timezone.utc).isoformat(),requested_shops=len(r.shops),verified_open=len(open_ids),
    returned_shop_info=len(rows),selection_seconds=round(prior+time.monotonic()-phase_started,2),
    not_open=[dict(shop_id=r.shops[x['shop']]['shop_id'],status=json.loads(x['payload']).get('data',{}).get('status')) for x in rows if x['shop'] not in open_ids])
  atomic_json(r.output/'opening-verification.json',result)
  print(json.dumps(dict(event='opening_verification',**result)),flush=True)
  if len(open_ids)!=len(r.shops) or r.stop.is_set():
   r.fatal=r.fatal or 'opening_verification_incomplete'
   with r.db:r.db.execute("UPDATE meta SET value='blocked' WHERE key='state'")
   r.waiters={};r.status('blocked');r.export();return
  with r.db:r.db.execute("UPDATE tasks SET state='pending' WHERE state='selection_hold'")
  r.manifest['phase']='collecting';r.manifest['all_open_verified_at']=result['checked_at']
  r.manifest['collection_started_at']=datetime.now(timezone.utc).isoformat()
  r.manifest['selection_active_seconds']=result['selection_seconds']
  atomic_json(folder/'manifest.json',r.manifest);atomic_json(r.output/'manifest.json',r.manifest)
  r.run()

if __name__=='__main__':main()
