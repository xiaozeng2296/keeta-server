"""Read-only timing/accounting for the authorized recommendation batch."""
from collections import Counter,defaultdict
from datetime import datetime,timezone
import json,sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def read(path):return json.loads(path.read_text()) if path.exists() else {}

def report(folder):
 folder=Path(folder);meta=read(folder/'manifest.json');out=Path(meta['output'])
 manifest=read(folder/'manifest.json');baseline=read(folder/'benchmark-start.json')
 if not baseline:
  print(json.dumps(dict(state='not_started',business_requests=0)));return
 started=baseline['started_at'];now=datetime.now(timezone.utc)
 with sqlite3.connect('file:'+str(folder/'local.sqlite3')+'?mode=ro',uri=True) as db:
  db.row_factory=sqlite3.Row
  db.execute('BEGIN')
  state=db.execute("SELECT value FROM meta WHERE key='state'").fetchone()[0]
  attempts=[dict(r) for r in db.execute('SELECT id,account,endpoint,started,finished,outcome,http,sent,metrics FROM attempts')]
  task_counts=[dict(r) for r in db.execute('SELECT endpoint,state,COUNT(*) n FROM tasks GROUP BY endpoint,state')]
  unavailable=[dict(shop_id=json.loads(r['data'])['shop_id'],product_id=r['target'],task_state=r['state'],attempts=r['attempts']) for r in db.execute("""SELECT t.target,t.state,t.attempts,s.data FROM tasks t JOIN shops s ON s.id=t.shop
   WHERE t.endpoint='productSpecifics' AND t.state NOT IN ('succeeded','skipped_closed','skipped_unavailable')
   AND EXISTS(SELECT 1 FROM attempts a WHERE a.task=t.id AND a.code='201003212')""")]
  # A completed shop here means all generated tasks have succeeded; export
  # coverage remains the separate acceptance gate for the final delivery.
  closed=[r[0] for r in db.execute('SELECT id FROM shops WHERE closed=1')]
  task_complete=db.execute("SELECT COUNT(*) FROM shops s WHERE NOT EXISTS(SELECT 1 FROM tasks t WHERE t.shop=s.id AND t.state NOT IN ('succeeded','skipped_closed','skipped_unavailable'))").fetchone()[0]
 totals=Counter();endpoints=defaultdict(Counter);routes=defaultdict(Counter);accounts=defaultdict(Counter)
 for row in attempts:
  if not row['sent']:continue
  label='in_flight' if row['outcome'] in ('sent','reserved') else row['outcome']
  rid=json.loads(row['metrics']).get('route_id') or manifest['route_bindings'][str(row['account'])]
  for target in (totals,endpoints[row['endpoint']],routes[rid],accounts[str(row['account'])]):
   target['sent']+=1;target[label]+=1
   if row['http']==403:target['http403']+=1
   if row['http']==200:target['http200']+=1
 summary=read(out/'summary.json');coverage=read(out/'delivery.coverage.json')
 collection_start=manifest.get('collection_started_at');terminal=state in ('complete','blocked','stopped')
 finished=(summary.get('collection_finished_at') or summary.get('updated_at') or max((r['finished'] for r in attempts if r['finished']),default=started)) if terminal else now.isoformat()
 maintenance=Counter()
 for aid in manifest['account_ids']:
  path=ROOT/'.private/account-checks/fingerprint-maintenance'/str(aid)/'local.sqlite3'
  if not path.exists():continue
  with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
   for outcome,http,sent,n in db.execute('SELECT outcome,http,sent,COUNT(*) FROM attempts WHERE started>=? AND started<=? GROUP BY outcome,http,sent',(started,finished)):
    maintenance[outcome]+=n
    if sent:maintenance['sent']+=n
    if http==403:maintenance['http403']+=n
 wall=(datetime.fromisoformat(finished)-datetime.fromisoformat(started)).total_seconds()
 collection_seconds=(datetime.fromisoformat(finished)-datetime.fromisoformat(collection_start)).total_seconds() if collection_start else 0
 collection_sent=sum(bool(r['sent']) and r['started']>=collection_start for r in attempts) if collection_start else 0
 repair=read(out/'crash-repair.json');downtime=0
 if repair.get('repair_resume_started_at'):
  downtime=max(0,(datetime.fromisoformat(repair['repair_resume_started_at'])-datetime.fromisoformat(repair['last_precrash_response'])).total_seconds())
 active_seconds=max(0,collection_seconds-downtime)
 for row in attempts:
  if collection_start and row['sent'] and row['started']>=collection_start:
   rid=json.loads(row['metrics']).get('route_id') or manifest['route_bindings'][str(row['account'])]
   routes[rid]['menu_stage_sent']+=1
 for counts in routes.values():counts['menu_requests_per_active_minute']=round(counts['menu_stage_sent']/max(active_seconds,1)*60,2)
 resumed=Counter()
 for row in attempts:
  if repair.get('baseline_attempts') is not None and row['id']>repair['baseline_attempts'] and row['sent']:
   resumed['sent']+=1
   resumed['in_flight' if row['outcome'] in ('sent','reserved') else row['outcome']]+=1
   if row['http']==403:resumed['http403']+=1
 result=dict(updated_at=now.isoformat(),state=state,started_at=started,collection_finished_at=finished if terminal else None,elapsed_seconds=round(wall,2),
  collection_seconds=round(collection_seconds,2),collection_requests_per_minute=round(collection_sent/max(collection_seconds,1)*60,2),
  repair_downtime_seconds=round(downtime,2),collection_active_seconds=round(active_seconds,2),
  collection_active_requests_per_minute=round(collection_sent/max(active_seconds,1)*60,2),after_repair=dict(resumed),
  opening_verification=read(out/'opening-verification.json'),excluded_recommendations=manifest.get('excluded_recommendations',[]),
  shops_with_tasks_complete=task_complete,currently_closed_in_batch=len(closed),business=dict(totals),
  fingerprint_maintenance=dict(maintenance),total_actual_http=totals['sent']+maintenance['sent'],
  endpoints={k:dict(v) for k,v in endpoints.items()},routes={k:dict(v) for k,v in routes.items()},
  accounts={k:dict(v) for k,v in accounts.items()},tasks=task_counts,
  unavailable_products=unavailable,
  preparation_requests={'recommendation_discovery':'not_in_business_ledger','public_ip_preflight':'not_in_business_ledger'},
  final_delivery=summary.get('delivery'),stop_reason=summary.get('stop_reason'),
  note='Wall time includes opening selection, replacement, and repair downtime. Active collection time excludes only documented crash/repair downtime, not cooldown or quota waits. Recommendation discovery and public-IP preflights are excluded. HTTP success does not substitute for final delivery coverage.')
 (out/'benchmark.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k not in ('accounts','tasks','opening_verification','note')},ensure_ascii=False))

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path)
 report(p.parse_args().folder)
