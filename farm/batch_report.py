"""Read-only batch accounting from the single authoritative MySQL ledger."""
import argparse
from collections import Counter, defaultdict
from datetime import timezone
import json
from pathlib import Path
from farm.mysql_store import Store, ROOT, utcnow, unpack_json
from farm.local_files import atomic_json


def report(store, run_id, output=None):
    runs=store.rows('SELECT * FROM collection_runs WHERE id=%s',(run_id,))
    if not runs:raise ValueError('unknown_run')
    run=runs[0];settings=unpack_json(run['settings'])
    attempts=store.rows('SELECT a.* FROM request_attempts a JOIN tasks t ON t.id=a.task_id JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s ORDER BY a.started_at,a.id',(run_id,))
    totals=Counter();accounts=defaultdict(Counter);endpoints=defaultdict(Counter);routes=defaultdict(Counter)
    for row in attempts:
        if not row['counts_budget'] or row['state'] not in ('sent','done','uncertain'):continue
        label='in_flight' if row['state']=='sent' else row['outcome']
        route=settings.get('route_bindings',{}).get(str(row['account_id']),'account_proxy')
        for counter in (totals,accounts[row['account_id']],endpoints[row['endpoint']],routes[route]):
            counter['sent']+=1;counter[label]+=1
            if row['http_status']==403:counter['http403']+=1
            if row['http_status']==200:counter['http200']+=1
    jobs=store.rows("SELECT t.endpoint,t.state,COUNT(*) n FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id=%s GROUP BY t.endpoint,t.state",(run_id,))
    start=min((r['started_at'] for r in attempts),default=None)
    ended=max((r['finished_at'] for r in attempts if r['finished_at']),default=start)
    terminal=run['status'] in ('complete','failed','stopped','incomplete')
    elapsed=((ended if terminal else utcnow())-start).total_seconds() if start else 0
    maintenance=Counter()
    if start:
        end=ended if terminal else utcnow()
        for aid in settings.get('account_ids',sorted(accounts)):
            path=ROOT/'.private/account-checks/fingerprint-maintenance'/str(aid)/'usage.json'
            if not path.exists():continue
            from farm.mysql_store import when
            for row in json.loads(path.read_text()):
                if start<=when(row['started'])<=end and row['sent']:
                    maintenance['sent']+=1;maintenance[row['outcome']]+=1
    result=dict(run_id=run_id,state=run['status'],started_at=start,finished_at=ended if terminal else None,
                elapsed_seconds=round(elapsed,2),business=dict(totals),accounts=dict(accounts),endpoints=dict(endpoints),
                routes=dict(routes),tasks=jobs,fingerprint_maintenance=dict(maintenance),
                note='Elapsed time includes cooldown, quota and network waits; task success is separate from delivery coverage.')
    if output:atomic_json(Path(output),result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run_id',type=int);p.add_argument('--output',type=Path)
    a=p.parse_args();print(json.dumps(report(Store(),a.run_id,a.output),ensure_ascii=False,default=str,indent=2))

if __name__=='__main__':main()
