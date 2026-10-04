"""MySQL-backed Keeta account import, queue, budgets, statistics and delivery export."""
import argparse
import json
from pathlib import Path
from farm.mysql_store import Store,DEFAULT_CONFIG,ENDPOINTS,utcnow


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,default=DEFAULT_CONFIG)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init')
    q=sub.add_parser('import-curl',aliases=['import-accounts']);q.add_argument('files',type=Path,nargs='+');q.add_argument('--proxy',default='http://127.0.0.1:7897');q.add_argument('--front-proxy',help='本地前置代理，例如 http://127.0.0.1:7897');q.add_argument('--verify',action='store_true',help='verify accountInfo once when its template exists');q.add_argument('--refresh-ipfoxy',action='store_true')
    q.add_argument('--environment',choices=('test','production'),default='test');q.add_argument('--tag',action='append')
    q=sub.add_parser('import-tasks');q.add_argument('file',type=Path);q.add_argument('--label',default='店铺采集任务')
    q=sub.add_parser('status');q.add_argument('--out',type=Path)
    q=sub.add_parser('run');q.add_argument('--run-id',type=int,required=True);q.add_argument('--max-requests',type=int,default=1);q.add_argument('--account-id',type=int);q.add_argument('--endpoint',action='append',choices=ENDPOINTS);q.add_argument('--delay',type=float,default=4)
    q.add_argument('--environment',choices=('test','production'),default='test');q.add_argument('--accounts',help='IDs or ranges: 1,3,5-9');q.add_argument('--tag',action='append');q.add_argument('--preview',action='store_true')
    q=sub.add_parser('profile');q.add_argument('--accounts',required=True);q.add_argument('--environment',choices=('test','production'),required=True);q.add_argument('--tag',action='append',default=[])
    q=sub.add_parser('budget');q.add_argument('--account-id',type=int,required=True);q.add_argument('--endpoint',required=True,choices=ENDPOINTS);q.add_argument('--work-limit',type=int,required=True);q.add_argument('--hard-limit',type=int,required=True)
    q=sub.add_parser('probe');q.add_argument('--account-id',type=int,required=True);q.add_argument('--endpoint',required=True,choices=ENDPOINTS);q.add_argument('--shop-job-id',type=int)
    q=sub.add_parser('export');q.add_argument('--run-id',type=int,required=True);q.add_argument('--out',type=Path,required=True)
    for command in ('delete-accounts','delete-runs'):
        q=sub.add_parser(command);q.add_argument('--ids',required=True)
    args=p.parse_args();store=Store(args.config)
    if args.command=='init':store.setup();result={'database':'keeta','schema_version':4}
    elif args.command in ('import-curl','import-accounts'):
        from farm.mysql_import import import_curls
        texts=[(path.stem,path.read_text(encoding='utf-8-sig')) for path in args.files]
        result=import_curls(store,texts,args.proxy,args.front_proxy,refresh_ipfoxy=args.refresh_ipfoxy)
        from farm.mysql_selection import set_profile
        for item in result:
            if item.get('account_id'):
                aid=item['account_id'];set_profile(store,[aid],args.environment,args.tag or [])
                if args.verify:
                    from farm.mysql_worker import Worker
                    item['verification']=Worker(store).probe(aid,'accountInfo')
    elif args.command=='delete-accounts':
        from farm.mysql_admin import delete_accounts
        result=delete_accounts(store,args.ids)
    elif args.command=='delete-runs':
        from farm.mysql_admin import delete_runs
        result=delete_runs(store,args.ids)
    elif args.command=='import-tasks':
        from farm.mysql_import import import_tasks
        result=import_tasks(store,args.file,args.label)
    elif args.command=='status':
        result={'accounts':store.rows('SELECT * FROM account_dashboard ORDER BY id'),
                'daily':store.rows('SELECT * FROM daily_account_requests ORDER BY business_date,account_id,endpoint,origin'),
                'queue':store.rows('SELECT j.run_id,t.endpoint,t.state,COUNT(*) n FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id GROUP BY j.run_id,t.endpoint,t.state')}
        if args.out:
            from farm.mysql_export import export_status
            result['export']=export_status(store,args.out)
    elif args.command=='budget':
        if not 0<=args.work_limit<=args.hard_limit:p.error('require 0 <= work-limit <= hard-limit')
        with store.transaction() as c:
            c.execute('UPDATE budget_policies SET work_limit=%s,hard_limit=%s WHERE account_id=%s AND endpoint=%s',(args.work_limit,args.hard_limit,args.account_id,args.endpoint))
            if not c.rowcount:
                c.execute('SELECT account_id FROM budget_policies WHERE account_id=%s AND endpoint=%s',(args.account_id,args.endpoint))
                if not c.fetchone():raise ValueError('unknown account policy')
        result={'account_id':args.account_id,'endpoint':args.endpoint,'work_limit':args.work_limit,'hard_limit':args.hard_limit}
    elif args.command=='run':
        if args.delay<0:p.error('delay must be nonnegative')
        from farm.mysql_worker import Worker
        from farm.mysql_selection import parse_ids,select_accounts
        ids=parse_ids(args.accounts)
        if args.account_id is not None:ids=[args.account_id] if ids is None or args.account_id in ids else []
        selected=select_accounts(store,args.environment,ids,args.tag)
        if args.preview:result={'accounts':selected}
        else:result=Worker(store).run(args.run_id,args.max_requests,None,args.endpoint,args.delay,environment=args.environment,account_ids=[a['id'] for a in selected],tags=args.tag)
    elif args.command=='profile':
        from farm.mysql_selection import set_profile
        result=set_profile(store,args.accounts,args.environment,args.tag)
    elif args.command=='probe':
        from farm.mysql_worker import Worker
        result=Worker(store).probe(args.account_id,args.endpoint,args.shop_job_id)
    elif args.command=='export':
        from farm.mysql_export import export_run
        result=export_run(store,args.run_id,args.out)
    print(json.dumps(result,ensure_ascii=False,default=str,indent=2))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Never print a DB DSN, raw curl, request headers, or exception URL.
        print(json.dumps({'error_type':type(exc).__name__,'error_code':exc.args[0] if exc.args and isinstance(exc.args[0],int) else None}))
        raise SystemExit(1)
