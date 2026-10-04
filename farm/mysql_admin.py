"""Delete database accounts or batches without losing unrelated results/budgets."""
from contextlib import contextmanager

from farm.mysql_selection import parse_ids
from farm.mysql_store import unpack_json


class DeletionConflict(ValueError):
    pass


def required_ids(values):
    ids=parse_ids(values)
    if not ids:raise ValueError('必须明确选择要删除的 ID')
    return ids


def marks(values):
    return ','.join(['%s']*len(values))


@contextmanager
def locked_accounts(store, ids):
    # Match the worker's account lock, including non-panel CLI/probe requests.
    con=store.connect();locks=[]
    try:
        with con.cursor() as c:
            for aid in ids:
                name='keeta:account:'+str(aid)
                c.execute('SELECT GET_LOCK(%s,0) locked',(name,))
                if c.fetchone()['locked']!=1:
                    raise DeletionConflict(f'账号 #{aid} 正在执行请求，请停止后重试')
                locks.append(name)
        yield
    finally:
        try:
            with con.cursor() as c:
                for name in reversed(locks):c.execute('SELECT RELEASE_LOCK(%s)',(name,))
        finally:con.close()


def delete_accounts(store, account_ids):
    ids=required_ids(account_ids);params=marks(ids);selected=set(ids)
    with locked_accounts(store,ids),store.transaction() as c:
        c.execute(f'SELECT id FROM accounts WHERE id IN ({params}) ORDER BY id FOR UPDATE',ids)
        if {r['id'] for r in c.fetchall()}!=selected:raise ValueError('存在未知账号')
        c.execute("SELECT id,account_ids FROM executions WHERE state IN ('queued','running') FOR UPDATE")
        for row in c.fetchall():
            if selected.intersection(unpack_json(row['account_ids'])):
                raise DeletionConflict(f"请先停止运行 #{row['id']}，再删除账号")
        c.execute(f"SELECT id FROM request_attempts WHERE account_id IN ({params}) AND state IN ('reserved','sent') LIMIT 1",ids)
        if c.fetchone():raise DeletionConflict('账号还有未结算请求，请先恢复或结束任务')
        # Results remain exportable; only remove their live account foreign key.
        c.execute(f'UPDATE task_results SET account_id=NULL WHERE account_id IN ({params})',ids)
        results=c.rowcount
        c.execute(f'DELETE FROM request_attempts WHERE account_id IN ({params})',ids)
        c.execute(f'DELETE c FROM capabilities c JOIN account_sessions s ON s.id=c.session_id WHERE s.account_id IN ({params})',ids)
        for table in ('experiment_members','daily_usage','budget_policies','account_tags','account_profiles','account_sessions'):
            c.execute(f'DELETE FROM {table} WHERE account_id IN ({params})',ids)
        c.execute(f'DELETE FROM accounts WHERE id IN ({params})',ids)
    return {'deleted_accounts':ids,'preserved_results':results}


def delete_runs(store, run_ids):
    ids=required_ids(run_ids);params=marks(ids)
    with store.transaction() as c:
        c.execute(f'SELECT id FROM collection_runs WHERE id IN ({params}) ORDER BY id FOR UPDATE',ids)
        if {r['id'] for r in c.fetchall()}!=set(ids):raise ValueError('存在未知批次')
        c.execute(f'SELECT id,state FROM executions WHERE run_id IN ({params}) FOR UPDATE',ids)
        executions=c.fetchall()
        if any(r['state'] in ('queued','running') for r in executions):
            raise DeletionConflict('请先停止批次的排队或运行任务，再删除批次')
        c.execute(f'''SELECT t.id,t.state FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id
                      WHERE j.run_id IN ({params}) FOR UPDATE''',ids)
        tasks=c.fetchall()
        if any(r['state']=='leased' for r in tasks):
            raise DeletionConflict('批次还有已领取的请求，请等待结束或恢复租约后重试')
        # Requests really happened: deleting a batch must not refund usage or
        # remove the evidence used for daily statistics. task_id is nullable.
        c.execute(f'''UPDATE request_attempts r JOIN tasks t ON t.id=r.task_id
                      JOIN shop_jobs j ON j.id=t.shop_job_id
                      SET r.task_id=NULL WHERE j.run_id IN ({params})''',ids)
        c.execute(f'DELETE r FROM task_results r JOIN shop_jobs j ON j.id=r.shop_job_id WHERE j.run_id IN ({params})',ids)
        deleted_results=c.rowcount
        c.execute(f'DELETE t FROM tasks t JOIN shop_jobs j ON j.id=t.shop_job_id WHERE j.run_id IN ({params})',ids)
        c.execute(f'DELETE FROM shop_jobs WHERE run_id IN ({params})',ids)
        c.execute(f'DELETE FROM executions WHERE run_id IN ({params})',ids)
        c.execute(f'DELETE FROM collection_runs WHERE id IN ({params})',ids)
    return {'deleted_runs':ids,'deleted_tasks':len(tasks),'deleted_results':deleted_results,
            'deleted_execution_ids':[r['id'] for r in executions]}
