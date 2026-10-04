"""Shared account selection for the panel and the worker; filters intersect."""
import re
from farm.storage.mysql import utcnow

ENVIRONMENTS = ('test', 'production')


def parse_ids(value):
    if value is None or value == '':
        return None
    if isinstance(value, list):
        if not value:
            return []
        value = ','.join(map(str, value))
    ids = set()
    for part in str(value).split(','):
        match = re.fullmatch(r'\s*([1-9]\d*)(?:\s*-\s*([1-9]\d*))?\s*', part)
        if not match:
            raise ValueError('账号范围格式应为 1,3,5-9')
        lo = int(match[1]); hi = int(match[2] or lo)
        if hi < lo or hi - lo > 10000 or hi > 2**63 - 1:
            raise ValueError('账号范围无效或过大')
        ids.update(range(lo, hi + 1))
    if len(ids) > 10000:
        raise ValueError('单次最多选择 10000 个账号')
    return sorted(ids)


def parse_tags(value):
    if isinstance(value, str):
        value = value.split(',')
    tags = sorted(set(str(v).strip().lower() for v in value or [] if str(v).strip()))
    if len(tags) > 32 or any(not re.fullmatch(r'[\w.:-]{1,64}', tag) for tag in tags):
        raise ValueError('标签仅支持文字、数字、下划线、点、冒号和短横线，长度不超过 64')
    return tags


def selection_clause(environment=None, account_ids=None, tags=None, alias='a'):
    clauses = []; args = []
    if environment is not None:
        if environment not in ENVIRONMENTS:
            raise ValueError('运行环境必须是 test 或 production')
        clauses.append(f'EXISTS (SELECT 1 FROM account_profiles ap WHERE ap.account_id={alias}.id AND ap.environment=%s)')
        args.append(environment)
    if account_ids is not None:
        if not account_ids:
            clauses.append('FALSE')
        else:
            clauses.append(f'{alias}.id IN ({",".join(["%s"]*len(account_ids))})')
            args.extend(account_ids)
    tags = parse_tags(tags)
    if tags:
        clauses.append(f'EXISTS (SELECT 1 FROM account_tags atg WHERE atg.account_id={alias}.id AND atg.tag IN ({",".join(["%s"]*len(tags))}))')
        args.extend(tags)
    return (' AND ' + ' AND '.join(clauses) if clauses else ''), args


def select_accounts(store, environment, account_ids=None, tags=None):
    clause, args = selection_clause(environment, parse_ids(account_ids), tags)
    return store.rows('SELECT a.id,a.label,a.paused,a.identity_status FROM accounts a WHERE 1=1'+clause+' ORDER BY a.id', args)


def set_profile(store, account_ids, environment, tags, paused=None):
    ids = parse_ids(account_ids)
    if not ids or environment not in ENVIRONMENTS:
        raise ValueError('请选择账号和环境')
    tags = parse_tags(tags)
    with store.transaction() as c:
        for aid in ids:
            c.execute('SELECT id FROM accounts WHERE id=%s FOR UPDATE', (aid,))
            if not c.fetchone():
                raise ValueError('存在未知账号')
            c.execute('INSERT INTO account_profiles(account_id,environment,updated_at) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE environment=VALUES(environment),updated_at=VALUES(updated_at)', (aid, environment, utcnow()))
            c.execute('DELETE FROM account_tags WHERE account_id=%s', (aid,))
            if tags:
                c.executemany('INSERT INTO account_tags(account_id,tag) VALUES(%s,%s)', [(aid,t) for t in tags])
            if paused is not None:
                c.execute('UPDATE accounts SET paused=%s WHERE id=%s', (bool(paused),aid))
    return {'account_ids':ids, 'environment':environment, 'tags':tags}
