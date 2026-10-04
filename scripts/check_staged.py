"""Check staged repository bytes; never print credential matches."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    args=['git','ls-files','--cached','-z'] if '--all' in sys.argv else ['git','diff','--cached','--name-only','-z']
    paths=filter(None,subprocess.check_output(args,cwd=ROOT).decode().split('\0'))
    problems=[];secrets=[]
    config=ROOT/'.private/mysql.json'
    if config.is_file():
        password=json.loads(config.read_text()).get('password')
        if password and password!='CHANGE_ME':secrets.append(password.encode())
    for path in paths:
        parts=Path(path).parts
        if parts[0] in ('.private','exports','workspace','dump','evidence','.venv') or path.endswith(('.key','.sqlite3','.xlsx','.chlsj','.pcap')):
            problems.append((path,'runtime/private artifact'));continue
        result=subprocess.run(['git','show',':'+path],cwd=ROOT,capture_output=True)
        if result.returncode:continue
        raw=result.stdout
        if len(raw)>2*1024*1024:problems.append((path,'oversized source artifact'))
        if re.search(rb'(?<![A-Za-z0-9_-])F\d{6}[A-Za-z0-9_-]{80,}',raw):problems.append((path,'captured account token'))
        if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',raw):problems.append((path,'private key'))
        if re.search(rb'M\.R3_[A-Za-z0-9_.!*-]{40,}|1//[A-Za-z0-9_-]{50,}',raw):problems.append((path,'OAuth credential'))
        if re.search(rb'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}',raw):problems.append((path,'repository credential'))
        if any(secret in raw for secret in secrets):problems.append((path,'configured database password'))
        if re.search(rb'(?i)(?:mysql|mariadb)://[^\s]+:[^\s]+@',raw):problems.append((path,'embedded database DSN'))
    for path,reason in problems:print(path+': '+reason)
    if problems:return 1
    print('Staged bytes passed runtime-file and credential checks.')
    return 0

if __name__=='__main__':raise SystemExit(main())
