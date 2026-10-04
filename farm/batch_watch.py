"""Observe one worker through OS exit; record crashes without automatic restart."""
from datetime import datetime,timezone
import argparse,fcntl,json,os,signal,sqlite3,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
from farm.local_batch import atomic_json

def utc():return datetime.now(timezone.utc).isoformat()

def record_exit(folder,output,code,started,pid):
    # The child has been reaped. Acquire its lock so a different worker cannot
    # be overwritten, and leave all tasks, usage, and cooldowns untouched.
    with (folder/'runner.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with sqlite3.connect(folder/'local.sqlite3') as db:
            state=db.execute("SELECT value FROM meta WHERE key='state'").fetchone()[0]
            if state not in ('complete','blocked','stopped'):
                reason='worker_process_exit_'+str(code)
                db.execute("UPDATE meta SET value='blocked' WHERE key='state'")
                path=output/'progress.json'
                progress=json.loads(path.read_text()) if path.exists() else {}
                progress.update(state='blocked',stop_reason=reason,waiting=None,active={},updated_at=utc())
                atomic_json(path,progress)
                state='blocked'
        record=dict(started_at=started,ended_at=utc(),worker_pid=pid,exit_code=code,state=state)
        atomic_json(folder/'supervisor-status.json',record)
        with (folder/'worker-sessions.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
        return record

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--resume',action='store_true')
    a=p.parse_args();folder=a.folder.resolve()
    config=json.loads((folder/'manifest.json').read_text());output=Path(config['output'])
    with (folder/'supervisor.lock').open('a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with (folder/'runner.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        started=utc()
        with (folder/'runner.log').open('ab') as log:
            child=subprocess.Popen([sys.executable,'-u','-X','faulthandler','-m','farm.batch_run',str(folder)]+(['--resume'] if a.resume else []),
                cwd=ROOT,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        def stop(*_):
            if child.poll() is None:child.terminate()
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        atomic_json(folder/'supervisor-status.json',dict(state='running',started_at=started,worker_pid=child.pid,supervisor_pid=os.getpid()))
        code=child.wait()
        print(json.dumps(record_exit(folder,output,code,started,child.pid)),flush=True)

if __name__=='__main__':main()
