"""Run the existing MySQL execution manager separately from the Web process."""
import argparse
from pathlib import Path
import signal
from farm.storage.mysql import Store, DEFAULT_CONFIG
from farm.collection.executions import ExecutionManager


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,default=DEFAULT_CONFIG)
    a=p.parse_args();store=Store(a.config);store.setup()
    manager=ExecutionManager(store)
    def stop(*_):manager.quit.set()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    manager.serve()

if __name__=='__main__':main()
