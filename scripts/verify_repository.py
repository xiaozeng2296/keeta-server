"""Verify portable source closure and local Markdown links without network access."""
import ast
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote
ROOT=Path(__file__).resolve().parents[1]


def main():
    errors=[]
    files=[p for p in ROOT.rglob('*') if p.is_file() and not any(x in p.relative_to(ROOT).parts for x in ('.git','.private','.venv','__pycache__','exports'))]
    for p in files:
        if p.suffix=='.py':
            try:ast.parse(p.read_text())
            except SyntaxError:errors.append(str(p.relative_to(ROOT))+': syntax error')
        if p.suffix=='.md':
            for target in re.findall(r'\]\(([^)]+)\)',p.read_text()):
                target=target.split('#',1)[0].split(' "',1)[0].strip('<>')
                if not target or '://' in target or target.startswith(('mailto:','/')):continue
                if not (p.parent/unquote(target)).exists():errors.append(str(p.relative_to(ROOT))+': broken local link '+target)
    sys.path.insert(0,str(ROOT))
    from rpc.deploy import RUNTIME_FILES
    for path in RUNTIME_FILES:
        if not (ROOT/path).is_file():errors.append('RPC package missing '+path)
    for module in ('farm.panel','farm.batch_prepare','farm.recommendations','farm.batch_audit','farm.batch_report','farm.executor','farm.proxy_service','keeta_rpc'):
        __import__(module)
    for error in errors:print(error)
    if errors:return 1
    print('Source entrypoints, RPC package files and Markdown links verified.')
    return 0

if __name__=='__main__':raise SystemExit(main())
