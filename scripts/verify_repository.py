"""Verify portable source closure and local Markdown links without network access."""
import ast
from pathlib import Path
import re
import sys
from urllib.parse import unquote
ROOT=Path(__file__).resolve().parents[1]


def main():
    errors=[]
    files=[p for p in ROOT.rglob('*') if p.is_file() and not any(x in p.relative_to(ROOT).parts for x in ('.git','.private','.venv','__pycache__','exports'))]
    for p in files:
        if p.suffix=='.py':
            try:
                tree=ast.parse(p.read_text())
                for node in ast.walk(tree):
                    if isinstance(node,ast.Import): names=[n.name for n in node.names]
                    elif isinstance(node,ast.ImportFrom):
                        if node.level:
                            package=list(p.relative_to(ROOT).parts[:-1])
                            base=package[:len(package)-node.level+1]
                            names=['.'.join(base+((node.module or '').split('.') if node.module else []))]
                        else:names=[node.module or '']
                    else:continue
                    for name in names:
                        if name.split('.')[0] not in ('farm','mtgsig','rpc','scripts','tests'):continue
                        target=ROOT.joinpath(*name.split('.'))
                        if not target.with_suffix('.py').exists() and not (target/'__init__.py').exists():
                            errors.append(str(p.relative_to(ROOT))+': missing local import '+name)
            except SyntaxError:errors.append(str(p.relative_to(ROOT))+': syntax error')
        if p.suffix=='.md':
            for target in re.findall(r'\]\(([^)]+)\)',p.read_text()):
                target=target.split('#',1)[0].split(' "',1)[0].strip('<>')
                if not target or '://' in target or target.startswith(('mailto:','/')):continue
                if not (p.parent/unquote(target)).exists():errors.append(str(p.relative_to(ROOT))+': broken local link '+target)
    sys.path.insert(0,str(ROOT))
    for module in ('farm.web.app','farm.collection.prepare','farm.collection.recommendations','farm.delivery.audit','farm.delivery.report','farm.executor','farm.network.service','rpc.server','mtgsig.api'):
        __import__(module)
    for file in (ROOT/'mtgsig').glob('*.py'):
        for node in ast.walk(ast.parse(file.read_text())):
            name=node.module if isinstance(node,ast.ImportFrom) else ''
            names=[n.name for n in node.names] if isinstance(node,ast.Import) else [name or '']
            if any(n.split('.')[0] in ('farm','rpc') for n in names):
                errors.append(file.name+': codec depends on service layer')
    for error in errors:print(error)
    if errors:return 1
    print('Source entrypoints, package imports and Markdown links verified.')
    return 0

if __name__=='__main__':raise SystemExit(main())
