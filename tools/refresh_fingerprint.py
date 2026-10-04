#!/usr/bin/env python3
"""One-report a7 maintenance; default is offline preflight."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from farm.fingerprint_maintenance import main
if __name__=='__main__':raise SystemExit(main())
