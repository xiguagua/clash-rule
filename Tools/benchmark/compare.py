#!/usr/bin/env python3
"""
Convenience entrypoint forwarding to scripts/compare_benchmark.py
"""
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
target_script = repo_root / "scripts" / "compare_benchmark.py"

if not target_script.is_file():
    sys.exit(f"Error: {target_script} not found.")

import runpy
runpy.run_path(str(target_script), run_name="__main__")
