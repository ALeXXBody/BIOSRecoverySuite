"""Bridge to run ME Analyzer programmatically and extract structured results."""

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from bios_recovery.third_party.mea import MEA_PATH, ensure_data_files, MEA_ROOT


@dataclass
class MEAResult:
    success: bool
    output_json_path: Optional[str] = None
    json_data: Dict[str, Any] = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    messages: List[str] = None

    def __post_init__(self):
        if self.messages is None:
            self.messages = []


def _find_python():
    if getattr(sys, "frozen", False):
        return sys.executable
    return sys.executable


def run_mea_analyzer(input_file: str, output_dir: Optional[str] = None,
                     include_html: bool = False) -> MEAResult:
    if not ensure_data_files():
        return MEAResult(success=False, error="ME Analyzer data files missing")

    if not os.path.exists(input_file):
        return MEAResult(success=False, error=f"Input file not found: {input_file}")

    work_dir = output_dir or tempfile.mkdtemp(prefix="mea_")
    os.makedirs(work_dir, exist_ok=True)

    python_exe = _find_python()
    args = [python_exe, MEA_PATH, input_file, "-skip", "-exit", "-json", "-duc", "-out", work_dir]
    if include_html:
        args.append("-html")

    env = os.environ.copy()
    if getattr(sys, "frozen", False):
        env["PYTHONPATH"] = os.pathsep.join([
            env.get("PYTHONPATH", ""),
            os.path.dirname(sys.executable),
            MEA_ROOT,
        ])
    else:
        env["PYTHONPATH"] = os.pathsep.join([
            env.get("PYTHONPATH", ""),
            os.path.dirname(MEA_ROOT),
        ])

    try:
        proc = subprocess.run(
            args,
            cwd=MEA_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=300,
            text=True,
            encoding="utf-8", errors="replace"
        )
    except subprocess.TimeoutExpired:
        return MEAResult(success=False, error="ME Analyzer timed out (300s)")
    except Exception as e:
        return MEAResult(success=False, error=f"Failed to run ME Analyzer: {e}")

    json_path = os.path.join(work_dir, os.path.basename(input_file) + ".json")
    json_data = None
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
        except Exception:
            json_data = None

    success = proc.returncode == 0 or json_data is not None
    res = MEAResult(
        success=success,
        output_json_path=json_path if os.path.exists(json_path) else None,
        json_data=json_data,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        error="" if success else (f"Return code {proc.returncode}" if proc.returncode != 0 else "No JSON output"),
    )

    if json_data and isinstance(json_data, dict):
        file_key = next((k for k in json_data if k == os.path.basename(input_file) or k == input_file), None)
        if file_key and isinstance(json_data[file_key], dict) and "Messages" in json_data[file_key]:
            try:
                res.messages = list(json_data[file_key]["Messages"])
            except Exception:
                pass

    return res
