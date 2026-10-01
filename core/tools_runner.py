"""ForenZX Mobile DFIR Tool Runner: ALEAPP, iLEAPP, and Andriller.

Provides secure, structured execution of open-source mobile forensic triage tools
with real-time log streaming, process isolation, and automated report indexing.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from core.db import db
from core.utils.logger import get_logger

logger = get_logger("forenzx.tools")

BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR / "tools"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Find python interpreter
def _get_python_executable() -> str:
    # 1. Prefer local .venv312 if present
    venv312_py = BASE_DIR / ".venv312" / "Scripts" / "python.exe"
    if venv312_py.exists():
        return str(venv312_py)
    # 2. Check standard .venv
    venv_win = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    if venv_win.exists():
        return str(venv_win)
    venv_nix = BASE_DIR / ".venv" / "bin" / "python"
    if venv_nix.exists():
        return str(venv_nix)
    # 3. Fallback to current runtime
    return sys.executable


class ToolTask:
    def __init__(
        self,
        task_id: str,
        tool: str,
        action: str,
        command: List[str],
        output_dir: Optional[Path] = None,
    ):
        self.task_id = task_id
        self.tool = tool
        self.action = action
        self.command = command
        self.output_dir = output_dir
        self.status = "queued"  # queued, running, completed, failed
        self.exit_code: Optional[int] = None
        self.started_at: str = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.logs: List[str] = []
        self.report_path: Optional[str] = None
        self.report_url: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tool": self.tool,
            "action": self.action,
            "command": " ".join(self.command),
            "status": self.status,
            "exit_code": self.exit_code,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "report_path": self.report_path,
            "report_url": self.report_url,
            "log_lines": len(self.logs),
            "recent_logs": self.logs[-50:],
        }


class ToolsRunner:
    def __init__(self):
        self._tasks: Dict[str, ToolTask] = {}
        self._lock = threading.Lock()

    def get_tool_inventory(self) -> Dict[str, Any]:
        aleapp_path = TOOLS_DIR / "ALEAPP" / "aleapp.py"
        ileapp_path = TOOLS_DIR / "iLEAPP" / "ileapp.py"
        andriller_gui = TOOLS_DIR / "andriller" / "andriller-gui.py"
        andriller_pkg = TOOLS_DIR / "andriller" / "andriller"
        adb_path = shutil.which("adb")

        # Scan for existing reports
        reports = self.list_reports()

        return {
            "python_executable": _get_python_executable(),
            "tools": {
                "aleapp": {
                    "installed": aleapp_path.exists(),
                    "path": str(aleapp_path),
                    "supported_types": ["fs", "tar", "zip", "gz", "raw"],
                    "description": "Android Logs Events And Protobuf Parser",
                },
                "ileapp": {
                    "installed": ileapp_path.exists(),
                    "path": str(ileapp_path),
                    "supported_types": ["fs", "tar", "zip", "gz", "itunes", "file", "raw"],
                    "description": "iOS Logs Events And Plists Parser",
                },
                "andriller": {
                    "installed": andriller_gui.exists() or andriller_pkg.exists(),
                    "path": str(andriller_gui),
                    "adb_available": adb_path is not None,
                    "adb_path": adb_path,
                    "description": "Android Forensic Triage & Decoders (Live USB/ADB)",
                },
            },
            "recent_reports": reports[:10],
            "active_tasks": [t.to_dict() for t in self._tasks.values() if t.status == "running"],
        }

    def list_reports(self) -> List[Dict[str, Any]]:
        results = []
        if not REPORTS_DIR.exists():
            return results

        # Find all index.html files inside REPORTS_DIR subdirectories
        for p in REPORTS_DIR.glob("**/index.html"):
            rel = p.relative_to(REPORTS_DIR)
            folder_name = rel.parts[0] if rel.parts else p.parent.name
            stat = p.stat()
            results.append({
                "name": folder_name,
                "relative_path": str(rel).replace("\\", "/"),
                "full_path": str(p),
                "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "size_bytes": stat.st_size,
                "url": f"/reports/{str(rel).replace(chr(92), '/')}",
            })
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results

    def get_task(self, task_id: str) -> Optional[ToolTask]:
        return self._tasks.get(task_id)

    def list_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        sorted_tasks = sorted(self._tasks.values(), key=lambda t: t.started_at, reverse=True)
        return [t.to_dict() for t in sorted_tasks[:limit]]

    def run_aleapp(
        self,
        input_type: str,
        input_path: str,
        output_path: Optional[str] = None,
        custom_folder: Optional[str] = None,
        user_id: str = "admin",
    ) -> ToolTask:
        py_exe = _get_python_executable()
        script = TOOLS_DIR / "ALEAPP" / "aleapp.py"
        if not script.exists():
            raise FileNotFoundError(f"ALEAPP script not found at {script}")

        # Resolve input path
        resolved_input = Path(input_path)
        if not resolved_input.is_absolute():
            resolved_input = (BASE_DIR / input_path).resolve()
        if not resolved_input.exists():
            for alt_prefix in [Path("/data"), Path("/data/vault"), Path("/app/vault"), BASE_DIR / "vault"]:
                candidate = (alt_prefix / Path(input_path).name).resolve()
                if candidate.exists():
                    resolved_input = candidate
                    break
        if not resolved_input.exists():
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        valid_types = {"fs", "tar", "zip", "gz", "raw"}
        if input_type not in valid_types:
            raise ValueError(f"Invalid input type '{input_type}'. Must be one of {valid_types}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_out = Path(output_path) if output_path else (REPORTS_DIR / f"aleapp_{timestamp}")
        if not target_out.is_absolute():
            target_out = (BASE_DIR / target_out).resolve()
        target_out.mkdir(parents=True, exist_ok=True)

        cmd = [
            py_exe,
            str(script),
            "-t",
            input_type,
            "-i",
            str(resolved_input),
            "-o",
            str(target_out),
        ]
        if custom_folder:
            cmd.extend(["--custom_output_folder", custom_folder])

        task_id = f"aleapp_{timestamp}_{uuid4().hex[:6]}"
        task = ToolTask(task_id, "aleapp", "analyze", cmd, target_out)
        self._register_and_spawn(task, user_id)
        return task

    def run_ileapp(
        self,
        input_type: str,
        input_path: str,
        output_path: Optional[str] = None,
        custom_folder: Optional[str] = None,
        user_id: str = "admin",
    ) -> ToolTask:
        py_exe = _get_python_executable()
        script = TOOLS_DIR / "iLEAPP" / "ileapp.py"
        if not script.exists():
            raise FileNotFoundError(f"iLEAPP script not found at {script}")

        # Resolve input path
        resolved_input = Path(input_path)
        if not resolved_input.is_absolute():
            resolved_input = (BASE_DIR / input_path).resolve()
        if not resolved_input.exists():
            for alt_prefix in [Path("/data"), Path("/data/vault"), Path("/app/vault"), BASE_DIR / "vault"]:
                candidate = (alt_prefix / Path(input_path).name).resolve()
                if candidate.exists():
                    resolved_input = candidate
                    break
        if not resolved_input.exists():
            raise FileNotFoundError(f"Input path does not exist: {input_path}")

        valid_types = {"fs", "tar", "zip", "gz", "itunes", "file", "raw"}
        if input_type not in valid_types:
            raise ValueError(f"Invalid input type '{input_type}'. Must be one of {valid_types}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_out = Path(output_path) if output_path else (REPORTS_DIR / f"ileapp_{timestamp}")
        if not target_out.is_absolute():
            target_out = (BASE_DIR / target_out).resolve()
        target_out.mkdir(parents=True, exist_ok=True)

        cmd = [
            py_exe,
            str(script),
            "-t",
            input_type,
            "-i",
            str(resolved_input),
            "-o",
            str(target_out),
        ]
        if custom_folder:
            cmd.extend(["--custom_output_folder", custom_folder])

        task_id = f"ileapp_{timestamp}_{uuid4().hex[:6]}"
        task = ToolTask(task_id, "ileapp", "analyze", cmd, target_out)
        self._register_and_spawn(task, user_id)
        return task

    def run_andriller_gui(self, user_id: str = "admin") -> ToolTask:
        py_exe = _get_python_executable()
        script = TOOLS_DIR / "andriller" / "andriller-gui.py"
        if not script.exists():
            raise FileNotFoundError(f"Andriller GUI script not found at {script}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cmd = [py_exe, str(script)]
        task_id = f"andriller_gui_{timestamp}_{uuid4().hex[:6]}"
        task = ToolTask(task_id, "andriller", "gui", cmd, None)
        self._register_and_spawn(task, user_id, is_gui=True)
        return task

    def run_andriller_adb_triage(
        self, output_path: Optional[str] = None, user_id: str = "admin"
    ) -> ToolTask:
        py_exe = _get_python_executable()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_out = Path(output_path) if output_path else (REPORTS_DIR / f"andriller_{timestamp}")
        target_out.mkdir(parents=True, exist_ok=True)

        # Python inline script to run ADB device probe & triage
        runner_code = (
            "import sys, os, json\n"
            f"sys.path.insert(0, r'{TOOLS_DIR / 'andriller'}')\n"
            "from andriller import adb_conn, utils\n"
            "adb = adb_conn.ADBConn()\n"
            "print('[+] Checking connected ADB devices...')\n"
            "serial, status = adb.device()\n"
            "print(f'[+] Connected device: {serial} (status: {status})')\n"
            "info = {'serial': serial, 'status': status}\n"
            "try:\n"
            "    props = adb.adb_out('getprop').splitlines()\n"
            "    for line in props[:25]:\n"
            "        print('   ', line.strip())\n"
            "except Exception as e:\n"
            "    print(f'[-] Error querying props: {e}')\n"
            f"report_file = os.path.join(r'{target_out}', 'adb_triage.json')\n"
            "with open(report_file, 'w', encoding='utf-8') as f:\n"
            "    json.dump(info, f, indent=2)\n"
            "print(f'[+] Triage summary saved to {report_file}')\n"
        )

        cmd = [py_exe, "-c", runner_code]
        task_id = f"andriller_triage_{timestamp}_{uuid4().hex[:6]}"
        task = ToolTask(task_id, "andriller", "adb_triage", cmd, target_out)
        self._register_and_spawn(task, user_id)
        return task

    def _register_and_spawn(self, task: ToolTask, user_id: str, is_gui: bool = False):
        with self._lock:
            self._tasks[task.task_id] = task

        db.event(
            user_id,
            "TOOL_LAUNCH",
            task.task_id,
            True,
            {"tool": task.tool, "action": task.action, "cmd": " ".join(task.command)},
        )

        def _worker():
            task.status = "running"
            task.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Started: {' '.join(task.command)}")
            try:
                # Set working directory to the tool's directory so relative assets work
                tool_sub = TOOLS_DIR / (
                    "ALEAPP" if task.tool == "aleapp" else ("iLEAPP" if task.tool == "ileapp" else "andriller")
                )
                cwd = tool_sub if tool_sub.exists() else BASE_DIR

                proc = subprocess.Popen(
                    task.command,
                    cwd=str(cwd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )
                task.process = proc

                if proc.stdout:
                    for line in iter(proc.stdout.readline, ""):
                        clean_line = line.rstrip()
                        if clean_line:
                            task.logs.append(clean_line)
                    proc.stdout.close()

                proc.wait()
                task.exit_code = proc.returncode
                task.status = "completed" if proc.returncode == 0 else "failed"
                task.completed_at = datetime.now(timezone.utc).isoformat()
                task.logs.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Process finished with exit code {proc.returncode}"
                )

                # Check if report was produced
                if task.output_dir and task.output_dir.exists():
                    index_files = list(task.output_dir.glob("**/index.html"))
                    if index_files:
                        chosen = index_files[0]
                        task.report_path = str(chosen)
                        rel = chosen.relative_to(REPORTS_DIR)
                        task.report_url = f"/reports/{str(rel).replace(chr(92), '/')}"
                        task.logs.append(f"[+] Report generated: {task.report_url}")

                db.event(
                    user_id,
                    "TOOL_FINISHED",
                    task.task_id,
                    task.status == "completed",
                    {
                        "exit_code": task.exit_code,
                        "report_url": task.report_url,
                        "status": task.status,
                    },
                )
            except Exception as exc:
                task.status = "failed"
                task.completed_at = datetime.now(timezone.utc).isoformat()
                task.logs.append(f"[-] Execution error: {exc}")
                logger.error(f"Error executing tool {task.task_id}: {exc}")
                db.event(user_id, "TOOL_ERROR", task.task_id, False, {"error": str(exc)})

        threading.Thread(target=_worker, daemon=True).start()


tools_runner = ToolsRunner()
