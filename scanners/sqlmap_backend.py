

import os
import sys
import shutil
import asyncio
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path
import platform

from core.debug_logger import logger
#https://bugs.python.org/issue21808
#https://stackoverflow.com/questions/57131654/using-utf-8-encoding-chcp-65001-in-command-prompt-windows-powershell-window
 
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    os.environ['PYTHONIOENCODING'] = 'utf-8:replace'
    os.environ['PYTHONUTF8'] = '1'
    # Set console to UTF-8
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleCP(65001)
    kernel32.SetConsoleOutputCP(65001)


class SQLMapBackend:
    def __init__(self, backend_type: str = "sqlmap.py"):
        self.backend_type = backend_type
        self.sqlmap_path = self._find_sqlmap()
        self.api_url = "http://127.0.0.1:8775"
        self.supported_options = self._get_supported_options()
        logger.info("SQLMAP", f"Backend initialized: {backend_type}")

    def _find_sqlmap(self) -> str:
        # Find sqlmap installation 
        # Get the directory where the current script is located
        script_dir = Path(__file__).parent.resolve()
        # Also check current working directory as fallback
        cwd = Path.cwd()
        
        candidates = [
            "sqlmap.py",
            str(Path.home() / "sqlmap" / "sqlmap.py"),
            str(Path.home() / "sqlmap-dev" / "sqlmap.py"),
            shutil.which("sqlmap") or "",
            r"C:\Python312\Scripts\sqlmap.py",
            r"C:\Python311\Scripts\sqlmap.py",
            r"C:\Python310\Scripts\sqlmap.py",
            r"C:\Python314\Scripts\sqlmap.py",
            "/usr/local/bin/sqlmap",
            "/usr/bin/sqlmap",
            # Check in script directory/sqlmap/sqlmap.py
            str(script_dir / "sqlmap" / "sqlmap.py"),
            # Check in script directory/sqlmap.py
            str(script_dir / "sqlmap.py"),
            # Check in current working directory/sqlmap/sqlmap.py
            str(cwd / "sqlmap" / "sqlmap.py"),
            str(cwd / "sqlmap.py"),
        ]
        for p in candidates:
            if p and Path(p).expanduser().exists():
                return str(Path(p).expanduser())
        return "sqlmap.py"

    def _get_supported_options(self) -> Dict[str, Dict]:
        #Get supported options INCLUDING THREADs
        return {
            'url': {'type': 'string', 'flag': '-u', 'required': True},
            'data': {'type': 'string', 'flag': '--data'},
            'cookie': {'type': 'string', 'flag': '--cookie'},
            'headers': {'type': 'string', 'flag': '--header'},
            'method': {'type': 'string', 'flag': '--method'},
            'level': {'type': 'int', 'flag': '--level'},
            'risk': {'type': 'int', 'flag': '--risk'},
            'technique': {'type': 'string', 'flag': '--technique'},
            'tamper': {'type': 'string', 'flag': '--tamper'},
            'delay': {'type': 'int', 'flag': '--delay'},
            'timeout': {'type': 'int', 'flag': '--timeout'},
            'retries': {'type': 'int', 'flag': '--retries'},
            'threads': {'type': 'int', 'flag': '--threads'},  # ENABLED or DISABLE it
            'dbms': {'type': 'string', 'flag': '--dbms'},
            'dbs': {'type': 'bool', 'flag': '--dbs'},
            'tables': {'type': 'bool', 'flag': '--tables'},
            'columns': {'type': 'bool', 'flag': '--columns'},
            'dump': {'type': 'bool', 'flag': '--dump'},
            'dump_all': {'type': 'bool', 'flag': '--dump-all'},
            'db': {'type': 'string', 'flag': '-D'},
            'table': {'type': 'string', 'flag': '-T'},
            'column': {'type': 'string', 'flag': '-C'},
            'start': {'type': 'int', 'flag': '--start'},
            'stop': {'type': 'int', 'flag': '--stop'},
            'tor': {'type': 'bool', 'flag': '--tor'},
            'random_agent': {'type': 'bool', 'flag': '--random-agent'},
            'batch': {'type': 'bool', 'flag': '--batch'},
            'flush_session': {'type': 'bool', 'flag': '--flush-session'},
            'time_sec': {'type': 'int', 'flag': '--time-sec'},
        }

    def build_command(self, options: Dict[str, Any], phase: str = 'detection') -> List[str]:
        #Build SQLMap command for execute
        cmd = [
            sys.executable, self.sqlmap_path,
            "-u", options.get('url', ''),
            "--batch",
        ]

        if not options.get('user_agent') and options.get('random_agent') is not False:
            cmd.append("--random-agent")

        # Process options with INCLUDING threads now !!
        for key, value in options.items():
            if key in ['url'] or value is None or value is False:
                continue
            if key in self.supported_options:
                opt_def = self.supported_options[key]
                flag = opt_def['flag']
                opt_type = opt_def['type']
                if opt_type == 'bool' and value is True:
                    cmd.append(flag)
                elif opt_type == 'int' and value is not None:
                    cmd.extend([flag, str(value)])
                elif opt_type == 'string' and value:
                    cmd.extend([flag, str(value)])

        # Handle headers/cookies
        if options.get('headers'):
            headers = options['headers']
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd.extend(["--header", f"{k}: {v}"])
            elif isinstance(headers, str):
                for line in headers.split('\n'):
                    if line.strip():
                        cmd.extend(["--header", line.strip()])

        if options.get('cookies'):
            cmd.extend(["--cookie", options['cookies']])
        elif options.get('cookie'):
            cmd.extend(["--cookie", options['cookie']])

        # === DEFAULT OPTIMIZATIONS ===
        if '--threads' not in ' '.join(cmd):
            cmd.extend(['--threads', '5'])
        if '--timeout' not in ' '.join(cmd):
            cmd.extend(['--timeout', '30'])
        if '--retries' not in ' '.join(cmd):
            cmd.extend(['--retries', '2'])

        # Phase-specific
        if phase == 'detection':
            if '--level' not in ' '.join(cmd):
                cmd.extend(['--level', '1'])
            if '--risk' not in ' '.join(cmd):
                cmd.extend(['--risk', '1'])
        elif phase == 'bypass':
            if '--level' not in ' '.join(cmd):
                cmd.extend(['--level', '2'])
            if '--risk' not in ' '.join(cmd):
                cmd.extend(['--risk', '2'])
        elif phase == 'dump':
            if '--time-sec' not in ' '.join(cmd):
                cmd.extend(['--time-sec', '3'])
            if '--start' not in ' '.join(cmd):
                cmd.extend(['--start', '1'])
            if '--stop' not in ' '.join(cmd):
                cmd.extend(['--stop', '50'])

        return cmd

    async def execute(self, cmd: List[str], cycle: int) -> List[str]:
        #Execute with ROBUST encoding handling 
        logs = []
        try:
            logger.debug("SQLMAP", f"Cycle {cycle}: {' '.join(cmd[:10])}...")

            if not Path(cmd[1]).exists():
                return [f"ERROR: SQLMap not found at {cmd[1]}"]

            is_dump = '--dump' in cmd
            timeout = 120 if is_dump else 60

            # CRITICAL: Create environment with UTF-8 forced
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8:replace'
            env['PYTHONUTF8'] = '1'

            creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            #https://stackoverflow.com/questions/79828378/monitor-asyncio-create-subprocess-exec-pipes-for-errors
            # Use asyncio subprocess (NO THREADING ISSUES)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=env,
                creationflags=creationflags
            )

            stdout_data = []
            stderr_data = []
            last_output = asyncio.get_event_loop().time()
            progress_timeout = 30

            async def read_stream(stream, storage):
                nonlocal last_output
                while True:
                    try:
                        # Read bytes in chunks
                        chunk = await asyncio.wait_for(stream.read(8192), timeout=2.0)
                        if not chunk:
                            break

                        # CRITICAL: Decode with replacement for invalid chars
                        try:
                            text = chunk.decode('utf-8', errors='replace')
                        except:
                            text = chunk.decode('cp1252', errors='replace')

                        lines = text.splitlines()
                        for line in lines:
                            if line:
                                storage.append(line)
                                last_output = asyncio.get_event_loop().time()
                                if any(k in line.lower() for k in ['error', 'warning', 'found', 'injection', 'vulnerable']):
                                    logger.debug("SQLMAP", line[:80])
                    except asyncio.TimeoutError:
                        if proc.returncode is not None:
                            break
                        if asyncio.get_event_loop().time() - last_output > progress_timeout:
                            logger.warning("SQLMAP", f"No output for {progress_timeout}s")
                            break
                        continue
                    except Exception as e:
                        logger.debug("SQLMAP", f"Read error: {e}")
                        break

            # Execute with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_stream(proc.stdout, stdout_data),
                        read_stream(proc.stderr, stderr_data)
                    ),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning("SQLMAP", f"Timeout after {timeout}s")

            # Cleanup process
            if proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except:
                    proc.kill()
                    await proc.wait()

            logs.extend(stdout_data)
            for err in stderr_data:
                logs.append(f"STDERR: {err}")

            if not logs:
                logs.append("WARNING: No output from sqlmap")

        except Exception as e:
            logger.error("SQLMAP", f"Error: {e}")
            logs.append(f"ERROR: {e}")
            import traceback
            logs.extend(traceback.format_exc().splitlines())

        return logs