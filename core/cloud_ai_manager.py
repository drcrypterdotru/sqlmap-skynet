import os
import aiohttp
from typing import Dict, Optional, List
from debug_logger import logger

class CloudAIManager:
    # Manage cloud AI providers with automatic failover 
    
    PROVIDERS = {
        'deepseek': {
            'url': 'https://api.deepseek.com/v1/chat/completions',
            'model': 'deepseek-coder',
            'env_key': 'DEEPSEEK_API_KEY',
            'headers': lambda key: {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
        },
        'kimi': {
            'url': 'https://api.moonshot.cn/v1/chat/completions',
            'model': 'kimi-latest',
            'env_key': 'KIMI_API_KEY',
            'headers': lambda key: {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
        },
        'openai': {
            'url': 'https://api.openai.com/v1/chat/completions',
            'model': 'gpt-4o',
            'env_key': 'OPENAI_API_KEY',
            'headers': lambda key: {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
        },
        'claude': {
            'url': 'https://api.anthropic.com/v1/messages',
            'model': 'claude-3-5-sonnet-20241022',
            'env_key': 'ANTHROPIC_API_KEY',
            'headers': lambda key: {'x-api-key': key, 'Content-Type': 'application/json', 'anthropic-version': '2023-06-01'}
        },
        'groq': {
            'url': 'https://api.groq.com/openai/v1/chat/completions',
            'model': 'llama-3.3-70b-versatile',
            'env_key': 'GROQ_API_KEY',
            'headers': lambda key: {'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'}
        }
    }
    
    def __init__(self):
        self.available = []
        self._check_providers()
        
    def _check_providers(self):
        #Check which providers have API keys 
        for name, config in self.PROVIDERS.items():
            key = os.getenv(config['env_key'])
            if key:
                self.available.append(name)
                logger.info("AI", f"Cloud provider ready: {name}")
        
        if not self.available:
            logger.warning("AI", "No cloud AI providers configured (using Ollama only)")
    
    async def query(self, prompt: str, provider: str = None, timeout: int = 60) -> Optional[str]:
        # Query AI with failover 
        if provider and provider in self.available:
            return await self._try_provider(provider, prompt, timeout)
        
        # Try all available
        for prov in self.available:
            result = await self._try_provider(prov, prompt, timeout)
            if result:
                return result
        return None
    
    async def _try_provider(self, name: str, prompt: str, timeout: int) -> Optional[str]:
        # Try specific provider 
        cfg = self.PROVIDERS[name]
        key = os.getenv(cfg['env_key'])
        
        try:
            if name == 'claude':
                return await self._query_claude(cfg, key, prompt, timeout)
            else:
                return await self._query_openai_style(cfg, key, prompt, timeout)
        except Exception as e:
            logger.error("AI", f"{name} failed: {e}")
            return None
    
    async def _query_openai_style(self, cfg: Dict, key: str, prompt: str, timeout: int) -> str:
        # Query OpenAI-compatible API 
        headers = cfg['headers'](key)
        payload = {
            'model': cfg['model'],
            'messages': [
                {'role': 'system', 'content': 'You are a SQL injection expert. Be concise.'},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 2000,
            'temperature': 0.3
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(cfg['url'], headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['choices'][0]['message']['content']
                raise Exception(f"HTTP {resp.status}")
    
    async def _query_claude(self, cfg: Dict, key: str, prompt: str, timeout: int) -> str:
        # Query Claude API 
        headers = cfg['headers'](key)
        payload = {
            'model': cfg['model'],
            'max_tokens': 2000,
            'messages': [{'role': 'user', 'content': prompt}]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(cfg['url'], headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['content'][0]['text']
                raise Exception(f"HTTP {resp.status}")