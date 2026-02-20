#Multi-Engine Web Search Module
import os
import re 
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from config import SEARCH_APIS, MEMORY_DIR
from core.debug_logger import logger
import json

class WebSearchEngine:
    #Advanced web search with multiple engine support
    
    def __init__(self):
        self.apis = SEARCH_APIS.copy()
        self.search_history = []
        self.learned_patterns = []
        self.debug_mode = True
        self.patterns_file = MEMORY_DIR / "attack_patterns.md"
        logger.info("SEARCH", "Web search engine initialized")
    
    def enable_api(self, api_name: str, api_key: Optional[str] = None) -> bool:
        #Enable a search API
        if api_name not in self.apis:
            return False
        
        self.apis[api_name]['enabled'] = True
        if api_key and self.apis[api_name].get('key_required'):
            os.environ[self.apis[api_name]['key_env']] = api_key
        
        logger.info("SEARCH", f"Enabled: {self.apis[api_name]['name']}")
        return True
    
    def disable_api(self, api_name: str):
        #Disable a search API
        if api_name in self.apis:
            self.apis[api_name]['enabled'] = False
            logger.info("SEARCH", f"Disabled: {self.apis[api_name]['name']}")
    
    async def search_bypass_techniques(self, waf_type: str, error_msg: str = "", logs: str = "") -> List[Dict]:
        #AI-powered search for WAF bypass techniques
        queries = self._generate_queries(waf_type, error_msg, logs)
        
        logger.debug("SEARCH", f"Searching for WAF: {waf_type}", {"queries": len(queries)})
        
        all_results = []
        for query in queries:
            results = await self._perform_search(query, waf_type)
            if results:
                all_results.extend(results)
                if len(all_results) >= 10:
                    break
        
        techniques = []
        for result in all_results:
            technique = self._extract_technique(result, waf_type)
            if technique:
                techniques.append(technique)
                self._save_pattern(waf_type, technique, result.get('source', 'unknown'))
        
        logger.info("SEARCH", f"Found {len(techniques)} techniques for {waf_type}")
        return techniques
    
    def _generate_queries(self, waf_type: str, error_msg: str, logs: str) -> List[str]:
        #Generate AI search queries
        queries = [
            f"sqlmap bypass {waf_type} WAF",
            f"sqlmap tamper scripts {waf_type} evasion",
        ]
        
        if error_msg:
            error_snippet = ' '.join(error_msg.split()[:8])
            queries.append(f"sqlmap \"{error_snippet}\" solution")
        
        if logs:
            if 'time-based' in logs.lower():
                queries.append(f"{waf_type} time-based blind sqlmap bypass")
            if 'union' in logs.lower():
                queries.append(f"{waf_type} union select bypass tamper")
        
        queries.extend([
            f"SQL injection bypass {waf_type} techniques github",
            f"{waf_type} sqlmap --tamper recommendations"
        ])
        
        seen = set()
        unique = []
        for q in queries:
            if q.lower() not in seen:
                seen.add(q.lower())
                unique.append(q)
        
        return unique[:5]
    
    async def _perform_search(self, query: str, context: str = "") -> List[Dict]:
        #Execute search across enabled engines
        results = []
        engines_order = ['searxng', 'brave', 'bing', 'serpapi', 'duckduckgo', 'startpage', 'qwant']
        
        for engine_name in engines_order:
            if not self.apis[engine_name]['enabled']:
                continue
            
            try:
                if engine_name == 'searxng':
                    results = await self._search_searxng(query)
                elif engine_name == 'brave':
                    results = await self._search_brave(query)
                elif engine_name == 'bing':
                    results = await self._search_bing(query)
                elif engine_name == 'serpapi':
                    results = await self._search_serpapi(query)
                elif engine_name == 'duckduckgo':
                    results = await self._search_duckduckgo(query)
                elif engine_name == 'startpage':
                    results = await self._search_startpage(query)
                elif engine_name == 'qwant':
                    results = await self._search_qwant(query)
                
                if results:
                    logger.debug("SEARCH", f"Success from {engine_name}", {"results": len(results)})
                    break
                    
            except Exception as e:
                logger.debug("SEARCH", f"{engine_name} failed", {"error": str(e)})
                continue
        
        self.search_history.append({
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'context': context,
            'results_count': len(results),
            'engine_used': results[0].get('source') if results else 'none'
        })
        
        return results
    
    async def _search_searxng(self, query: str) -> List[Dict]:
        #Search using SearXNG instances
        instances = [
            "https://search.sapti.me",
            "https://searx.be",
            "https://search.disroot.org",
            "https://searx.fmac.xyz",
            "http://localhost:8080"
        ]
        
        for instance in instances:
            try:
                params = {
                    'q': query,
                    'format': 'json',
                    'language': 'en',
                    'safesearch': '0',
                    'categories': 'general'
                }
                
                response = requests.get(
                    f"{instance}/search",
                    params=params,
                    timeout=15,
                    headers={'Accept': 'application/json'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results = data.get('results', [])
                    if results:
                        return [{
                            'title': r.get('title', ''),
                            'url': r.get('url', ''),
                            'description': r.get('content', ''),
                            'source': 'searxng',
                            'engine': instance
                        } for r in results[:5]]
                
            except Exception:
                continue
        
        return []
    
    async def _search_brave(self, query: str) -> List[Dict]:
        #Search using Brave API
        api_key = os.getenv('BRAVE_API_KEY')
        if not api_key:
            return []
        
        try:
            headers = {
                'X-Subscription-Token': api_key,
                'Accept': 'application/json'
            }
            params = {
                'q': query,
                'count': 5,
                'offset': 0,
                'mkt': 'en-US',
                'safesearch': 'off',
                'freshness': 'py'
            }
            
            response = requests.get(
                self.apis['brave']['url'],
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                web_results = data.get('web', {}).get('results', [])
                return [{
                    'title': r.get('title', ''),
                    'url': r.get('url', ''),
                    'description': r.get('description', ''),
                    'source': 'brave'
                } for r in web_results]
                
        except Exception:
            pass
        
        return []
    
    async def _search_bing(self, query: str) -> List[Dict]:
        #Search using Bing API
        api_key = os.getenv('BING_API_KEY')
        if not api_key:
            return []
        
        try:
            headers = {'Ocp-Apim-Subscription-Key': api_key}
            params = {
                'q': query,
                'count': 5,
                'mkt': 'en-US',
                'safesearch': 'Off'
            }
            
            response = requests.get(
                'https://api.bing.microsoft.com/v7.0/search',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                web_pages = data.get('webPages', {}).get('value', [])
                return [{
                    'title': p.get('name', ''),
                    'url': p.get('url', ''),
                    'description': p.get('snippet', ''),
                    'source': 'bing'
                } for p in web_pages]
                
        except Exception:
            pass
        
        return []
    
    async def _search_serpapi(self, query: str) -> List[Dict]:
        #Search using SerpAPI
        api_key = os.getenv('SERPAPI_KEY')
        if not api_key:
            return []
        
        try:
            params = {
                'q': query,
                'api_key': api_key,
                'engine': 'google',
                'num': 5,
                'tbs': 'qdr:y'
            }
            
            response = requests.get(
                'https://serpapi.com/search',
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('organic_results', [])
                return [{
                    'title': r.get('title', ''),
                    'url': r.get('link', ''),
                    'description': r.get('snippet', ''),
                    'source': 'serpapi'
                } for r in results]
                
        except Exception:
            pass
        
        return []
    
    async def _search_duckduckgo(self, query: str) -> List[Dict]:
        #Scrape DuckDuckGo
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            params = {'q': query}
            
            response = requests.get(
                'https://html.duckduckgo.com/html/',
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                results = []
                titles = re.findall(r'<a[^>]+class="result__a"[^>]*>([^<]+)</a>', response.text)
                urls = re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', response.text)
                snippets = re.findall(r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>', response.text)
                
                for i in range(min(len(titles), 5)):
                    results.append({
                        'title': titles[i],
                        'url': urls[i] if i < len(urls) else '',
                        'description': snippets[i] if i < len(snippets) else '',
                        'source': 'duckduckgo'
                    })
                
                return results
                
        except Exception:
            pass
        
        return []
    
    async def _search_startpage(self, query: str) -> List[Dict]:
        #Scrape StartPage
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
                'Accept': 'text/html'
            }
            
            data = {
                'query': query,
                'cat': 'web',
                'pl': 'chrome',
                'language': 'english'
            }
            
            response = requests.post(
                'https://www.startpage.com/sp/search',
                data=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                results = []
                titles = re.findall(r'<h3[^>]*>([^<]+)</h3>', response.text)
                urls = re.findall(r'<a[^>]+href="([^"]+)"[^>]*class="[^"]*result-link[^"]*"', response.text)
                
                for i in range(min(len(titles), 5)):
                    results.append({
                        'title': titles[i],
                        'url': urls[i] if i < len(urls) else '',
                        'description': 'StartPage result',
                        'source': 'startpage'
                    })
                
                return results
                
        except Exception:
            pass
        
        return []
    
    async def _search_qwant(self, query: str) -> List[Dict]:
        #Scrape Qwant
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
                'Accept': 'application/json'
            }
            
            params = {
                'q': query,
                'count': 5,
                'locale': 'en_US',
                'device': 'desktop',
                'safesearch': '0'
            }
            
            response = requests.get(
                'https://api.qwant.com/v3/search/web',
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('data', {}).get('result', {}).get('items', {}).get('mainline', [])
                results = []
                
                for item in items:
                    if item.get('type') == 'web':
                        for result in item.get('items', []):
                            results.append({
                                'title': result.get('title', ''),
                                'url': result.get('url', ''),
                                'description': result.get('desc', ''),
                                'source': 'qwant'
                            })
                
                return results[:5]
                
        except Exception:
            pass
        
        return []
    
    def _extract_technique(self, result: Dict, waf_type: str) -> Optional[Dict]:
        #Extract technique from search result
        title = result.get('title', '').lower()
        desc = result.get('description', '').lower()
        text = f"{title} {desc}"
        
        tamper_pattern = r'(\w+)\.py|tamper[=\s]+(\w+)|--tamper[=:\s]+(\w+)'
        tampers = re.findall(tamper_pattern, text)
        tampers = [t for group in tampers for t in group if t]
        
        techniques = []
        if 'time-based' in text or 'time based' in text:
            techniques.append('time-based blind')
        if 'boolean-based' in text or 'boolean based' in text:
            techniques.append('boolean-based blind')
        if 'union' in text:
            techniques.append('union query')
        if 'error-based' in text or 'error based' in text:
            techniques.append('error-based')
        if 'stacked' in text:
            techniques.append('stacked queries')
        
        if tampers or techniques:
            return {
                'waf_type': waf_type,
                'tampers': list(set(tampers))[:3],
                'techniques': techniques,
                'source_url': result.get('url'),
                'source_title': result.get('title'),
                'source_engine': result.get('source'),
                'confidence': self._calculate_confidence(text, waf_type)
            }
        return None
    
    def _calculate_confidence(self, text: str, waf_type: str) -> float:
        #Calculate confidence score
        score = 0.5
        if waf_type.lower() in text:
            score += 0.3
        if 'sqlmap' in text:
            score += 0.1
        if 'bypass' in text or 'evasion' in text:
            score += 0.1
        return min(score, 1.0)
    
    def _save_pattern(self, category: str, data: Dict, source: str):
        #Save learned pattern to file
        pattern = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'data': data,
            'source': source
        }
        self.learned_patterns.append(pattern)
        
        try:
            with open(self.patterns_file, 'a', encoding='utf-8') as f:
                f.write(f"\n## Web Search Learning - {datetime.now().isoformat()}\n")
                f.write(f"**Category**: {category}\n")
                f.write(f"**Source**: {source}\n")
                f.write(f"**Data**: {json.dumps(data, indent=2)}\n")
                f.write("---\n")
        except Exception as e:
            logger.debug("SEARCH", f"Failed to save pattern: {e}")
    
    def get_search_stats(self) -> Dict:
        #Get search statistics
        return {
            'total_searches': len(self.search_history),
            'learned_patterns': len(self.learned_patterns),
            'apis_enabled': [k for k, v in self.apis.items() if v.get('enabled')],
            'recent_queries': [s['query'] for s in self.search_history[-5:]],
            'last_search': self.search_history[-1] if self.search_history else None
        }

web_search = WebSearchEngine()