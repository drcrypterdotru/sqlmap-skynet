from pathlib import Path
from typing import Dict, List, Any
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
 
# Base directories
BASE_DIR = Path(__file__).parent
REPORT_DIR = BASE_DIR / "sqlmap_reports"
MEMORY_DIR = BASE_DIR / "memory"
SESSIONS_DIR = MEMORY_DIR / "sessions"
DUMPS_DIR = MEMORY_DIR / "dumps"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
# LOGS_DIR = BASE_DIR / "logs"
URL_LIST_FILE = BASE_DIR / "targets.txt"


# Create directories
for d in [REPORT_DIR, MEMORY_DIR, SESSIONS_DIR, DUMPS_DIR, STATIC_DIR, TEMPLATES_DIR]:
    d.mkdir(exist_ok=True, parents=True)

# ============================================================================
# AI MODEL CONFIGURATION - SIMPLIFIED
# ============================================================================

OLLAMA_MODELS = {
    'default': 'llama3.2:latest',
    # 'embedding': 'nomic-embed-text:latest'
}

# Cloud AI API Configuration
CLOUD_AI_CONFIG = {
    'deepseek': {
        'name': 'DeepSeek',
        'api_url': 'https://api.deepseek.com/v1/chat/completions',
        'model': 'deepseek-coder',
        'api_key_env': 'DEEPSEEK_API_KEY',
        'enabled': False,
        'timeout': 60,
        'max_tokens': 4096
    },
    'kimi': {
        'name': 'Kimi (Moonshot)',
        'api_url': 'https://api.moonshot.cn/v1/chat/completions',
        'model': 'kimi-latest',
        'api_key_env': 'KIMI_API_KEY',
        'enabled': False,
        'timeout': 60,
        'max_tokens': 4096
    },
    'openai': {
        'name': 'OpenAI',
        'api_url': 'https://api.openai.com/v1/chat/completions',
        'model': 'gpt-4o',
        'api_key_env': 'OPENAI_API_KEY',
        'enabled': False,
        'timeout': 60,
        'max_tokens': 4096
    },
    'claude': {
        'name': 'Claude (Anthropic)',
        'api_url': 'https://api.anthropic.com/v1/messages',
        'model': 'claude-3-5-sonnet-20241022',
        'api_key_env': 'ANTHROPIC_API_KEY',
        'enabled': False,
        'timeout': 60,
        'max_tokens': 4096
    },
    'groq': {
        'name': 'Groq',
        'api_url': 'https://api.groq.com/openai/v1/chat/completions',
        'model': 'llama-3.3-70b-versatile',
        'api_key_env': 'GROQ_API_KEY',
        'enabled': False,
        'timeout': 30,
        'max_tokens': 4096
    }
}

#AI providers (check local first, then cloud)
AI_PRIORITY = ['ollama', 'deepseek', 'kimi', 'groq', 'openai', 'claude']

# ============================================================================
# REAL-WORLD SQL INJECTION BYPASS TECHNIQUES
# ============================================================================

REAL_WORLD_BYPASSES = {
    'cloudflare': {
        'techniques': [
            {'name': 'CF Standard #1', 'tamper': 'randomcomments,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'CF Standard #2', 'tamper': 'between,charencode', 'delay': 5, 'threads': 1},
            {'name': 'CF Aggressive #3', 'tamper': 'chardoubleencode,percentage', 'delay': 4, 'threads': 2},
            {'name': 'CF Unicode #4', 'tamper': 'charunicodeencode,randomcase', 'delay': 5, 'threads': 1},
            {'name': 'CF HPP #5', 'tamper': 'hpp,space2comment', 'delay': 2, 'threads': 3},
            {'name': 'CF Base64 #6', 'tamper': 'base64encode,space2randomblank', 'delay': 4, 'threads': 2},
            {'name': 'CF Double Enc #7', 'tamper': 'chardoubleencode,apostrophemask', 'delay': 6, 'threads': 1},
            {'name': 'CF HTML Enc #8', 'tamper': 'htmlencode,randomcomments', 'delay': 3, 'threads': 2},
            {'name': 'CF Null Byte #9', 'tamper': 'appendnullbyte,space2comment', 'delay': 4, 'threads': 1},
            {'name': 'CF Union #10', 'tamper': 'unionalltounion,space2plus', 'delay': 3, 'threads': 2}
        ],
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive'
        }
    },
    
    'mod_security': {
        'techniques': [
            {'name': 'ModSec CRS4 #1', 'tamper': 'modsecurityversioned,space2comment', 'delay': 2, 'threads': 3},
            {'name': 'ModSec CRS4 #2', 'tamper': 'modsecurityzeroversioned,between', 'delay': 2, 'threads': 3},
            {'name': 'ModSec HPP #3', 'tamper': 'hpp,space2plus', 'delay': 1, 'threads': 5},
            {'name': 'ModSec Unicode #4', 'tamper': 'charunicodeencode,apostrophenullencode', 'delay': 3, 'threads': 2},
            {'name': 'ModSec Comment #5', 'tamper': 'randomcomments,htmlencode', 'delay': 2, 'threads': 3},
            {'name': 'ModSec Case #6', 'tamper': 'randomcase,percentage', 'delay': 2, 'threads': 4},
            {'name': 'ModSec Null #7', 'tamper': 'appendnullbyte,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'ModSec Double #8', 'tamper': 'chardoubleencode,randomcomments', 'delay': 4, 'threads': 2},
            {'name': 'ModSec Base64 #9', 'tamper': 'base64encode,between', 'delay': 5, 'threads': 1},
            {'name': 'ModSec Union #10', 'tamper': 'unionalltounion,space2comment', 'delay': 3, 'threads': 2}
        ]
    },
    
    'aws_waf': {
        'techniques': [
            {'name': 'AWS Standard #1', 'tamper': 'space2randomblank,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'AWS Standard #2', 'tamper': 'charencode,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'AWS Token #3', 'tamper': 'randomcomments,charencode', 'delay': 8, 'threads': 1},
            {'name': 'AWS HPP #4', 'tamper': 'hpp,percentage', 'delay': 3, 'threads': 2},
            {'name': 'AWS Slow #5', 'tamper': 'space2comment,between', 'delay': 6, 'threads': 1},
            {'name': 'AWS Unicode #6', 'tamper': 'charunicodeencode,space2plus', 'delay': 5, 'threads': 1},
            {'name': 'AWS Double #7', 'tamper': 'chardoubleencode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'AWS Base64 #8', 'tamper': 'base64encode,space2randomblank', 'delay': 5, 'threads': 2},
            {'name': 'AWS Null #9', 'tamper': 'appendnullbyte,space2comment', 'delay': 6, 'threads': 1},
            {'name': 'AWS Union #10', 'tamper': 'unionalltounion,charencode', 'delay': 4, 'threads': 2}
        ],
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'X-Forwarded-For': '127.0.0.1'
        }
    },
    
    'incapsula': {
        'techniques': [
            {'name': 'Incapsula #1', 'tamper': 'base64encode,charencode', 'delay': 3, 'threads': 2},
            {'name': 'Incapsula #2', 'tamper': 'charunicodeencode,percentage', 'delay': 4, 'threads': 1},
            {'name': 'Incapsula #3', 'tamper': 'randomcomments,apostrophemask', 'delay': 3, 'threads': 2},
            {'name': 'Incapsula #4', 'tamper': 'htmlencode,space2randomblank', 'delay': 5, 'threads': 1},
            {'name': 'Incapsula #5', 'tamper': 'chardoubleencode,unionalltounion', 'delay': 4, 'threads': 2},
            {'name': 'Incapsula #6', 'tamper': 'space2comment,randomcase', 'delay': 3, 'threads': 2},
            {'name': 'Incapsula #7', 'tamper': 'between,apostrophenullencode', 'delay': 4, 'threads': 2},
            {'name': 'Incapsula #8', 'tamper': 'appendnullbyte,charencode', 'delay': 5, 'threads': 1},
            {'name': 'Incapsula #9', 'tamper': 'hpp,space2plus', 'delay': 3, 'threads': 2},
            {'name': 'Incapsula #10', 'tamper': 'modsecurityversioned,space2comment', 'delay': 4, 'threads': 2}
        ]
    },
    
    'akamai': {
        'techniques': [
            {'name': 'Akamai #1', 'tamper': 'randomcomments,space2plus', 'delay': 3, 'threads': 2},
            {'name': 'Akamai #2', 'tamper': 'apostrophemask,space2comment', 'delay': 2, 'threads': 3},
            {'name': 'Akamai #3', 'tamper': 'charencode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'Akamai #4', 'tamper': 'between,percentage', 'delay': 3, 'threads': 2},
            {'name': 'Akamai #5', 'tamper': 'hpp,base64encode', 'delay': 5, 'threads': 1},
            {'name': 'Akamai #6', 'tamper': 'charunicodeencode,space2randomblank', 'delay': 4, 'threads': 2},
            {'name': 'Akamai #7', 'tamper': 'chardoubleencode,randomcomments', 'delay': 5, 'threads': 1},
            {'name': 'Akamai #8', 'tamper': 'unionalltounion,apostrophenullencode', 'delay': 3, 'threads': 2},
            {'name': 'Akamai #9', 'tamper': 'htmlencode,space2comment', 'delay': 4, 'threads': 2},
            {'name': 'Akamai #10', 'tamper': 'appendnullbyte,between', 'delay': 6, 'threads': 1}
        ]
    },
    
    'sucuri': {
        'techniques': [
            {'name': 'Sucuri #1', 'tamper': 'space2comment,randomcase', 'delay': 2, 'threads': 3},
            {'name': 'Sucuri #2', 'tamper': 'unionalltounion,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'Sucuri #3', 'tamper': 'charencode,apostrophenullencode', 'delay': 4, 'threads': 2},
            {'name': 'Sucuri #4', 'tamper': 'randomcomments,htmlencode', 'delay': 3, 'threads': 2},
            {'name': 'Sucuri #5', 'tamper': 'between,percentage', 'delay': 3, 'threads': 3},
            {'name': 'Sucuri #6', 'tamper': 'charunicodeencode,space2plus', 'delay': 4, 'threads': 2},
            {'name': 'Sucuri #7', 'tamper': 'base64encode,randomcase', 'delay': 5, 'threads': 1},
            {'name': 'Sucuri #8', 'tamper': 'chardoubleencode,space2randomblank', 'delay': 4, 'threads': 2},
            {'name': 'Sucuri #9', 'tamper': 'hpp,apostrophemask', 'delay': 3, 'threads': 2},
            {'name': 'Sucuri #10', 'tamper': 'appendnullbyte,unionalltounion', 'delay': 5, 'threads': 1}
        ]
    },
    
    'azure_waf': {
        'techniques': [
            {'name': 'Azure #1', 'tamper': 'space2comment,between', 'delay': 3, 'threads': 2},
            {'name': 'Azure #2', 'tamper': 'randomcase,charencode', 'delay': 4, 'threads': 2},
            {'name': 'Azure #3', 'tamper': 'charunicodeencode,space2randomblank', 'delay': 5, 'threads': 1},
            {'name': 'Azure #4', 'tamper': 'hpp,percentage', 'delay': 3, 'threads': 2},
            {'name': 'Azure #5', 'tamper': 'base64encode,randomcomments', 'delay': 4, 'threads': 2},
            {'name': 'Azure #6', 'tamper': 'chardoubleencode,space2plus', 'delay': 5, 'threads': 1},
            {'name': 'Azure #7', 'tamper': 'unionalltounion,htmlencode', 'delay': 4, 'threads': 2},
            {'name': 'Azure #8', 'tamper': 'apostrophemask,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'Azure #9', 'tamper': 'modsecurityversioned,between', 'delay': 4, 'threads': 2},
            {'name': 'Azure #10', 'tamper': 'appendnullbyte,charencode', 'delay': 6, 'threads': 1}
        ]
    },
    
    'cloud_armor': {
        'techniques': [
            {'name': 'GCA #1', 'tamper': 'modsecurityversioned,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'GCA #2', 'tamper': 'randomcomments,percentage', 'delay': 4, 'threads': 2},
            {'name': 'GCA #3', 'tamper': 'charunicodeencode,space2plus', 'delay': 5, 'threads': 1},
            {'name': 'GCA #4', 'tamper': 'space2randomblank,randomcase', 'delay': 3, 'threads': 2},
            {'name': 'GCA #5', 'tamper': 'charencode,between', 'delay': 4, 'threads': 2},
            {'name': 'GCA #6', 'tamper': 'hpp,apostrophemask', 'delay': 3, 'threads': 3},
            {'name': 'GCA #7', 'tamper': 'base64encode,space2comment', 'delay': 5, 'threads': 1},
            {'name': 'GCA #8', 'tamper': 'chardoubleencode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'GCA #9', 'tamper': 'unionalltounion,htmlencode', 'delay': 5, 'threads': 1},
            {'name': 'GCA #10', 'tamper': 'appendnullbyte,randomcomments', 'delay': 6, 'threads': 1}
        ]
    },
    
    'f5_asm': {
        'techniques': [
            {'name': 'F5 #1', 'tamper': 'space2comment,apostrophemask', 'delay': 3, 'threads': 2},
            {'name': 'F5 #2', 'tamper': 'between,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'F5 #3', 'tamper': 'hpp,charencode', 'delay': 3, 'threads': 3},
            {'name': 'F5 #4', 'tamper': 'charunicodeencode,space2plus', 'delay': 4, 'threads': 2},
            {'name': 'F5 #5', 'tamper': 'randomcomments,percentage', 'delay': 3, 'threads': 2},
            {'name': 'F5 #6', 'tamper': 'base64encode,space2randomblank', 'delay': 5, 'threads': 1},
            {'name': 'F5 #7', 'tamper': 'chardoubleencode,between', 'delay': 4, 'threads': 2},
            {'name': 'F5 #8', 'tamper': 'unionalltounion,apostrophenullencode', 'delay': 4, 'threads': 2},
            {'name': 'F5 #9', 'tamper': 'modsecurityversioned,htmlencode', 'delay': 5, 'threads': 1},
            {'name': 'F5 #10', 'tamper': 'appendnullbyte,space2comment', 'delay': 6, 'threads': 1}
        ]
    },
    
    'fortinet': {
        'techniques': [
            {'name': 'FortiWeb #1', 'tamper': 'randomcomments,space2randomblank', 'delay': 3, 'threads': 2},
            {'name': 'FortiWeb #2', 'tamper': 'chardoubleencode,percentage', 'delay': 4, 'threads': 2},
            {'name': 'FortiWeb #3', 'tamper': 'space2comment,randomcase', 'delay': 3, 'threads': 2},
            {'name': 'FortiWeb #4', 'tamper': 'charencode,between', 'delay': 4, 'threads': 2},
            {'name': 'FortiWeb #5', 'tamper': 'hpp,apostrophemask', 'delay': 3, 'threads': 2},
            {'name': 'FortiWeb #6', 'tamper': 'charunicodeencode,space2plus', 'delay': 5, 'threads': 1},
            {'name': 'FortiWeb #7', 'tamper': 'base64encode,randomcomments', 'delay': 5, 'threads': 1},
            {'name': 'FortiWeb #8', 'tamper': 'unionalltounion,htmlencode', 'delay': 4, 'threads': 2},
            {'name': 'FortiWeb #9', 'tamper': 'modsecurityversioned,percentage', 'delay': 4, 'threads': 2},
            {'name': 'FortiWeb #10', 'tamper': 'appendnullbyte,space2comment', 'delay': 6, 'threads': 1}
        ]
    },
    
    'barracuda': {
        'techniques': [
            {'name': 'Barracuda #1', 'tamper': 'space2comment,htmlencode', 'delay': 3, 'threads': 2},
            {'name': 'Barracuda #2', 'tamper': 'base64encode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'Barracuda #3', 'tamper': 'randomcomments,charencode', 'delay': 3, 'threads': 2},
            {'name': 'Barracuda #4', 'tamper': 'between,apostrophemask', 'delay': 4, 'threads': 2},
            {'name': 'Barracuda #5', 'tamper': 'charunicodeencode,space2randomblank', 'delay': 5, 'threads': 1},
            {'name': 'Barracuda #6', 'tamper': 'hpp,percentage', 'delay': 3, 'threads': 2},
            {'name': 'Barracuda #7', 'tamper': 'chardoubleencode,space2plus', 'delay': 4, 'threads': 2},
            {'name': 'Barracuda #8', 'tamper': 'unionalltounion,between', 'delay': 4, 'threads': 2},
            {'name': 'Barracuda #9', 'tamper': 'modsecurityversioned,randomcase', 'delay': 5, 'threads': 1},
            {'name': 'Barracuda #10', 'tamper': 'appendnullbyte,apostrophenullencode', 'delay': 6, 'threads': 1}
        ]
    },
    
    'imperva': {
        'techniques': [
            {'name': 'Imperva #1', 'tamper': 'charunicodeencode,space2comment', 'delay': 4, 'threads': 2},
            {'name': 'Imperva #2', 'tamper': 'randomcomments,base64encode', 'delay': 5, 'threads': 1},
            {'name': 'Imperva #3', 'tamper': 'hpp,charencode', 'delay': 3, 'threads': 2},
            {'name': 'Imperva #4', 'tamper': 'space2randomblank,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'Imperva #5', 'tamper': 'chardoubleencode,apostrophemask', 'delay': 5, 'threads': 1},
            {'name': 'Imperva #6', 'tamper': 'between,htmlencode', 'delay': 4, 'threads': 2},
            {'name': 'Imperva #7', 'tamper': 'unionalltounion,percentage', 'delay': 4, 'threads': 2},
            {'name': 'Imperva #8', 'tamper': 'modsecurityversioned,space2plus', 'delay': 5, 'threads': 1},
            {'name': 'Imperva #9', 'tamper': 'appendnullbyte,randomcomments', 'delay': 6, 'threads': 1},
            {'name': 'Imperva #10', 'tamper': 'apostrophenullencode,between', 'delay': 4, 'threads': 2}
        ]
    },
    
    'wordfence': {
        'techniques': [
            {'name': 'Wordfence #1', 'tamper': 'space2comment,randomcase', 'delay': 2, 'threads': 3},
            {'name': 'Wordfence #2', 'tamper': 'charencode,between', 'delay': 3, 'threads': 2},
            {'name': 'Wordfence #3', 'tamper': 'randomcomments,apostrophemask', 'delay': 3, 'threads': 2},
            {'name': 'Wordfence #4', 'tamper': 'hpp,space2plus', 'delay': 2, 'threads': 3},
            {'name': 'Wordfence #5', 'tamper': 'charunicodeencode,percentage', 'delay': 4, 'threads': 2},
            {'name': 'Wordfence #6', 'tamper': 'base64encode,htmlencode', 'delay': 5, 'threads': 1},
            {'name': 'Wordfence #7', 'tamper': 'chardoubleencode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'Wordfence #8', 'tamper': 'unionalltounion,space2comment', 'delay': 3, 'threads': 2},
            {'name': 'Wordfence #9', 'tamper': 'modsecurityversioned,space2randomblank', 'delay': 4, 'threads': 2},
            {'name': 'Wordfence #10', 'tamper': 'appendnullbyte,between', 'delay': 5, 'threads': 1}
        ]
    },
    
    'generic_403': {
        'techniques': [
            {'name': 'Generic #1', 'tamper': 'space2comment,between', 'delay': 3, 'threads': 2},
            {'name': 'Generic #2', 'tamper': 'randomcase,charencode', 'delay': 4, 'threads': 1},
            {'name': 'Generic #3', 'tamper': 'apostrophemask,space2comment', 'delay': 2, 'threads': 3},
            {'name': 'Generic #4', 'tamper': 'randomcomments,percentage', 'delay': 3, 'threads': 2},
            {'name': 'Generic #5', 'tamper': 'hpp,space2plus', 'delay': 2, 'threads': 4},
            {'name': 'Generic #6', 'tamper': 'charunicodeencode,between', 'delay': 5, 'threads': 1},
            {'name': 'Generic #7', 'tamper': 'base64encode,randomcase', 'delay': 4, 'threads': 2},
            {'name': 'Generic #8', 'tamper': 'chardoubleencode,apostrophenullencode', 'delay': 5, 'threads': 1},
            {'name': 'Generic #9', 'tamper': 'unionalltounion,htmlencode', 'delay': 4, 'threads': 2},
            {'name': 'Generic #10', 'tamper': 'modsecurityversioned,space2randomblank', 'delay': 4, 'threads': 2},
            {'name': 'Generic #11', 'tamper': 'appendnullbyte,randomcomments', 'delay': 6, 'threads': 1},
            {'name': 'Generic #12', 'tamper': 'space2plus,charunicodeencode', 'delay': 4, 'threads': 2}
        ]
    },
    
    'rate_limit': {
        'techniques': [
            {'name': 'Slow #1', 'tamper': 'space2comment', 'delay': 10, 'threads': 1},
            {'name': 'Slow #2', 'tamper': 'randomcase', 'delay': 15, 'threads': 1},
            {'name': 'Slow #3', 'tamper': 'between', 'delay': 12, 'threads': 1},
            {'name': 'Slow #4', 'tamper': 'charencode', 'delay': 20, 'threads': 1},
            {'name': 'Slow #5', 'tamper': 'space2randomblank', 'delay': 8, 'threads': 1}
        ]
    }
}


# Advanced SQLMap Tamper Scripts Database (You can extract mor in next level and unlimited to challenge in real world)
# TAMPER_SCRIPTS = {
#     'basic': ['space2comment', 'between', 'randomcase'],
#     'moderate': ['space2comment', 'randomcomments', 'charencode', 'percentage'],
#     'aggressive': ['base64encode', 'charunicodeencode', 'chardoubleencode', 'apostrophemask'],
#     'waf_specific': {
#         'cloudflare': ['randomcomments', 'space2comment', 'between', 'chardoubleencode'],
#         'mod_security': ['modsecurityversioned', 'modsecurityzeroversioned', 'space2comment'],
#         'aws_waf': ['space2randomblank', 'randomcase', 'charencode'],
#         'incapsula': ['base64encode', 'charencode', 'charunicodeencode'],
#         'akamai': ['randomcomments', 'space2plus', 'apostrophemask'],
#         'sucuri': ['space2comment', 'randomcase', 'unionalltounion']
#     }
# }
TAMPER_SCRIPTS = {
    'basic': [
        'space2comment', 'between', 'randomcase', 'space2plus', 
        'space2randomblank', 'charencode', 'percentage', 'apostrophemask'
    ],
    
    'moderate': [
        'space2comment', 'randomcomments', 'charencode', 'percentage',
        'apostrophemask', 'apostrophenullencode', 'htmlencode',
        'base64encode', 'between', 'randomcase', 'space2plus'
    ],
    
    'aggressive': [
        'base64encode', 'charunicodeencode', 'chardoubleencode', 
        'apostrophemask', 'apostrophenullencode', 'htmlencode',
        'appendnullbyte', 'prependnullbyte', 'hexencode',
        'modsecurityversioned', 'modsecurityzeroversioned'
    ],
    
    'waf_specific': {
        'cloudflare': [
            'randomcomments', 'space2comment', 'between', 'chardoubleencode',
            'htmlencode', 'space2randomblank', 'charunicodeencode',
            'apostrophemask', 'hpp', 'base64encode'
        ],
        'aws_waf': [
            'space2randomblank', 'randomcase', 'charencode', 'between',
            'modsecurityversioned', 'hpp', 'randomcomments',
            'charunicodeencode', 'space2plus'
        ],
        'mod_security': [
            'modsecurityversioned', 'modsecurityzeroversioned', 'space2comment',
            'randomcomments', 'apostrophenullencode', 'htmlencode',
            'chardoubleencode', 'between', 'randomcase'
        ],
        'incapsula': [
            'base64encode', 'charencode', 'charunicodeencode', 'htmlencode',
            'apostrophemask', 'randomcomments', 'chardoubleencode',
            'space2randomblank', 'hpp'
        ],
        'akamai': [
            'randomcomments', 'space2plus', 'apostrophemask', 'charencode',
            'randomcase', 'between', 'charunicodeencode',
            'base64encode', 'hpp'
        ],
        'sucuri': [
            'space2comment', 'randomcase', 'unionalltounion', 'charencode',
            'percentage', 'apostrophemask', 'randomcomments',
            'charunicodeencode', 'between'
        ],
        'azure_waf': [
            'space2comment', 'between', 'randomcase', 'charencode',
            'charunicodeencode', 'hpp', 'base64encode',
            'space2randomblank', 'unionalltounion'
        ],
        'cloud_armor': [
            'modsecurityversioned', 'randomcomments', 'charunicodeencode',
            'space2plus', 'charencode', 'randomcase', 'between',
            'space2randomblank', 'hpp'
        ],
        'f5_asm': [
            'space2comment', 'apostrophemask', 'between', 'hpp',
            'charunicodeencode', 'randomcomments', 'charencode',
            'base64encode', 'randomcase'
        ],
        'fortinet': [
            'randomcomments', 'space2randomblank', 'chardoubleencode',
            'space2comment', 'randomcase', 'charencode', 'between',
            'hpp', 'apostrophemask'
        ],
        'barracuda': [
            'space2comment', 'htmlencode', 'base64encode', 'randomcase',
            'randomcomments', 'charencode', 'between', 'charunicodeencode',
            'space2randomblank', 'hpp'
        ],
        'imperva': [
            'charunicodeencode', 'space2comment', 'randomcomments',
            'base64encode', 'hpp', 'charencode', 'space2randomblank',
            'randomcase', 'chardoubleencode'
        ],
        'wordfence': [
            'space2comment', 'randomcase', 'charencode', 'between',
            'randomcomments', 'apostrophemask', 'hpp', 'space2plus',
            'charunicodeencode', 'base64encode'
        ]
    }
}

# Real-world SQL injection techniques priority
TECHNIQUE_PRIORITY = {
    'error_based': ['E', 'X'],      # Error-based and stacked queries
    'union_based': ['U'],            # UNION query
    'blind_boolean': ['B'],          # Boolean-based blind
    'blind_time': ['T', 'S'],        # Time-based blind and stacked
    'out_of_band': ['O'],            # Out-of-band
    'inline': ['Q']                  # Inline queries
}



# Advanced detection patterns
DETECTION_PATTERNS = {
    'mysql': {
        'error_signatures': ['You have an error in your SQL syntax', 'MySQL server version', 'Warning: mysql_'],
        'comment_styles': ['-- ', '/**/', '#'],
        'concat_operator': 'CONCAT',
        'sleep_function': 'SLEEP',
        'version_query': 'VERSION()'
    },
    'postgresql': {
        'error_signatures': ['PostgreSQL query failed', 'ERROR: syntax error at or near'],
        'comment_styles': ['-- ', '/**/'],
        'concat_operator': '||',
        'sleep_function': 'PG_SLEEP',
        'version_query': 'VERSION()'
    },
    'mssql': {
        'error_signatures': ['Microsoft SQL Server', 'ODBC SQL Server Driver', 'SQL Server error'],
        'comment_styles': ['-- ', '/**/'],
        'concat_operator': '+',
        'sleep_function': 'WAITFOR DELAY',
        'version_query': '@@VERSION'
    },
    'oracle': {
        'error_signatures': ['ORA-', 'Oracle error', 'PL/SQL:'],
        'comment_styles': ['-- ', '/**/'],
        'concat_operator': '||',
        'sleep_function': 'DBMS_LOCK.SLEEP',
        'version_query': 'BANNER FROM V$VERSION'
    }
}

# ============================================================================
# EXISTING CONFIGURATION
# ============================================================================
DEBUG_CONFIG = {
    "enabled": True,
    "colors": {
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "magenta": "\033[95m",
        "reset": "\033[0m"
    },
    # "timestamp_format": "%H:%M:%S.%f"
    "timestamp_format": "%H:%M:%S"


}   
 


MCP_CONFIG = {
    "protocol_version": "2-21-2026",
    "server_name": "skynet-neural-core-v16",
    "capabilities": {
        "resources": True,
        "tools": True,
        "prompts": True,
        "sampling": False,
        "logging": True
    }
}

WAF_PATTERNS = {
    'cloudflare': {
        'patterns': ['cloudflare', 'cf-ray', '__cfduid', 'checking your browser', 'ray id'],
        'tampers': ['randomcomments', 'space2comment', 'between', 'chardoubleencode'],
        'techniques': ['time-based blind', 'boolean-based blind'],
        'recommendation': 'Use --random-agent + --delay=2 + tamper scripts'
    },
    'mod_security': {
        'patterns': ['mod_security', 'not acceptable', '406 not acceptable', 'modsecurity'],
        'tampers': ['modsecurityversioned', 'modsecurityzeroversioned', 'space2comment'],
        'techniques': ['union query', 'error-based'],
        'recommendation': 'Try versioned tamper scripts or chunked transfer'
    },
    'aws_waf': {
        'patterns': ['aws', 'awselb', 'x-amzn-requestid', 'aws waf'],
        'tampers': ['space2randomblank', 'randomcase', 'charencode'],
        'techniques': ['time-based blind'],
        'recommendation': 'Slow down requests, use random case tamper'
    },
    'incapsula': {
        'patterns': ['incapsula', 'visid_incap', 'incap_ses'],
        'tampers': ['base64encode', 'charencode', 'charunicodeencode'],
        'techniques': ['boolean-based blind'],
        'recommendation': 'Encoding tamper scripts required'
    },
    'akamai': {
        'patterns': ['akamai', 'aka-', 'ak_bmsc', 'akamai ghost'],
        'tampers': ['randomcomments', 'space2plus', 'apostrophemask'],
        'techniques': ['error-based', 'union query'],
        'recommendation': 'Use comment randomization and spacing changes'
    },
    'sucuri': {
        'patterns': ['sucuri', 'access denied', 'x-sucuri'],
        'tampers': ['space2comment', 'randomcase', 'unionalltounion'],
        'techniques': ['boolean-based blind', 'time-based blind'],
        'recommendation': 'Randomize case and use comment obfuscation'
    },
    'generic_403': {
        'patterns': ['403 forbidden', 'access denied', 'blocked', 'forbidden'],
        'tampers': ['space2comment', 'between', 'randomcase', 'charencode'],
        'techniques': ['time-based blind', 'boolean-based blind'],
        'recommendation': 'Switch to blind techniques with tamper scripts'
    },
    'generic_500': {
        'patterns': ['500 internal', 'server error', 'sql syntax', 'database error'],
        'tampers': ['space2comment', 'apostrophemask', 'randomcomments'],
        'techniques': ['error-based'],
        'recommendation': 'Error-based injection likely, check error messages'
    },
    'rate_limit': {
        'patterns': ['rate limit', 'too many requests', '429', 'slow down', 'throttled'],
        'tampers': ['space2comment'],
        'techniques': ['time-based blind'],
        'recommendation': 'Add --delay=5+ and reduce --threads to 1'
    },
    'sqli_filter': {
        'patterns': ['union select', 'illegal character', 'sql injection', 'detected'],
        'tampers': ['base64encode', 'charunicodeencode', 'percentage'],
        'techniques': ['boolean-based blind'],
        'recommendation': 'Heavy encoding required - try base64 or unicode'
    }
}

SEARCH_APIS = {
    'searxng': {
        'name': 'SearXNG',
        'url': 'https://search.sapti.me',
        'enabled': True,
        'key_required': False
    },
    'brave': {
        'name': 'Brave Search',
        'url': 'https://api.search.brave.com/res/v1/web/search',
        'key_env': 'BRAVE_API_KEY',
        'enabled': False,
        'key_required': True
    },
    'bing': {
        'name': 'Bing Search',
        'url': 'https://api.bing.microsoft.com/v7.0/search',
        'key_env': 'BING_API_KEY',
        'enabled': False,
        'key_required': True
    },
    'serpapi': {
        'name': 'SerpAPI (Google)',
        'url': 'https://serpapi.com/search',
        'key_env': 'SERPAPI_KEY',
        'enabled': False,
        'key_required': True
    },
    'duckduckgo': {
        'name': 'DuckDuckGo (Scrape)',
        'url': 'https://html.duckduckgo.com/html/',
        'enabled': True,
        'key_required': False
    },
    'startpage': {
        'name': 'StartPage (Scrape)',
        'url': 'https://www.startpage.com/sp/search',
        'enabled': False,
        'key_required': False
    },
    'qwant': {
        'name': 'Qwant (Scrape)',
        'url': 'https://www.qwant.com/',
        'enabled': False,
        'key_required': False
    }
}


#Extract your own idea with new keyword more enjoy <3 
HIGH_VALUE_COLUMNS = [
    'password', 'passwd', 'pass', 'pwd', 'user_password', 'user_pass', 'pass_word',
    'hash', 'salt', 'encrypted_password', 'password_hash', 'password_salt',
    'email', 'e_mail', 'mail', 'user_email', 'email_address',
    'username', 'user_name', 'user', 'login', 'usr', 'uid', 'user_id', 'userid',
    'name', 'first_name', 'last_name', 'fullname', 'full_name', 'fname', 'lname',
    'admin', 'administrator', 'root', 'superuser', 'role', 'permission', 'group',
    'is_admin', 'admin_level', 'privilege', 'access_level',
    'phone', 'mobile', 'tel', 'telephone', 'cell', 'fax', 'contact',
    'address', 'addr', 'street', 'city', 'state', 'zip', 'postal', 'country',
    'token', 'api_key', 'apikey', 'auth_token', 'session', 'jwt', 'secret',
    'private_key', 'public_key', 'secret_key', 'access_token', 'refresh_token',
    'ssn', 'social_security', 'sin', 'national_id', 'nid', 'passport',
    'dob', 'birthdate', 'birth_date', 'age', 'gender', 'sex',
    'credit_card', 'cc_number', 'ccnum', 'card_number', 'cardnum', 'ccn',
    'cvv', 'cvv2', 'ccv', 'cvc', 'cvc2', 'expiry', 'expiration', 'exp_date',
    'bank_account', 'account_number', 'acct_num', 'iban', 'swift', 'routing',
    'balance', 'amount', 'currency', 'payment', 'price', 'cost', 'total',
    'ip', 'ip_address', 'last_ip', 'login_ip', 'registration_ip', 'user_ip',
    'secret', 'private', 'personal', 'confidential', 'restricted'
]

TARGET_CATEGORIES = {
    'credentials': ['password', 'passwd', 'pass', 'pwd', 'hash', 'salt', 'token'],
    'personal': ['email', 'username', 'name', 'phone', 'address', 'ssn', 'dob'],
    'financial': ['credit_card', 'cvv', 'bank', 'balance', 'payment'],
    'admin': ['admin', 'root', 'role', 'permission']
}