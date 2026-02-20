#RAG Memory System Learning from Past Sessions 
import json
import hashlib
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config import MEMORY_DIR, SESSIONS_DIR, DUMPS_DIR, HIGH_VALUE_COLUMNS
from core.debug_logger import logger




class RAGMemorySystem:
    # Advanced RAG system with semantic search and persistent storage 

    def __init__(self):
        self.memory_file = MEMORY_DIR / "skynet_memory.md"
        self.knowledge_file = MEMORY_DIR / "skynet_knowledge.md"
        self.patterns_file = MEMORY_DIR / "attack_patterns.md"
        self.session_vectors = {}
        self.session_metadata = {}

        # Memory dict for compatibility with main.py
        self.memory = {
            'sessions': [],
            'patterns': [],
            'waf_bypasses': []
        }

        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            lowercase=True
        )
        self._init_files()
        self._load_sessions()
        self._load_memory_from_files()
        logger.info("RAG", "Memory system initialized", {"sessions": len(self.session_metadata)})

    @property
    def sessions(self):
        #Property to access sessions list - returns list of session dicts 
        return self.memory.get('sessions', [])
    
    def _load_memory_from_files(self):
        #Load sessions from JSON files into memory dict 
        try:
            sessions = []
            for session_file in SESSIONS_DIR.glob("*.json"):
                try:
                    data = json.loads(session_file.read_text(encoding='utf-8'))
                    sessions.append(data)
                except Exception as e:
                    logger.debug("RAG", f"Failed to load session {session_file}: {e}")

            self.memory['sessions'] = sessions
            logger.info("RAG", f"Loaded {len(sessions)} sessions into memory")
        except Exception as e:
            logger.error("RAG", f"Failed to load memory from files: {e}")

    def _init_files(self):
        #Init memory files if they don't exist
        if not self.memory_file.exists():
            self.memory_file.write_text("""# SKYNET Neural Memory v16

## Session Index
| Session ID | Target | Date | Status | DBs | Tables | Columns | Dumps | Technique | WAF Detected |

## High-Value Data
| Date | Target | DB | Table | Column | Type | Session ID |

## WAF Encounters
| Date | Target | WAF Type | Bypass Used | Success | Session ID |

## Web Search Learnings
| Date | Query | Results | Technique Found | Confidence | Engine |
""", encoding='utf-8')

        if not self.knowledge_file.exists():
            self.knowledge_file.write_text("""# SKYNET Knowledge Base v16

## Techniques
| Technique | Success | Fail | Rate | Best For |

## URL Patterns
| Pattern | Example | Success Rate |

## POST Patterns
| Content-Type | Pattern | Injection Point | Success Rate |
""", encoding='utf-8')

    def _load_sessions(self):
        #Load historical sessions into vector index 
        if not self.memory_file.exists():
            return

        content = self.memory_file.read_text(encoding='utf-8')
        sessions = []
        lines = content.split('\n')
        in_table = False

        for line in lines:
            if '| Session ID |' in line:
                in_table = True
                continue
            if in_table and line.startswith('|') and 'Session ID' not in line and '---' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 10 and parts[1]:
                    session_text = f"Target: {parts[2]} Status: {parts[4]} DBs: {parts[5]} Tables: {parts[6]} Technique: {parts[9]} WAF: {parts[10] if len(parts) > 10 else 'None'}"
                    self.session_metadata[parts[1]] = {
                        'target': parts[2],
                        'status': parts[4],
                        'dbs': parts[5],
                        'tables': parts[6],
                        'technique': parts[9],
                        'waf': parts[10] if len(parts) > 10 else 'None',
                        'text': session_text
                    }
                    sessions.append(session_text)

        if sessions:
            try:
                vectors = self.vectorizer.fit_transform(sessions)
                for idx, (sid, metadata) in enumerate(self.session_metadata.items()):
                    self.session_vectors[sid] = vectors[idx]
                logger.info("RAG", f"Indexed {len(sessions)} historical sessions")
            except Exception as e:
                logger.error("RAG", f"Failed to index sessions: {e}")

    def get_similar_sessions(self, target: str, limit: int = 5) -> List[Dict]:
        #Find semantically similar sessions using cosine similarity

        if not self.session_vectors:
            return []

        try:
            target_vec = self.vectorizer.transform([target])
            similarities = []

            for sid, vec in self.session_vectors.items():
                sim = cosine_similarity(target_vec, vec)[0][0]
                similarities.append((sid, sim, self.session_metadata[sid]))

            similarities.sort(key=lambda x: x[1], reverse=True)

            results = []
            for sid, sim, meta in similarities[:limit]:
                if sim > 0.1:
                    results.append({
                        'session_id': sid,
                        'similarity': round(sim, 3),
                        'target': meta['target'],
                        'status': meta['status'],
                        'technique': meta['technique'],
                        'waf': meta['waf'],
                        'dbs': meta['dbs'],
                        'tables': meta['tables']
                    })

            logger.rag_query(target, len(results))
            return results
        except Exception as e:
            logger.error("RAG", f"Similarity search failed: {e}")
            return []

    def log_session(self, session_data: Dict):
        #log session to persistent memory
        session_id = session_data['id']
        timestamp = datetime.now().isoformat()

        try:
            # Add to memory dict
            self.memory['sessions'].append(session_data)

            content = self.memory_file.read_text(encoding='utf-8')
            lines = content.split('\n')

            session_line = f"| {session_id} | {session_data['target'][:50]} | {timestamp[:10]} | {session_data['status']} | {session_data['dbs']} | {session_data['tables']} | {session_data['columns']} | {session_data['dumps']} | {', '.join(session_data.get('techniques', [])[:2])} | {session_data.get('waf_detected', 'None')} |\n"

            for i, line in enumerate(lines):
                if '| Session ID |' in line and i+2 < len(lines):
                    lines.insert(i+2, session_line)
                    break

            self.memory_file.write_text('\n'.join(lines), encoding='utf-8')

            # Save detailed session log
            session_log = SESSIONS_DIR / f"{session_id}.json"
            session_log.write_text(json.dumps(session_data, indent=2, default=str), encoding='utf-8')

            logger.info("RAG", f"Session {session_id[:8]} logged", {"status": session_data['status']})
            self._load_sessions()  # Reload index

        except Exception as e:
            logger.error("RAG", f"Failed to log session: {e}")

    def get_memory_stats(self) -> Dict:
        #Get memory statistics
        sessions = list(SESSIONS_DIR.glob("*.json"))
        dumps = list(DUMPS_DIR.glob("*.csv"))
        return {
            'sessions': len(sessions),
            'dumps': len(dumps),
            'indexed': len(self.session_metadata)
        }

    def get_all_sessions(self) -> List[Dict]:
        #Get all sessions for display - FIXED to properly load from JSON files 
        sessions = []

        # First try to load from JSON files (more reliable)
        try:
            for session_file in sorted(SESSIONS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    data = json.loads(session_file.read_text(encoding='utf-8'))
                    session_id = data.get('id', session_file.stem)
                    target = data.get('target', 'Unknown')
                    status = data.get('status', 'Unknown')
                    dbs = data.get('dbs', 0)
                    tables = data.get('tables', 0)

                    sessions.append({
                        "category": f"Session {str(session_id)[:8]}",
                        "content": f"Target: {target[:40]} | Status: {status} | DBs:{dbs} | Tables:{tables}"
                    })
                except Exception as e:
                    logger.debug("RAG", f"Failed to parse session file {session_file}: {e}")
        except Exception as e:
            logger.error("RAG", f"Failed to load sessions from directory: {e}")

        # Fallback to markdown if no JSON files
        if not sessions and self.memory_file.exists():
            try:
                content = self.memory_file.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    if '|' in line and 'Session ID' not in line and '---' not in line:
                        parts = [p.strip() for p in line.split('|')]
                        if len(parts) >= 9 and parts[1]:
                            sessions.append({
                                "category": f"Session {parts[1][:8]}",
                                "content": f"Target: {parts[2]} | Status: {parts[4]} | DBs:{parts[5]}"
                            })
            except Exception as e:
                logger.error("RAG", f"Failed to load from markdown: {e}")

        return sessions[-20:]  # Return last 20 sessions

 
rag_memory = RAGMemorySystem()