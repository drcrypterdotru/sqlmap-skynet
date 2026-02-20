"""Log Parsers Module from sqlmap log in real time"""
import re
from typing import List, Dict, Any

class SQLMapLogParser:
    #Parse SQLMap output logs
    
    @staticmethod
    def parse_databases(logs: List[str]) -> List[str]:
        #Extract database names from logs
        databases = []
        text = '\n'.join(logs)
        
        # Pattern 1 => Standard sqlmap output "[*] database_name"
        for match in re.finditer(r'^\[\*\]\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*$', text, re.MULTILINE):
            db = match.group(1)
            if db and db.lower() not in ['tables', 'columns', 'entries', 'database', 'table', 'column']:
                databases.append(db)
        
        # Pattern 2 => "available databases" section
        in_db_section = False
        for line in logs:
            if 'available databases' in line.lower():
                in_db_section = True
                continue
            if in_db_section and line.strip().startswith('['):
                match = re.search(r'\[\d+\]\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
                if match:
                    db = match.group(1)
                    if db and db.lower() not in ['tables', 'columns', 'entries']:
                        databases.append(db)
            elif in_db_section and not line.strip().startswith('['):
                in_db_section = False
        
        return list(set(databases))
    
    @staticmethod
    def parse_tables(logs: List[str], db: str) -> List[str]:
        #Extract table names from logs
        text = '\n'.join(logs)
        tables = []
        
        # Pattern 1 => table_name 
        for match in re.finditer(r'\|\s+([a-zA-Z_][a-zA-Z0-9_]+)\s+\|', text):
            table = match.group(1)
            if table and table not in ['tables', 'columns', 'entries', 'table', 'column']:
                tables.append(table)
        
        # Pattern 2 => number table_name
        for match in re.finditer(r'\[\d+\]\s+([a-zA-Z_][a-zA-Z0-9_]*)', text):
            table = match.group(1)
            if table and table not in ['tables', 'columns', 'entries']:
                tables.append(table)
        
        
        return list(dict.fromkeys(tables))  # order, remove duplicates
    
    #Extract column names and types from logs
    @staticmethod
    def parse_columns(logs: List[str]) -> List[Dict[str, str]]:
        
        text = '\n'.join(logs)
        columns = []
        
        # Pattern 1 => column_name and type
        for match in re.finditer(r'\|\s+([a-zA-Z_][a-zA-Z0-9_]+)\s+\|\s+(\w+)', text):
            col_name = match.group(1)
            col_type = match.group(2)
            if col_name.lower() not in ['column', 'type', 'null', 'columns']:
                columns.append({'name': col_name, 'type': col_type})
        
        # Pattern 2 => number column_name
        for match in re.finditer(r'\[\d+\]\s+([a-zA-Z_][a-zA-Z0-9_]+)', text):
            col_name = match.group(1)
            if col_name.lower() not in ['column', 'type', 'null', 'columns']:
                if not any(c['name'] == col_name for c in columns):
                    columns.append({'name': col_name, 'type': 'unknown'})
        
        return columns

# Global instance
log_parser = SQLMapLogParser()