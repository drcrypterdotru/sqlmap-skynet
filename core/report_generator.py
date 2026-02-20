"""SQLMap Report Generator => Auto-generates HTML, JSON, TXT reports"""
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import unquote

# Import from existing files
try:
    from debug_logger import logger
    from config import REPORT_DIR
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    REPORT_DIR = Path("./sqlmap_reports")

class SQLMapReportGenerator:
    """Generate comprehensive scan reports in multiple formats"""
    
    def __init__(self):
        self.report_dir = REPORT_DIR
        self.report_dir.mkdir(exist_ok=True, parents=True)
        self.current_report_base = None
        
    def generate_all_reports(self, results: Dict[str, Any], session_id: str, 
                            target_url: str, commands_executed: List[Dict] = None):
        """Generate all three report formats automatically"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self._sanitize_filename(target_url.replace('://', '_').replace('/', '_'))
        
        self.current_report_base = self.report_dir / f"sqlmap_report_{safe_target}_{timestamp}"
        
        report_data = {
            'scan_info': {
                'session_id': session_id,
                'target_url': target_url,
                'timestamp': datetime.now().isoformat(),
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'status': results.get('status', 'COMPLETED'),
                'duration': results.get('duration', 'N/A'),
                'method': results.get('method', 'GET'),
                'backend': results.get('backend', 'sqlmap.py')
            },
            'findings': {
                'injection_found': results.get('injection_found', False),
                'waf_detected': results.get('waf_detected'),
                'techniques': results.get('techniques', []),
                'databases': results.get('databases', []),
                'tables': results.get('tables', {}),
                'columns': results.get('columns', {}),
                'total_databases': len(results.get('databases', [])),
                'total_tables': sum(len(t) for t in results.get('tables', {}).values()),
                'total_columns': sum(len(c) for c in results.get('columns', {}).values())
            },
            'commands': commands_executed or [],
            'ai_analysis': {
                'ollama_used': results.get('ollama_used', False),
                'ollama_recommendations': results.get('ollama_recommendations'),
                'web_searches': results.get('web_searches', 0),
                'cycles': results.get('cycles', 0)
            },
            'metadata': {
                'report_version': '1.0.0',
                'generator': 'SQLMAP SKYNET',
                'high_value_targets': self._extract_high_value_targets(results)
            }
        }
        
        # Generate all three formats
        json_path = self._generate_json(report_data)
        txt_path = self._generate_txt(report_data)
        html_path = self._generate_html(report_data)
        
        # FIXED: Use correct logger format (component, message, data)
        logger.info("REPORT", "Reports generated", {
            "json": json_path.name,
            "txt": txt_path.name,
            "html": html_path.name
        })
        
        return {
            'json': str(json_path),
            'txt': str(txt_path),
            'html': str(html_path),
            'data': report_data
        }
    
    def _generate_json(self, data: Dict) -> Path:
        """Generate JSON report"""
        filepath = Path(f"{self.current_report_base}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return filepath
    
    def _generate_txt(self, data: Dict) -> Path:
        """Generate TXT report"""
        filepath = Path(f"{self.current_report_base}.txt")
        
        lines = []
        lines.append("=" * 80)
        lines.append(" " * 20 + "SQLMAP SKYNET v1.0.0 - SQLMAP SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Scan Info
        info = data['scan_info']
        lines.append("[SCAN INFORMATION]")
        lines.append("-" * 80)
        lines.append(f"Session ID:     {info['session_id']}")
        lines.append(f"Target URL:     {info['target_url']}")
        lines.append(f"Date/Time:      {info['date']}")
        lines.append(f"Duration:       {info['duration']}")
        lines.append(f"HTTP Method:    {info['method']}")
        lines.append(f"Backend:        {info['backend']}")
        lines.append(f"Status:         {info['status']}")
        lines.append("")
        
        # Findings Summary
        findings = data['findings']
        lines.append("[FINDINGS SUMMARY]")
        lines.append("-" * 80)
        lines.append(f"SQL Injection:  {'FOUND ✓' if findings['injection_found'] else 'NOT FOUND ✗'}")
        lines.append(f"WAF Detected:   {findings['waf_detected'] if findings['waf_detected'] else 'None'}")
        lines.append(f"Techniques:     {', '.join(findings['techniques']) if findings['techniques'] else 'N/A'}")
        lines.append(f"Total DBs:      {findings['total_databases']}")
        lines.append(f"Total Tables:   {findings['total_tables']}")
        lines.append(f"Total Columns:  {findings['total_columns']}")
        lines.append("")
        
        # Detailed Results
        lines.append("[DETAILED RESULTS]")
        lines.append("-" * 80)
        
        if findings['databases']:
            lines.append("")
            lines.append("DATABASES:")
            for i, db in enumerate(findings['databases'], 1):
                lines.append(f"  [{i}] {db}")
            
            lines.append("")
            lines.append("TABLES:")
            for db, tables in findings['tables'].items():
                lines.append(f"  Database: {db}")
                for table in tables:
                    lines.append(f"    └─ {table}")
            
            lines.append("")
            lines.append("COLUMNS:")
            for key, columns in findings['columns'].items():
                db, table = key.split('.', 1)
                lines.append(f"  {db}.{table}:")
                for col in columns:
                    col_type = col.get('type', 'UNKNOWN')
                    lines.append(f"    └─ {col['name']} ({col_type})")
        else:
            lines.append("  No databases enumerated")
        
        lines.append("")
        
        # High Value Targets
        if data['metadata']['high_value_targets']:
            lines.append("[HIGH VALUE TARGETS DETECTED]")
            lines.append("-" * 80)
            for target in data['metadata']['high_value_targets']:
                lines.append(f"  ⚠️  {target['location']} -> {target['column']} ({target['category']})")
            lines.append("")
        
        # Commands Executed
        if data['commands']:
            lines.append("[COMMANDS EXECUTED]")
            lines.append("-" * 80)
            for i, cmd_info in enumerate(data['commands'], 1):
                lines.append(f"\\nCommand #{i}:")
                lines.append(f"  Phase:    {cmd_info.get('phase', 'unknown')}")
                lines.append(f"  Cycle:    {cmd_info.get('cycle', 'N/A')}")
                lines.append(f"  Command:  {cmd_info.get('command', 'N/A')}")
                if cmd_info.get('ai_recommendation'):
                    lines.append(f"  AI Rec:   {cmd_info['ai_recommendation']}")
            lines.append("")
        
        # AI Analysis
        ai = data['ai_analysis']
        lines.append("[AI ANALYSIS]")
        lines.append("-" * 80)
        lines.append(f"Ollama Used:            {'Yes' if ai['ollama_used'] else 'No'}")
        lines.append(f"Web Searches:           {ai['web_searches']}")
        lines.append(f"Autonomous Cycles:      {ai['cycles']}")
        if ai['ollama_recommendations']:
            lines.append(f"AI Recommendations:     {ai['ollama_recommendations']}")
        lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        
        return filepath
    
    def _generate_html(self, data: Dict) -> Path:
        """Generate professional HTML report with cyberpunk styling"""
        filepath = Path(f"{self.current_report_base}.html")
        
        info = data['scan_info']
        findings = data['findings']
        
        # Build databases section
        dbs_html = ""
        if findings['databases']:
            for db in findings['databases']:
                tables = findings['tables'].get(db, [])
                table_count = len(tables)
                dbs_html += f'<div class="database-item"><div class="db-header"><span class="db-icon">🗄️</span><span class="db-name">{db}</span><span class="db-stats">{table_count} tables</span></div></div>'
        else:
            dbs_html = '<div class="empty-state">No databases found</div>'
        
        # Build tables section
        tables_html = ""
        if findings['tables']:
            for db, tables in findings['tables'].items():
                for table in tables:
                    col_key = f"{db}.{table}"
                    columns = findings['columns'].get(col_key, [])
                    col_count = len(columns)
                    
                    cols_list = ""
                    if columns:
                        cols_list = '<div class="columns-grid">'
                        for col in columns:
                            col_class = "high-value" if self._is_high_value_column(col['name']) else ""
                            cols_list += f'<span class="column-tag {col_class}">{col["name"]} <small>({col.get("type", "?")})</small></span>'
                        cols_list += "</div>"
                    
                    tables_html += f'<div class="table-card"><div class="table-header"><span class="table-name">{db}.{table}</span><span class="column-count">{col_count} columns</span></div>{cols_list}</div>'
        else:
            tables_html = '<div class="empty-state">No tables enumerated</div>'
        
        # Build commands section
        commands_html = ""
        if data['commands']:
            for i, cmd in enumerate(data['commands'], 1):
                ai_badge = '<span class="ai-badge">🤖 AI</span>' if cmd.get('ai_recommendation') else ''
                commands_html += f'<div class="command-item"><div class="command-header"><span class="cmd-number">#{i}</span><span class="cmd-phase">{cmd.get("phase", "unknown").upper()}</span><span class="cmd-cycle">Cycle {cmd.get("cycle", "N/A")}</span>{ai_badge}</div><code class="command-code">{cmd.get("command", "N/A")}</code></div>'
        else:
            commands_html = '<div class="empty-state">No commands logged</div>'
        
        # High value targets
        hv_html = ""
        if data['metadata']['high_value_targets']:
            for target in data['metadata']['high_value_targets']:
                hv_html += f'<div class="hv-item"><span class="hv-category">{target["category"]}</span><span class="hv-location">{target["location"]}</span><span class="hv-column">{target["column"]}</span></div>'
        
        # Build HTML with proper escaping
        html_parts = []
        html_parts.append('<!DOCTYPE html>')
        html_parts.append('<html lang="en">')
        html_parts.append('<head>')
        html_parts.append('    <meta charset="UTF-8">')
        html_parts.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_parts.append(f'    <title>SKYNET Report | {info["target_url"][:50]}</title>')
        html_parts.append('    <style>')
        html_parts.append('        :root { --neon-cyan: #00f3ff; --neon-green: #00ff9d; --neon-pink: #ff00ff; --dark-bg: #0a0a0f; --panel-bg: #111118; --border-color: #1a1a2e; --text-primary: #e0e0e0; --text-secondary: #888; --success: #00ff9d; --danger: #ff0044; }')
        html_parts.append('        * { margin: 0; padding: 0; box-sizing: border-box; }')
        html_parts.append('        body { font-family: "Segoe UI", Roboto, monospace; background: var(--dark-bg); color: var(--text-primary); line-height: 1.6; min-height: 100vh; }')
        html_parts.append('        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }')
        html_parts.append('        .header { background: linear-gradient(135deg, var(--panel-bg) 0%, #1a1a2e 100%); border: 1px solid var(--border-color); border-radius: 12px; padding: 30px; margin-bottom: 30px; position: relative; overflow: hidden; }')
        html_parts.append('        .header::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--neon-cyan), var(--neon-green), var(--neon-pink)); }')
        html_parts.append('        .header h1 { font-size: 2.5em; background: linear-gradient(90deg, var(--neon-cyan), var(--neon-green)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }')
        html_parts.append('        .header-meta { display: flex; gap: 30px; flex-wrap: wrap; margin-top: 20px; }')
        html_parts.append('        .meta-item { display: flex; flex-direction: column; }')
        html_parts.append('        .meta-label { font-size: 0.8em; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }')
        html_parts.append('        .meta-value { font-size: 1.1em; color: var(--neon-cyan); font-weight: 600; }')
        html_parts.append('        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }')
        html_parts.append('        .stat-card { background: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; text-align: center; }')
        html_parts.append('        .stat-value { font-size: 2.5em; font-weight: bold; color: var(--neon-green); }')
        html_parts.append('        .stat-label { color: var(--text-secondary); margin-top: 5px; }')
        html_parts.append('        .section { background: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }')
        html_parts.append('        .section-header { background: linear-gradient(90deg, rgba(0,243,255,0.1), transparent); padding: 15px 20px; border-bottom: 1px solid var(--border-color); }')
        html_parts.append('        .section-header h2 { color: var(--neon-cyan); font-size: 1.2em; }')
        html_parts.append('        .section-content { padding: 20px; }')
        html_parts.append('        .database-item { background: rgba(0, 243, 255, 0.05); border-left: 3px solid var(--neon-cyan); padding: 15px; margin-bottom: 10px; border-radius: 0 8px 8px 0; }')
        html_parts.append('        .db-header { display: flex; align-items: center; gap: 10px; }')
        html_parts.append('        .db-name { font-weight: bold; color: var(--neon-cyan); font-size: 1.1em; }')
        html_parts.append('        .db-stats { margin-left: auto; background: rgba(0, 243, 255, 0.2); padding: 4px 12px; border-radius: 20px; font-size: 0.9em; }')
        html_parts.append('        .table-card { background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; margin-bottom: 15px; }')
        html_parts.append('        .table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); }')
        html_parts.append('        .table-name { font-family: monospace; color: var(--neon-green); font-size: 1.1em; }')
        html_parts.append('        .column-count { background: rgba(0, 255, 157, 0.2); color: var(--neon-green); padding: 4px 12px; border-radius: 20px; font-size: 0.85em; }')
        html_parts.append('        .columns-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }')
        html_parts.append('        .column-tag { background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-color); padding: 6px 12px; border-radius: 6px; font-family: monospace; font-size: 0.9em; }')
        html_parts.append('        .column-tag.high-value { background: rgba(255, 0, 68, 0.2); border-color: var(--danger); color: var(--danger); }')
        html_parts.append('        .command-item { background: rgba(0, 0, 0, 0.3); border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; margin-bottom: 15px; }')
        html_parts.append('        .command-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }')
        html_parts.append('        .cmd-number { background: var(--neon-cyan); color: var(--dark-bg); padding: 4px 10px; border-radius: 4px; font-weight: bold; }')
        html_parts.append('        .hv-item { display: flex; align-items: center; gap: 15px; padding: 12px; background: rgba(255, 0, 68, 0.1); border: 1px solid var(--danger); border-radius: 8px; margin-bottom: 10px; }')
        html_parts.append('        .hv-category { background: var(--danger); color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }')
        html_parts.append('        .footer { text-align: center; padding: 30px; color: var(--text-secondary); border-top: 1px solid var(--border-color); margin-top: 30px; }')
        html_parts.append('    </style>')
        html_parts.append('</head>')
        html_parts.append('<body>')
        html_parts.append('    <div class="container">')
        html_parts.append('        <header class="header">')
        html_parts.append('            <h1>⚡ SQLMAP SKYNET v1.0.0</h1>')
        html_parts.append('            <p style="color: var(--text-secondary);">Developed by DRCrypter.ru</p>')
        html_parts.append('            <div class="header-meta">')
        html_parts.append(f'                <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{info["target_url"]}</span></div>')
        html_parts.append(f'                <div class="meta-item"><span class="meta-label">Session ID</span><span class="meta-value">{info["session_id"]}</span></div>')
        html_parts.append(f'                <div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">{info["date"]}</span></div>')
        html_parts.append(f'                <div class="meta-item"><span class="meta-label">Status</span><span class="meta-value" style="color: {"var(--success)" if findings["injection_found"] else "var(--danger)"};">{"✓ VULNERABLE" if findings["injection_found"] else "✗ NOT VULNERABLE"}</span></div>')
        html_parts.append('            </div>')
        html_parts.append('        </header>')
        html_parts.append('        <div class="stats-grid">')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{findings["total_databases"]}</div><div class="stat-label">Databases</div></div>')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{findings["total_tables"]}</div><div class="stat-label">Tables</div></div>')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{findings["total_columns"]}</div><div class="stat-label">Columns</div></div>')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{len(data["commands"])}</div><div class="stat-label">Commands</div></div>')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{data["ai_analysis"]["cycles"]}</div><div class="stat-label">AI Cycles</div></div>')
        html_parts.append(f'            <div class="stat-card"><div class="stat-value">{info["duration"]}</div><div class="stat-label">Duration</div></div>')
        html_parts.append('        </div>')
        html_parts.append('        <div class="section"><div class="section-header"><h2>🗄️ Databases Discovered</h2></div><div class="section-content">' + dbs_html + '</div></div>')
        html_parts.append('        <div class="section"><div class="section-header"><h2>📋 Tables & Columns</h2></div><div class="section-content">' + tables_html + '</div></div>')
        
        if data['metadata']['high_value_targets']:
            html_parts.append('        <div class="section"><div class="section-header"><h2>🎯 High Value Targets</h2></div><div class="section-content">' + hv_html + '</div></div>')
        
        html_parts.append('        <div class="section"><div class="section-header"><h2>⚙️ Commands Executed</h2></div><div class="section-content">' + commands_html + '</div></div>')
        html_parts.append('        <footer class="footer"><p>Generated by SQLMAP SKYNET v1.0.0 | SQLMap Automation Framework</p><p style="margin-top: 10px; font-size: 0.9em;">Report ID: ' + info['session_id'] + ' | ' + info['date'] + '</p></footer>')
        html_parts.append('    </div>')
        html_parts.append('</body>')
        html_parts.append('</html>')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html_parts))

        
        return filepath
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize string for use in filename"""
        invalid_chars = '<>:\"/\\\\|?*'
        for char in invalid_chars:
            name = name.replace(char, '_')
        return name[:50]
    
    def _is_high_value_column(self, col_name: str) -> bool:
        """Check if column name contains high-value keywords"""
        high_value_keywords = ['password', 'passwd', 'pass', 'pwd', 'hash', 'salt', 'email', 'mail', 'user', 'username', 'login', 'admin', 'root', 'token', 'api_key', 'secret', 'credit', 'card', 'cvv', 'ssn', 'phone']
        col_lower = col_name.lower()
        return any(keyword in col_lower for keyword in high_value_keywords)
    
    def _extract_high_value_targets(self, results: Dict) -> List[Dict]:
        """Extract high-value columns from results"""
        targets = []
        high_value_keywords = [('password', 'credentials'), ('passwd', 'credentials'), ('pass', 'credentials'), ('pwd', 'credentials'), ('hash', 'credentials'), ('salt', 'credentials'), ('email', 'personal'), ('mail', 'personal'), ('user', 'personal'), ('admin', 'admin'), ('root', 'admin'), ('token', 'security'), ('api_key', 'security'), ('secret', 'security'), ('credit', 'financial'), ('card', 'financial'), ('cvv', 'financial'), ('ssn', 'personal')]
        
        for key, columns in results.get('columns', {}).items():
            db, table = key.split('.', 1)
            for col in columns:
                col_name = col['name'].lower()
                for keyword, category in high_value_keywords:
                    if keyword in col_name:
                        targets.append({'location': f"{db}.{table}", 'column': col['name'], 'category': category.upper()})
                        break
        return targets

 
report_generator = SQLMapReportGenerator()