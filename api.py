from flask import Flask, jsonify, render_template
from flask_cors import CORS
from core.state_manager import state

# Your existing app initialization
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
#https://stackoverflow.com/questions/13317536/get-list-of-all-routes-defined-in-the-flask-app
#https://www.geeksforgeeks.org/python/flask-app-routing/
# ADD THIS ROUTE - Must be before app.run()
@app.route('/api/stats')
def get_stats():
    """Return current enumeration stats - FIXES 404 ERROR"""
    try:
        runner = getattr(state, 'current_runner', None)
        
        if runner and hasattr(runner, 'results'):
            # Calculate counts from actual data
            db_count = len(runner.results.get('databases', []))
            table_count = sum(len(tables) for tables in runner.results.get('tables', {}).values())
            column_count = sum(len(cols) for cols in runner.results.get('columns', {}).values())
            
            # Calculate target keyword hits
            target_hits = []
            from config import HIGH_VALUE_COLUMNS
            
            for key, columns in runner.results.get('columns', {}).items():
                for col in columns:
                    col_name = col['name'].lower()
                    matched = [kw for kw in HIGH_VALUE_COLUMNS if kw in col_name]
                    if matched:
                        target_hits.append({
                            'location': key,
                            'column': col['name'],
                            'type': col.get('type', 'UNKNOWN'),
                            'keywords': matched[:3]
                        })
            
            return jsonify({
                'cycles': runner.results.get('cycles', 0),
                'databases': db_count,
                'tables': table_count,
                'columns': column_count,
                'targets': len(runner.results.get('databases', [])),
                'target_hits_count': len(target_hits),
                'target_hits': target_hits[:20],
                'running': state.running,
                'status': 'RUNNING' if state.running else 'IDLE',
                'target': runner.results.get('target', '')[:50],
                'progress': min(100, (runner.results.get('cycles', 0) / 30) * 100),
                'max_cycles': 30
            }), 200
        
        # Return empty but valid response HTTP 200 only and not 404
        return jsonify({
            'cycles': 0,
            'databases': 0,
            'tables': 0,
            'columns': 0,
            'targets': 0,
            'target_hits_count': 0,
            'target_hits': [],
            'running': False,
            'status': 'IDLE',
            'target': '',
            'progress': 0,
            'max_cycles': 30
        }), 200
        
    except Exception as e:
        # Log error but still return valid JSON
        print(f"[API Stats Error] {e}")
        return jsonify({
            'error': str(e),
            'cycles': 0, 'databases': 0, 'tables': 0, 'columns': 0,
            'running': False, 'status': 'ERROR'
        }), 500

@app.route('/')
def index():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)