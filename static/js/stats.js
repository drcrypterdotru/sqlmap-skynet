// static/js/stats.js - Cleaned & Fixed
class StatsManager {
    constructor() {
        this.stats = {
            cycles: 0,
            databases: 0,
            tables: 0,
            targets: 0,
            columns: 0,
            running: false,
            progress: 0
        };
        this.pollInterval = null;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.seenHits = new Set(); // Track target hits
    }

    startPolling() {
        // Try WebSocket first, fallback to polling
        this.connectWebSocket();
        this.pollInterval = setInterval(() => this.fetchStats(), 2000);
        console.log('[StatsManager] Started');
    }

    connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('[StatsManager] WS Connected');
                this.reconnectAttempts = 0;
            };
            
            this.ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    this.handleWebSocketUpdate(msg);
                } catch (e) {
                    console.error('[StatsManager] Parse Error:', e);
                }
            };
            
            this.ws.onclose = () => {
                if (this.reconnectAttempts < this.maxReconnectAttempts) {
                    setTimeout(() => this.connectWebSocket(), 3000);
                    this.reconnectAttempts++;
                }
            };
            
            this.ws.onerror = (err) => {
                console.error('[StatsManager] WS Error:', err);
            };
            
        } catch (error) {
            console.error('[StatsManager] Connection failed:', error);
        }
    }

    async fetchStats() {
        try {
            const response = await fetch('/api/stats');
            
            // Handle 404 specifically
            if (response.status === 404) {
                console.warn('[StatsManager] /api/stats not found - backend may not have this endpoint');
                return;
            }
            
            if (!response.ok) {
                console.warn('[StatsManager] HTTP', response.status);
                return;
            }
            
            const data = await response.json();
            this.updateDisplay(data);
            
        } catch (error) {
            // Silent fail - don't spam console
            if (error.message.includes('Failed to fetch')) {
                console.warn('[StatsManager] Backend unreachable');
            }
        }
    }

    updateDisplay(data) {
        // Update all metrics with fallback to 0
        this.setText('stat-cycles', data.cycles ?? data.cycle ?? 0);
        this.setText('stat-dbs', data.databases ?? data.db_count ?? 0);
        this.setText('stat-tables', data.tables ?? data.table_count ?? 0);
        this.setText('stat-columns', data.columns ?? data.column_count ?? 0);
        this.setText('stat-targets', data.targets ?? data.target_count ?? 1);
        
        // Progress bar
        const progress = data.progress ?? 0;
        const bar = document.getElementById('progress-bar');
        if (bar) {
            bar.style.width = `${Math.min(100, progress)}%`;
        }
        
        // LIVE badge
        const running = data.running || (data.status === 'RUNNING');
        this.updateLiveBadge(running);
        
        // Target hits (if provided by API)
        if (data.target_hits && Array.isArray(data.target_hits)) {
            data.target_hits.forEach(hit => this.addTargetHit(hit));
        }
        
        // Store current state
        this.stats = { ...this.stats, ...data };
    }

    setText(elementId, value) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const newValue = String(value);
        if (element.textContent === newValue) return;
        
        element.textContent = newValue;
        
        // Flash animation
        element.style.transform = 'scale(1.3)';
        element.style.color = '#ffff00';
        element.style.transition = 'all 0.2s';
        
        setTimeout(() => {
            element.style.transform = 'scale(1)';
            element.style.color = '';
        }, 200);
    }

    updateLiveBadge(running) {
        const badge = document.getElementById('live-badge') || document.querySelector('.panel-badge');
        if (!badge) return;
        
        if (running) {
            badge.textContent = 'LIVE';
            badge.style.background = '#00ff88';
            badge.style.color = '#000';
            badge.style.boxShadow = '0 0 10px #00ff88';
            badge.style.animation = 'pulse 2s infinite';
        } else {
            badge.textContent = 'IDLE';
            badge.style.background = '#666';
            badge.style.color = '#fff';
            badge.style.boxShadow = 'none';
            badge.style.animation = 'none';
        }
    }

    addTargetHit(hit) {
        const hitId = `${hit.location || hit.db}.${hit.column}`;
        if (this.seenHits.has(hitId)) return;
        this.seenHits.add(hitId);
        
        const container = document.getElementById('target-hits');
        if (!container) return;
        
        // Remove empty state if exists
        const emptyState = container.querySelector('.empty-state');
        if (emptyState) emptyState.remove();
        
        const div = document.createElement('div');
        div.className = 'target-hit';
        div.innerHTML = `
            <span class="target-icon">🎯</span>
            <span class="target-path">${hitId}</span>
            <span class="target-keywords">${(hit.keywords || []).slice(0, 2).join(', ')}</span>
        `;
        
        container.insertBefore(div, container.firstChild);
        
        // Update hit count badge
        const hitBadge = document.getElementById('target-badge');
        if (hitBadge) {
            hitBadge.textContent = `${this.seenHits.size} HITS`;
        }
    }

    handleWebSocketUpdate(msg) {
        switch(msg.type) {
            case 'status':
                const p = msg.payload || {};
                this.updateDisplay({
                    cycles: p.cycle ?? p.cycles,
                    databases: p.db_count,
                    tables: p.table_count,
                    columns: p.column_count,
                    targets: p.target_count ?? 1,
                    progress: p.progress,
                    running: p.status === 'RUNNING' || p.status === 'SCANNING' || p.status === 'ENUMERATING',
                    status: p.status
                });
                break;
                
            case 'finding':
                // Handle real-time findings
                if (msg.payload?.type === 'DATABASE') {
                    this.stats.databases++;
                    this.setText('stat-dbs', this.stats.databases);
                } else if (msg.payload?.type === 'TABLES') {
                    this.stats.tables++;
                    this.setText('stat-tables', this.stats.tables);
                } else if (msg.payload?.type === 'COLUMN') {
                    this.stats.columns++;
                    this.setText('stat-columns', this.stats.columns);
                }
                break;
                
            case 'targeting':
                // Handle target keyword hits
                if (msg.payload?.type === 'TARGET_KEYWORD_HIT' || msg.payload?.type === 'HIGH_VALUE_FOUND') {
                    this.addTargetHit({
                        location: msg.payload.detail,
                        column: msg.payload.detail?.split('.').pop(),
                        keywords: msg.payload.keywords || ['target']
                    });
                }
                break;
        }
    }

    stop() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

if (msg.type === 'targeting') {
    if (msg.payload.type === 'TARGET_KEYWORD_HIT') {
        // Highlight in UI
        const hit = msg.payload;
        console.log(`🎯 Target hit: ${hit.detail}`);
        
        // Add to a "Target Hits" panel
        const targetPanel = document.getElementById('target-hits');
        if (targetPanel) {
            const div = document.createElement('div');
            div.className = 'target-hit';
            div.innerHTML = `
                <span class="target-icon">🎯</span>
                <span class="target-path">${hit.detail}</span>
                <span class="target-keywords">${hit.keywords.join(', ')}</span>
            `;
            targetPanel.appendChild(div);
        }
    }
}

// Initialize only once
const statsManager = new StatsManager();

// Wait for DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => statsManager.startPolling());
} else {
    statsManager.startPolling();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => statsManager.stop());