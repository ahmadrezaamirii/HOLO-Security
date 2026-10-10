let attackTypeChart = null;
let attackTimeChart = null;
let refreshInterval = null;

const chartPalette = ['#ef4444', '#f59e0b', '#3b82f6', '#22c55e', '#8b5cf6', '#22d3ee'];

function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    loadDashboardData();
    refreshInterval = setInterval(loadDashboardData, 5000);

    const username = sessionStorage.getItem('username') || 'Admin';
    const usernameDisplay = document.getElementById('usernameDisplay');
    if (usernameDisplay) {
        usernameDisplay.textContent = username;
    }
});

function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function initializeCharts() {
    const chartDefaults = {
        color: '#8fa2b4',
        font: {
            family: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
        }
    };

    if (window.Chart) {
        Chart.defaults.color = chartDefaults.color;
        Chart.defaults.font = chartDefaults.font;
    }

    const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');
    attackTypeChart = new Chart(attackTypeCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: chartPalette,
                borderColor: '#111820',
                borderWidth: 3,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '62%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 10,
                        boxHeight: 10,
                        usePointStyle: true
                    }
                }
            }
        }
    });

    const attackTimeCtx = document.getElementById('attackTimeChart').getContext('2d');
    attackTimeChart = new Chart(attackTimeCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                borderColor: '#22d3ee',
                backgroundColor: 'rgba(34, 211, 238, 0.12)',
                pointBackgroundColor: '#22d3ee',
                pointBorderColor: '#0b0f14',
                pointRadius: 4,
                tension: 0.35,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(143, 162, 180, 0.12)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 },
                    grid: { color: 'rgba(143, 162, 180, 0.12)' }
                }
            }
        }
    });
}

async function loadDashboardData() {
    try {
        const response = await fetch('/api/state');
        const data = await response.json();

        updateStats(data);
        updateAlertsTable(data.alerts || []);
        updateARPTable(data.arp_table || []);
        updateBlockedList(data.blocked_ips || [], data.blocked_macs || []);
        updateCharts(data.alerts || []);
    } catch (error) {
        console.error('Unable to load dashboard data:', error);
    }
}

function updateStats(data) {
    const alerts = data.alerts || [];
    const blockedIPs = data.blocked_ips || [];
    const blockedMACs = data.blocked_macs || [];
    const arpTable = data.arp_table || [];

    document.getElementById('totalAlerts').textContent = alerts.length;
    document.getElementById('blockedHosts').textContent = blockedIPs.length + blockedMACs.length;
    document.getElementById('networkDevices').textContent = arpTable.length;

    const recentAlerts = alerts.slice(-50);
    const criticalAlerts = recentAlerts.filter(alert =>
        ['ARP_SPOOF', 'IP_SPOOF', 'MAC_BLOCKED', 'SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'PORT_SCAN'].includes(alert.type)
    ).length;

    let threatLevel = 'LOW';
    if (criticalAlerts > 20) threatLevel = 'CRITICAL';
    else if (criticalAlerts > 10) threatLevel = 'HIGH';
    else if (criticalAlerts > 5) threatLevel = 'MEDIUM';

    const threatElement = document.getElementById('threatLevel');
    const threatCard = document.getElementById('threatCard');
    threatElement.textContent = threatLevel;
    threatCard.className = `stat-card ${threatLevel === 'LOW' ? 'success' : threatLevel === 'MEDIUM' ? 'warning' : 'danger'}`;
}

function updateAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');

    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No security alerts detected.</td></tr>';
        return;
    }

    const recentAlerts = alerts.slice(-100).reverse();

    tbody.innerHTML = recentAlerts.map(alert => {
        const badgeClass = getBadgeClass(alert.type);
        const ip = alert.ip || 'N/A';
        const mac = alert.mac || 'N/A';

        return `
            <tr>
                <td>${escapeHTML(alert.time || alert.timestamp || '')}</td>
                <td><span class="badge ${badgeClass}">${escapeHTML(alert.type || 'UNKNOWN')}</span></td>
                <td><code>${escapeHTML(ip)}</code></td>
                <td><code>${escapeHTML(mac)}</code></td>
                <td>${escapeHTML(alert.dpid || 'N/A')}</td>
                <td>${escapeHTML(alert.reason || alert.action || '')}</td>
                <td>
                    ${ip !== 'N/A' || mac !== 'N/A' ? `
                        <button class="row-action" onclick="blockFromAlert('${escapeHTML(ip)}', '${escapeHTML(mac)}')">
                            <i class="fas fa-ban"></i> Block
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    }).join('');
}

function updateARPTable(arpTable) {
    const tbody = document.getElementById('arpTableBody');

    if (arpTable.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No ARP bindings available yet.</td></tr>';
        return;
    }

    tbody.innerHTML = arpTable.map(entry => {
        const ip = entry.ip || '';
        const mac = entry.mac || '';

        return `
            <tr>
                <td><code>${escapeHTML(ip)}</code></td>
                <td><code>${escapeHTML(mac)}</code></td>
                <td>${escapeHTML(entry.dpid || '')}</td>
                <td>
                    <button class="row-action" onclick="blockFromAlert('${escapeHTML(ip)}', '${escapeHTML(mac)}')">
                        <i class="fas fa-ban"></i> Block
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function updateBlockedList(blockedIPs, blockedMACs) {
    const ipsList = document.getElementById('blockedIPsList');
    const macsList = document.getElementById('blockedMACsList');

    if (blockedIPs.length === 0 && blockedMACs.length === 0) {
        ipsList.innerHTML = '<p class="empty-state">No blocked endpoints.</p>';
        macsList.innerHTML = '';
        return;
    }

    ipsList.innerHTML = blockedIPs.map(ip => `
        <div class="chip">
            <i class="fas fa-network-wired"></i>
            <span>IP ${escapeHTML(ip)}</span>
            <button onclick="unblockHost('${escapeHTML(ip)}', null)" title="Unblock IP">
                <i class="fas fa-xmark"></i>
            </button>
        </div>
    `).join('');

    macsList.innerHTML = blockedMACs.map(mac => `
        <div class="chip">
            <i class="fas fa-ethernet"></i>
            <span>MAC ${escapeHTML(mac)}</span>
            <button onclick="unblockHost(null, '${escapeHTML(mac)}')" title="Unblock MAC">
                <i class="fas fa-xmark"></i>
            </button>
        </div>
    `).join('');
}

function updateCharts(alerts) {
    const alertTypes = {};
    alerts.forEach(alert => {
        const type = alert.type || 'UNKNOWN';
        alertTypes[type] = (alertTypes[type] || 0) + 1;
    });

    const labels = Object.keys(alertTypes);
    attackTypeChart.data.labels = labels.length ? labels : ['No alerts'];
    attackTypeChart.data.datasets[0].data = labels.length ? Object.values(alertTypes) : [1];
    attackTypeChart.data.datasets[0].backgroundColor = labels.length ? chartPalette : ['#243241'];
    attackTypeChart.update();

    const timeData = {};
    alerts.slice(-100).forEach(alert => {
        const time = alert.time || alert.timestamp;
        if (time && time.length >= 13) {
            const hour = time.substring(11, 13);
            timeData[hour] = (timeData[hour] || 0) + 1;
        }
    });

    const hours = Object.keys(timeData).sort();
    attackTimeChart.data.labels = hours.length ? hours.map(hour => `${hour}:00`) : ['Now'];
    attackTimeChart.data.datasets[0].data = hours.length ? hours.map(hour => timeData[hour]) : [0];
    attackTimeChart.update();
}

function getBadgeClass(type) {
    if (['ARP_SPOOF', 'IP_SPOOF', 'MAC_BLOCKED', 'SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'PORT_SCAN'].includes(type)) {
        return 'badge-danger';
    }
    if (['MAC_MOVE', 'SPOOF', 'FLOOD_SUSPECTED'].includes(type)) {
        return 'badge-warning';
    }
    if (type === 'LOW' || type === 'RESOLVED') {
        return 'badge-success';
    }
    return 'badge-info';
}

async function blockHost() {
    const ip = document.getElementById('blockIP').value.trim();
    const mac = document.getElementById('blockMAC').value.trim();

    if (!ip && !mac) {
        alert('Enter at least one IP address or MAC address.');
        return;
    }

    if (ip && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
        alert('Enter a valid IPv4 address.');
        return;
    }

    if (mac && !/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
        alert('Enter a valid MAC address.');
        return;
    }

    showLoading();

    try {
        const response = await fetch('/api/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() },
            body: JSON.stringify({ ip, mac })
        });

        const data = await response.json();

        if (data.success) {
            alert('Endpoint blocked successfully.');
            document.getElementById('blockIP').value = '';
            document.getElementById('blockMAC').value = '';
            loadDashboardData();
        } else {
            alert(`Error: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        alert('Unable to reach the dashboard service.');
    } finally {
        hideLoading();
    }
}

function blockFromAlert(ip, mac) {
    if (ip && ip !== 'N/A') {
        document.getElementById('blockIP').value = ip;
    }
    if (mac && mac !== 'N/A') {
        document.getElementById('blockMAC').value = mac;
    }
    blockHost();
}

async function unblockHost(ip, mac) {
    if (!confirm('Unblock this endpoint?')) {
        return;
    }

    showLoading();

    try {
        const response = await fetch('/api/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() },
            body: JSON.stringify({ ip, mac })
        });

        const data = await response.json();

        if (data.success) {
            alert('Endpoint unblocked successfully.');
            loadDashboardData();
        } else {
            alert(`Error: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        alert('Unable to reach the dashboard service.');
    } finally {
        hideLoading();
    }
}

async function analyzeThreats() {
    showLoading();

    try {
        const response = await fetch('/api/ai/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() }
        });

        const data = await response.json();

        if (data.error) {
            alert(`Error: ${data.error}`);
            return;
        }

        displayAIAnalysis(data);
    } catch (error) {
        alert('Unable to run AI analysis.');
    } finally {
        hideLoading();
    }
}

function displayAIAnalysis(analysis) {
    const card = document.getElementById('aiAnalysisCard');
    const content = document.getElementById('aiAnalysisContent');

    const threatLevel = analysis.threat_level || 'LOW';
    const recommendations = analysis.recommendations || [];
    const patterns = analysis.patterns || {};
    const anomaly = analysis.anomaly_detection || { available: false, reason: 'No data.' };
    const comparison = analysis.method_comparison || null;

    const patternItems = Object.entries(patterns)
        .map(([type, count]) => `<li><strong>${escapeHTML(type)}</strong>: ${escapeHTML(count)} events</li>`)
        .join('') || '<li>No patterns detected in the current alert window.</li>';

    const recommendationItems = recommendations
        .map(rec => `<li>${escapeHTML(rec)}</li>`)
        .join('') || '<li>No immediate recommendations. Continue monitoring live telemetry.</li>';

    let anomalyBlock;
    if (!anomaly.available) {
        anomalyBlock = `<p class="empty-state">${escapeHTML(anomaly.reason || 'Not enough data yet.')}</p>`;
    } else {
        const rows = anomaly.hosts.slice(0, 8).map(h => `
            <li>
                <strong>${escapeHTML(h.mac)}</strong>
                — score ${escapeHTML(h.anomaly_score)}/100
                ${h.is_anomaly ? '<span class="threat-level high">ANOMALY</span>' : '<span class="threat-level low">normal</span>'}
                ${h.cold_start ? '<span class="threat-level low">cold start</span>' : ''}
            </li>
        `).join('');
        anomalyBlock = `
            <p style="opacity:.7; font-size:.85em; margin-bottom:6px;">
                Model: ${escapeHTML(anomaly.model)} · ${escapeHTML(anomaly.total_samples_learned)} sample(s) learned so far
            </p>
            <ul class="analysis-list">${rows}</ul>
        `;
    }

    let comparisonBlock = '';
    if (comparison) {
        const methods = [
            { key: 'rule_threshold', label: 'Rule Threshold' },
            { key: 'batch_isolation_forest', label: 'Batch IsolationForest' },
            { key: 'our_online_method', label: 'Our Online Method' },
        ];
        const allMacs = new Set();
        methods.forEach(m => {
            const res = comparison[m.key];
            if (res && res.available) {
                res.hosts.forEach(h => allMacs.add(h.mac));
            }
        });

        if (allMacs.size === 0) {
            comparisonBlock = `<p class="empty-state">Not enough data yet for a side-by-side comparison.</p>`;
        } else {
            const headerCells = methods.map(m => `<th>${escapeHTML(m.label)}</th>`).join('');
            const bodyRows = Array.from(allMacs).map(mac => {
                const cells = methods.map(m => {
                    const res = comparison[m.key];
                    if (!res || !res.available) return '<td>—</td>';
                    const host = res.hosts.find(h => h.mac === mac);
                    if (!host) return '<td>—</td>';
                    return `<td>${host.is_anomaly ? '<span class="threat-level high">flagged</span>' : '<span class="threat-level low">clear</span>'}</td>`;
                }).join('');
                return `<tr><td><strong>${escapeHTML(mac)}</strong></td>${cells}</tr>`;
            }).join('');
            comparisonBlock = `
                <p style="opacity:.7; font-size:.85em; margin-bottom:6px;">
                    Computed simultaneously on the same data, every check — real numbers, not placeholders.
                </p>
                <table class="comparison-table">
                    <thead><tr><th>Host</th>${headerCells}</tr></thead>
                    <tbody>${bodyRows}</tbody>
                </table>
            `;
        }
    }

    content.innerHTML = `
        <div class="ai-analysis">
            <div class="analysis-grid">
                <div>
                    <p class="eyebrow">Current Risk</p>
                    <span class="threat-level ${threatLevel.toLowerCase()}">${escapeHTML(threatLevel)}</span>
                </div>
                <div>
                    <p class="eyebrow">Detected Patterns</p>
                    <ul class="analysis-list">${patternItems}</ul>
                </div>
                <div>
                    <p class="eyebrow">ML Anomaly Detection</p>
                    ${anomalyBlock}
                </div>
                <div>
                    <p class="eyebrow">Recommendations</p>
                    <ul class="analysis-list">${recommendationItems}</ul>
                </div>
            </div>
            <div style="margin-top:16px;">
                <p class="eyebrow">Method Comparison</p>
                ${comparisonBlock}
            </div>
        </div>
    `;

    card.hidden = false;
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function resetOnlineModel() {
    if (!confirm('Reset the online anomaly model to cold start? Everything it has learned so far will be discarded.')) {
        return;
    }
    showLoading();
    try {
        const response = await fetch('/api/ai/reset-model', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() }
        });
        const data = await response.json();
        if (data.success) {
            alert('Online model reset to cold start.');
        } else {
            alert(`Error: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        alert('Unable to reach the dashboard service.');
    } finally {
        hideLoading();
    }
}

function exportReport(format) {
    showLoading();
    window.location.href = format === 'pdf' ? '/api/export/pdf' : '/api/export/csv';
    setTimeout(hideLoading, 1200);
}

function refreshData() {
    loadDashboardData();
}

function showLoading() {
    document.getElementById('loadingOverlay').classList.add('show');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('show');
}
