// ================================================================
// AegisDNS Dashboard Ã¢â‚¬â€ app.js  (stable, professional)
// ================================================================

const API = '/api';
let currentView   = 'dashboard';
let currentDevice = '';   // IP string or '' for all
let myIp          = '';   // auto-detected client IP
let policyRules   = { allowed:[], denied:{}, device_allowed:{}, device_denied:{} };


function toggleSidebar() {
    const sidebar  = document.querySelector('.sidebar');
    const overlay  = document.getElementById('sidebar-overlay');
    const isOpen   = sidebar.classList.toggle('open');
    overlay && overlay.classList.toggle('active', isOpen);
}


document.addEventListener('DOMContentLoaded', async () => {
    setupNav();

    // 1. Detect our own IP first so we can auto-select our device
    try {
        const r = await fetch(`${API}/me`);
        const d = await r.json();
        if (d && d.ip) myIp = d.ip;
    } catch (_) {}

    // 2. Load device list
    await loadDevices();

    // 3. Auto-select our device by default
    if (myIp) {
        const sel = document.getElementById('device-selector');
        if (sel) {
            // Find matching option
            for (const opt of sel.options) {
                if (opt.value === myIp) { opt.selected = true; break; }
            }
            currentDevice = sel.value;
        }
    }

    // 4. Initial data load
    refreshView();
    setInterval(refreshView, 10000);

    // Device selector change
    document.getElementById('device-selector').addEventListener('change', e => {
        currentDevice = e.target.value;
        syncPolicyDeviceDrop();
        updateMyDeviceBanner();
        refreshView();
    });

    updateMyDeviceBanner();
});

// Ã¢â€â‚¬Ã¢â€â‚¬ My Device Banner Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function updateMyDeviceBanner() {
    const banner = document.getElementById('my-device-banner');
    const ipEl   = document.getElementById('my-device-ip');
    if (!banner) return;
    if (currentDevice && currentDevice === myIp) {
        banner.style.display = 'flex';
        if (ipEl) ipEl.textContent = myIp;
    } else if (!currentDevice && myIp) {
        // Showing all Ã¢â‚¬â€ still show a banner mentioning their device
        banner.style.display = 'none';
    } else {
        banner.style.display = 'none';
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Navigation Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function setupNav() {
    const titles = { dashboard:'Dashboard', policy:'Policy Rules', blocklists:'Blocklists', schedules:'Schedules', tools:'Tools', devices:'Devices', actions:'Automations' };
    document.querySelectorAll('[data-view]').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            const v = link.getAttribute('data-view');
            currentView = v;
            document.querySelectorAll('[data-view]').forEach(l =>
                l.classList.toggle('active', l.getAttribute('data-view') === v));
            document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
            const target = document.getElementById(`view-${v}`);
            if (target) target.classList.add('active');
            const t = document.getElementById('page-title');
            if (t) t.textContent = titles[v] || '';
            refreshView();
        });
    });
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Per-view refresh Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function refreshView() {
    if (currentView === 'dashboard') {
        loadStats(); loadTopDomains(); loadTopBlocked(); loadThreatStatus();
        loadSafeSearch(); loadBlocklistsDash();
    } else if (currentView === 'policy') {
        loadPolicy(); loadSchedules(); loadDevicesForDrops();
    } else if (currentView === 'blocklists') {
        loadBlocklistsPage();
    } else if (currentView === 'schedules') {
        // merged
    } else if (currentView === 'devices') {
        loadQuarantine(); loadDevices();
    } else if (currentView === 'actions') {
        loadActions(); loadActionLogs();
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function qs() { return currentDevice ? `?device_id=${encodeURIComponent(currentDevice)}` : ''; }
function fmt(n) { return (n || 0).toLocaleString(); }

function setText(id, v) {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
}

function setHtml(id, v) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = v || '<div class="empty-state">No data available.</div>';
}

function deviceLabel(ip) {
    if (!ip || !ip.trim()) return 'Unknown';
    if (ip === '127.0.0.1' || ip === '::1') return 'Server (localhost)';
    if (ip.startsWith('100.')) return ip;
    return ip;
}

function domainRow(domain, right, badgeHtml = '') {
    return `<div class="d-row">
      <div class="d-left">
        <img src="https://icon.horse/icon/${domain}" class="d-favicon" loading="lazy" onerror="this.style.display='none'">
        <span class="d-name" title="${domain}">${domain}</span>
        ${badgeHtml}
      </div>
      <div class="d-right">${right}</div>
    </div>`;
}

function showToast(msg, err = false) {
    const t = document.getElementById('_toast');
    if (!t) return;
    t.style.background = err ? '#dc2626' : '#059669';
    t.textContent = msg;
    t.style.opacity = '1';
    clearTimeout(t._tid);
    t._tid = setTimeout(() => { t.style.opacity = '0'; }, 3000);
}

function sanitize(v) {
    let d = (v || '').trim().toLowerCase();
    if (d.startsWith('https://')) d = d.slice(8);
    if (d.startsWith('http://'))  d = d.slice(7);
    d = d.split('/')[0].split('?')[0];
    if (d.startsWith('www.')) d = d.slice(4);
    return d;
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Device Selectors Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadDevices() {
    try {
        const r = await fetch(`${API}/devices`);
        const devices = await r.json() || [];
        populateDeviceSelects(devices);

        const devList = document.getElementById('list-devices-all');
        if (devList) {
            if (!devices.length) {
                devList.innerHTML = '<div class="empty-state">No devices found.</div>';
            } else {
                devList.innerHTML = devices.map(ip => {
                    const label = ip === myIp ? `${deviceLabel(ip)} (Your Device)` : deviceLabel(ip);
                    return `<div class="d-row">
                      <div class="d-left"><span class="d-name">${label}</span></div>
                      <div class="d-right">${ip}</div>
                    </div>`;
                }).join('');
            }
        }
    } catch (e) { console.error('loadDevices', e); }
}

async function loadDevicesForDrops() {
    try {
        const r = await fetch(`${API}/devices`);
        const devices = await r.json() || [];
        populateDeviceSelects(devices);
        syncPolicyDeviceDrop();
    } catch (e) { console.error('loadDevicesForDrops', e); }
}

function populateDeviceSelects(devices) {
    const topSel = document.getElementById('device-selector');
    const polSel = document.getElementById('policy-device');
    const schSel = document.getElementById('sched-device');

    const buildOpts = (includeAll = true) => {
        let h = includeAll ? '<option value="">All Devices</option>' : '<option value="">Global - All Devices</option>';
        devices.forEach(ip => {
            if (!ip || !ip.trim()) return;
            const label = ip === myIp ? `Your Device (${deviceLabel(ip)})` : deviceLabel(ip);
            h += `<option value="${ip}">${label}</option>`;
        });
        return h;
    };

    if (topSel) {
        const prev = topSel.value;
        topSel.innerHTML = buildOpts(true);
        // Restore previous or auto-select myIp
        if (myIp && !prev) {
            for (const opt of topSel.options) { if (opt.value === myIp) { opt.selected = true; break; } }
        } else if (prev) {
            topSel.value = prev;
        }
        currentDevice = topSel.value;
    }
    if (polSel) { const v = polSel.value; polSel.innerHTML = buildOpts(false); if (v) polSel.value = v; }
    if (schSel) { const v = schSel.value; schSel.innerHTML = buildOpts(false); if (v) schSel.value = v; }
}

function syncPolicyDeviceDrop() {
    const polSel = document.getElementById('policy-device');
    if (polSel && currentDevice) polSel.value = currentDevice;
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Stats Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
let chartTraffic = null;
let chartTech = null;
let chartDomains = null;

const chartColors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ef4444', '#ec4899', '#14b8a6', '#f97316'];

async function loadStats() {
    try {
        const r = await fetch(`${API}/stats${qs()}`);
        const d = await r.json() || {};
        setText('stat-queries', fmt(d.queries_today));
        setText('stat-blocked', fmt(d.blocked_today));
        const rate = (d.queries_today || 0) > 0
            ? ((d.blocked_today / d.queries_today) * 100).toFixed(1) + '%'
            : '0.0%';
        setText('stat-rate', rate);
        setText('stat-latency', (d.avg_latency_ms || 0).toFixed(1));
        
        // Render Traffic Chart
        const ctx = document.getElementById('chart-traffic');
        if (ctx) {
            if (chartTraffic) chartTraffic.destroy();
            if (d.queries_today > 0) {
                chartTraffic = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Allowed', 'Blocked'],
                        datasets: [{
                            data: [d.allowed_today || 0, d.blocked_today || 0],
                            backgroundColor: ['rgba(16, 185, 129, 0.9)', 'rgba(239, 68, 68, 0.9)'],
                            hoverBackgroundColor: ['#10b981', '#ef4444'],
                            borderWidth: 2,
                            borderColor: getComputedStyle(document.documentElement).getPropertyValue('--surface').trim() || '#fff',
                            borderRadius: 6,
                            hoverOffset: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        layout: { padding: { left: 10, right: 10, top: 10, bottom: 25 } },
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    color: '#a1a1aa',
                                    font: { family: 'Inter', size: 12, weight: '500' },
                                    usePointStyle: true,
                                    padding: 20
                                }
                            },
                            tooltip: {
                                backgroundColor: 'rgba(0,0,0,0.8)',
                                titleFont: { family: 'Inter', size: 13 },
                                bodyFont: { family: 'Inter', size: 13 },
                                padding: 10,
                                cornerRadius: 8
                            }
                        },
                        cutout: '75%'
                    }
                });
            } else {
                ctx.parentElement.innerHTML = '<div class="empty-state">No traffic yet.</div>';
            }
        }
    } catch (e) { console.error('loadStats', e); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Top Domains Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
function categorizeTechCompany(domain) {
    if (/google|youtube|doubleclick|android|1e100/i.test(domain)) return 'Google';
    if (/apple|icloud|aaplimg|mzstatic/i.test(domain)) return 'Apple';
    if (/microsoft|windows|bing|live|office/i.test(domain)) return 'Microsoft';
    if (/amazon|aws|cloudfront|alexa/i.test(domain)) return 'Amazon';
    if (/facebook|instagram|whatsapp|meta/i.test(domain)) return 'Meta';
    if (/cloudflare/i.test(domain)) return 'Cloudflare';
    if (/netflix/i.test(domain)) return 'Netflix';
    if (/github/i.test(domain)) return 'GitHub';
    return null;
}

async function loadTopDomains() {
    try {
        const r = await fetch(`${API}/top-domains${qs()}`);
        const data = await r.json() || [];
        
        const domCtx = document.getElementById('chart-domains');
        const techCtx = document.getElementById('chart-tech');
        
        if (!data.length) { 
            setHtml('list-top-domains', '<div class="empty-state">No queries recorded yet.</div>');
            if (domCtx) { if (chartDomains) chartDomains.destroy(); domCtx.parentElement.innerHTML = '<div class="empty-state">No data available.</div>'; }
            if (techCtx) { if (chartTech) chartTech.destroy(); techCtx.parentElement.innerHTML = '<div class="empty-state">No data available.</div>'; }
            return; 
        }
        
        setHtml('list-top-domains', data.map(d =>
            domainRow(d.domain, `<span class="d-count">${fmt(d.count)}</span>`)
        ).join(''));
        
        // Prepare Data for Domains Chart
        const top5 = data.slice(0, 5);
        if (domCtx) {
            if (chartDomains) chartDomains.destroy();
            chartDomains = new Chart(domCtx, {
                type: 'doughnut',
                data: {
                    labels: top5.map(d => d.domain.length > 20 ? d.domain.substring(0,20)+'...' : d.domain),
                    datasets: [{
                        data: top5.map(d => d.count),
                        backgroundColor: chartColors.map(c => c.replace(')', ', 0.85)').replace('rgb', 'rgba')),
                        hoverBackgroundColor: chartColors,
                        borderWidth: 2,
                        borderColor: getComputedStyle(document.documentElement).getPropertyValue('--surface').trim() || '#fff',
                        borderRadius: 4,
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    layout: { padding: { left: 10, right: 10, top: 10, bottom: 25 } },
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#a1a1aa',
                                font: { family: 'Inter', size: 11, weight: '500' },
                                usePointStyle: true,
                                padding: 15
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0,0,0,0.8)',
                            titleFont: { family: 'Inter', size: 13 },
                            bodyFont: { family: 'Inter', size: 13 },
                            padding: 10,
                            cornerRadius: 8
                        }
                    },
                    cutout: '60%'
                }
            });
        }
        
        // Prepare Data for Tech Chart
        const techCounts = {};
        for (const d of data) {
            const company = categorizeTechCompany(d.domain);
            if (company) {
                techCounts[company] = (techCounts[company] || 0) + d.count;
            }
        }
        const techSorted = Object.entries(techCounts).sort((a,b) => b[1] - a[1]).slice(0, 5);
        if (techCtx && techSorted.length > 0) {
            if (chartTech) chartTech.destroy();
            chartTech = new Chart(techCtx, {
                type: 'bar',
                data: {
                    labels: techSorted.map(t => t[0]),
                    datasets: [{
                        label: 'Queries',
                        data: techSorted.map(t => t[1]),
                        backgroundColor: 'rgba(59, 130, 246, 0.85)',
                        hoverBackgroundColor: '#3b82f6',
                        borderRadius: 6,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    layout: { padding: { top: 20, bottom: 0 } },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(0,0,0,0.8)',
                            titleFont: { family: 'Inter', size: 13 },
                            bodyFont: { family: 'Inter', size: 13 },
                            padding: 10,
                            cornerRadius: 8,
                            displayColors: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false },
                            ticks: { color: '#a1a1aa', font: { family: 'Inter', size: 11 } }
                        },
                        x: {
                            grid: { display: false, drawBorder: false },
                            ticks: { color: '#a1a1aa', font: { family: 'Inter', size: 11 } }
                        }
                    }
                }
            });
        } else if (techCtx) {
            if (chartTech) chartTech.destroy();
            techCtx.parentElement.innerHTML = '<div class="empty-state">Not enough company data.</div>';
        }
        
    } catch (e) { console.error('loadTopDomains', e); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Top Blocked Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadTopBlocked() {
    try {
        const r = await fetch(`${API}/top-blocked${qs()}`);
        const data = await r.json() || [];
        if (!data.length) { setHtml('list-top-blocked', '<div class="empty-state">No blocked queries yet.</div>'); return; }
        setHtml('list-top-blocked', data.map(d =>
            domainRow(d.domain, `<span class="d-count red">${fmt(d.count)}</span>`)
        ).join(''));
    } catch (e) { console.error('loadTopBlocked', e); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Threat Status Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadThreatStatus() {
    try {
        const r = await fetch(`${API}/threats`);
        const d = await r.json() || {};
        setText('stat-threats', fmt(d.live_threat_count));
        const updEl = document.getElementById('threat-updated');
        if (updEl) {
            if (d.last_updated) {
                updEl.textContent = 'Updated ' + new Date(parseInt(d.last_updated) * 1000).toLocaleTimeString();
            } else {
                updEl.textContent = 'Pending first refresh';
            }
        }
    } catch (e) { console.error('loadThreatStatus', e); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Safe Search Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadSafeSearch() {
    try {
        const r = await fetch(`${API}/safesearch`);
        const d = await r.json() || {};
        const toggle = document.getElementById('safesearch-toggle');
        const label  = document.getElementById('safesearch-label');
        if (toggle) toggle.checked = !!d.enabled;
        if (label)  label.textContent = d.enabled ? 'On' : 'Off';
    } catch (e) { console.error('loadSafeSearch', e); }
}

async function toggleSafeSearch() {
    const toggle = document.getElementById('safesearch-toggle');
    const label  = document.getElementById('safesearch-label');
    if (!toggle) return;
    try {
        const r = await fetch(`${API}/safesearch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: toggle.checked })
        });
        const d = await r.json();
        if (label) label.textContent = toggle.checked ? 'On' : 'Off';
        showToast(d.message || 'Safe search updated');
    } catch (e) {
        toggle.checked = !toggle.checked;
        showToast('Failed to toggle safe search', true);
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Blocklists Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadBlocklistsDash() {
    try {
        const r = await fetch(`${API}/lists`);
        const data = await r.json() || [];
        if (!data.length) { setHtml('list-blocklists-dash', '<div class="empty-state">No blocklists configured.</div>'); return; }
        setHtml('list-blocklists-dash', data.map(l => `
          <div class="d-row">
            <div class="d-left">
              <span class="d-name" title="${l.name}">${l.name}</span>
            </div>
            <div class="d-right">
              <span class="d-count">${fmt(l.rule_count)} rules</span>
              <button class="btn btn-ghost btn-sm" onclick="deleteBlocklist('${l.name.replace(/'/g, "\\'")}')" style="color:var(--red);padding:6px; margin-left:4px" title="Remove blocklist">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            </div>
          </div>`).join(''));
    } catch (e) { console.error('loadBlocklistsDash', e); }
}

async function addBlocklist() {
    const name = document.getElementById('bl-name').value.trim();
    const source_url = document.getElementById('bl-url').value.trim();
    if (!name || !source_url) return;
    try {
        const r = await fetch(`${API}/blocklists`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, source_url })
        });
        if (r.ok) {
            showToast(`Added blocklist: ${name}`);
            document.getElementById('bl-name').value = '';
            document.getElementById('bl-url').value = '';
            loadBlocklistsDash();
        } else {
            showToast('Failed to add blocklist', true);
        }
    } catch (e) { showToast('Error adding blocklist', true); }
}

async function deleteBlocklist(name) {
    if (!confirm(`Are you sure you want to remove blocklist: ${name}?`)) return;
    try {
        const r = await fetch(`${API}/blocklists/${encodeURIComponent(name)}`, {
            method: 'DELETE'
        });
        if (r.ok) {
            showToast(`Removed blocklist: ${name}`);
            loadBlocklistsDash();
        } else {
            showToast('Failed to remove blocklist', true);
        }
    } catch (e) { showToast('Error removing blocklist', true); }
}

async function loadBlocklistsPage() {
    try {
        const r = await fetch(`${API}/lists`);
        const data = await r.json() || [];
        const tbody = document.querySelector('#tbl-blocklists tbody');
        if (!tbody) return;
        if (!data.length) { tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No blocklists.</td></tr>'; return; }
        tbody.innerHTML = data.map(l => `
          <tr>
            <td>${l.name}</td>
            <td class="num">${fmt(l.rule_count)}</td>
          </tr>`).join('');
    } catch (e) { console.error('loadBlocklistsPage', e); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Policy Rules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadPolicy() {
    try {
        const r = await fetch(`${API}/policy`);
        policyRules = await r.json() || { allowed:[], denied:[], device_allowed:{}, device_denied:{} };
        renderPolicies();
    } catch (e) { console.error('loadPolicy', e); }
}

function renderPolicies() {
    const dev = currentDevice;
    
    // Create maps to track origin
    let allowedList = (policyRules.allowed || []).map(d => ({ domain: d, isGlobal: true }));
    let deniedList  = (policyRules.denied  || []).map(d => ({ domain: d, isGlobal: true }));

    if (dev) {
        // Add device-specific rules, overwriting global flags if they exist in both
        const devAllowed = (policyRules.device_allowed?.[dev] || []).map(d => ({ domain: d, isGlobal: false }));
        const devDenied  = (policyRules.device_denied?.[dev]  || []).map(d => ({ domain: d, isGlobal: false }));
        
        // Merge them, giving preference to device specific
        const merge = (globals, devices) => {
            const map = new Map();
            globals.forEach(x => map.set(x.domain, x));
            devices.forEach(x => map.set(x.domain, x));
            return Array.from(map.values());
        };
        
        allowedList = merge(allowedList, devAllowed);
        deniedList  = merge(deniedList, devDenied);
    }

    const makeList = (items, flipAction) => {
        if (!items.length) return '<div class="empty-state">No domains in this list.</div>';
        return items.map(item => {
            const badge = `<span class="badge ${item.isGlobal ? 'badge-gray' : 'badge-blue'}">${item.isGlobal ? 'Global' : 'Device'}</span>`;
            return domainRow(item.domain,
                `<div class="d-right">
                  <button class="btn btn-sm ${flipAction==='allow'?'btn-allow':'btn-deny'}"
                    onclick="submitPolicy('${flipAction}','${item.domain}')">${flipAction==='allow'?'Allow':'Deny'}</button>
                  <button class="btn btn-sm btn-ghost" onclick="removePolicy('${item.domain}', ${item.isGlobal})">Remove</button>
                </div>`,
                dev ? badge : ''
            );
        }).join('');
    };

    setHtml('list-allowed', makeList(allowedList, 'deny'));
    setHtml('list-denied',  makeList(deniedList,  'allow'));
}

async function submitPolicy(action, domainArg) {
    const input = document.getElementById('policy-input');
    const raw   = domainArg || (input ? input.value : '');
    const domain = sanitize(raw);
    if (!domain) return;

    const polSel = document.getElementById('policy-device');
    const device_id = polSel ? (polSel.value || null) : null;
    const body = { domain };
    if (device_id) body.device_id = device_id;

    try {
        const r = await fetch(`${API}/${action}`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message || `Updated policy for ${domain}`);
        if (input && !domainArg) input.value = '';
        loadPolicy();
    } catch (e) { showToast('Failed to update policy', true); }
}

async function removePolicy(domain, isGlobal = false) {
    const polSel = document.getElementById('policy-device');
    const device_id = polSel ? (polSel.value || null) : null;
    const body = { domain };
    
    // Only send device_id if it's NOT a global rule we're trying to remove
    if (device_id && !isGlobal) {
        body.device_id = device_id;
    }
    
    try {
        const r = await fetch(`${API}/policy/remove`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message || `Removed ${domain}`);
        loadPolicy();
    } catch (e) { showToast('Failed to remove policy', true); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Schedules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadSchedules() {
    try {
        const r = await fetch(`${API}/schedules`);
        const data = await r.json() || [];
        if (!data.length) { setHtml('list-schedules', '<div class="empty-state">No schedules configured.</div>'); return; }
        const dmap = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
        const html = data.map(s => {
            const sh = String(Math.floor(s.start_minutes/60)).padStart(2,'0');
            const sm = String(s.start_minutes%60).padStart(2,'0');
            const eh = String(Math.floor(s.end_minutes/60)).padStart(2,'0');
            const em = String(s.end_minutes%60).padStart(2,'0');
            const dstr = s.days.length===7 ? 'Every day' : s.days.map(d=>dmap[d]).join(', ');
            const isAllow = (s.action||'').toLowerCase() === 'allow';
            return `<div class="d-row sched-row">
              <div class="d-left block">
                <div style="display:flex;align-items:center;gap:.45rem;flex-wrap:wrap">
                  <span class="badge ${isAllow?'badge-green':'badge-red'}">${s.action}</span>
                  <strong style="font-size:.84rem">${s.domain}</strong>
                  ${s.device_id ? `<span class="badge badge-blue">${s.device_id}</span>` : '<span class="badge badge-gray">Global</span>'}
                </div>
                <div class="sched-meta">${sh}:${sm} Ã¢â‚¬â€œ ${eh}:${em} &nbsp;&middot;&nbsp; ${dstr}</div>
              </div>
              <div class="d-right">
                <label class="toggle" title="${s.enabled?'Disable':'Enable'}">
                  <input type="checkbox" ${s.enabled?'checked':''} onchange="toggleSchedule('${s.id}',this.checked)">
                  <span class="toggle-track"></span>
                </label>
                <button class="btn btn-sm btn-deny" onclick="deleteSchedule('${s.id}')">Delete</button>
              </div>
            </div>`;
        }).join('');
        setHtml('list-schedules', html);
    } catch (e) { console.error('loadSchedules', e); }
}

async function submitSchedule() {
    const domain = sanitize(document.getElementById('sched-domain').value);
    if (!domain) { showToast('Enter a domain', true); return; }
    const action = document.getElementById('sched-action').value;
    const device_id = document.getElementById('sched-device').value || null;
    const start  = document.getElementById('sched-start').value.split(':');
    const end    = document.getElementById('sched-end').value.split(':');
    const days   = [];
    document.querySelectorAll('input[name="sched-day"]:checked').forEach(cb => days.push(parseInt(cb.value)));
    if (!days.length) { showToast('Select at least one day', true); return; }
    const sh = start[0].padStart(2,'0'), sm = start[1].padStart(2,'0');
    const eh = end[0].padStart(2,'0'),   em = end[1].padStart(2,'0');
    const label = `${action.toUpperCase()} ${domain} (${sh}:${sm}Ã¢â‚¬â€œ${eh}:${em})`;
    const body  = { domain, action, days, start_hour:parseInt(sh), start_min:parseInt(sm), end_hour:parseInt(eh), end_min:parseInt(em), device_id, label };
    try {
        const r = await fetch(`${API}/schedules`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message || 'Schedule created');
        document.getElementById('sched-domain').value = '';
        loadSchedules();
    } catch (e) { showToast('Failed to create schedule', true); }
}

async function toggleSchedule(id, enabled) {
    try {
        await fetch(`${API}/schedules/${id}/toggle`, {
            method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({enabled})
        });
        loadSchedules();
    } catch (e) { showToast('Failed to toggle schedule', true); loadSchedules(); }
}

async function deleteSchedule(id) {
    if (!confirm('Delete this schedule?')) return;
    try {
        await fetch(`${API}/schedules/${id}`, {method:'DELETE'});
        showToast('Schedule deleted');
        loadSchedules();
    } catch (e) { showToast('Failed to delete', true); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Diagnostics Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function submitDiagnose() {
    const domain = sanitize(document.getElementById('diag-input').value);
    if (!domain) return;
    const el = document.getElementById('diag-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'AnalyzingÃ¢â‚¬Â¦';
    try {
        const r = await fetch(`${API}/diagnose`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})
        });
        const d = await r.json();
        const cls = d.policy_result === 'BLOCKED' ? 'result-blocked' : 'result-allowed';
        el.className = `result-box ${cls}`;
        el.innerHTML = [
            ['Domain', `<code>${d.domain}</code>`],
            ['Result', `<strong>${d.policy_result}</strong>`],
            ['Reason', d.reason],
            ['Source', d.source],
            ['Action', d.action_suggested],
        ].map(([k,v]) => `<div class="result-row"><span class="result-key">${k}</span><span class="result-val">${v}</span></div>`).join('');
    } catch (e) { el.className = 'result-box result-blocked'; el.textContent = 'Diagnostic failed.'; }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Risk Check Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function submitRiskCheck() {
    const domain = sanitize(document.getElementById('risk-input').value);
    if (!domain) return;
    const el = document.getElementById('risk-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'AnalyzingÃ¢â‚¬Â¦';
    try {
        const r = await fetch(`${API}/risk`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})
        });
        const d = await r.json();
        const cls = d.score >= 70 ? 'result-blocked' : d.score >= 40 ? 'result-warn' : 'result-allowed';
        const barColor = d.score >= 70 ? '#dc2626' : d.score >= 40 ? '#d97706' : '#059669';
        const factors  = (d.factors||[]).map(f=>`<li>${f}</li>`).join('');
        el.className = `result-box ${cls}`;
        el.innerHTML = `
          <div class="result-row"><span class="result-key">Domain</span><code class="result-val">${domain}</code></div>
          <div class="result-row"><span class="result-key">Score</span><span class="result-val"><strong>${d.score}/100</strong> &mdash; ${d.level}</span></div>
          <div style="margin:.5rem 0;height:5px;background:#e5e7eb;border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${d.score}%;background:${barColor};border-radius:3px"></div>
          </div>
          <ul style="margin:.4rem 0 0 1.1rem;font-size:.78rem;color:#6b7280">${factors}</ul>`;
    } catch (e) { el.className = 'result-box result-blocked'; el.textContent = 'Risk analysis failed.'; }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Fallback Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function submitFallback() {
    const domain = sanitize(document.getElementById('fallback-input').value);
    if (!domain) return;
    try {
        const r = await fetch(`${API}/fallback`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})
        });
        const d = await r.json();
        showToast(d.message || `Fallback enabled for ${domain}`);
        document.getElementById('fallback-input').value = '';
    } catch (e) { showToast('Failed to enable fallback', true); }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Data Management Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function deleteLogs() {
    const timeframe = document.getElementById('log-timeframe').value;
    const tfText = document.getElementById('log-timeframe').options[document.getElementById('log-timeframe').selectedIndex].text;
    
    if (!confirm(`Are you sure you want to delete ${tfText}? This action cannot be undone.`)) return;
    
    try {
        const r = await fetch(`${API}/logs`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timeframe })
        });
        const d = await r.json();
        if (d.success) {
            showToast(d.message);
            // Optionally reload stats if they are currently viewed
            loadStats();
        } else {
            showToast(d.message, true);
        }
    } catch (e) {
        showToast('Failed to delete logs', true);
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Devices & Quarantine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async function loadQuarantine() {
    try {
        const r = await fetch(`${API}/quarantine`);
        const data = await r.json() || [];
        const container = document.getElementById('list-quarantine');
        if (!container) return;
        if (!data.length) {
            container.innerHTML = '<div class="empty-state">No quarantined devices.</div>';
            return;
        }
        container.innerHTML = data.map(ip => {
            return `<div class="d-row">
              <div class="d-left">
                <span class="d-name">${ip}</span>
                <span class="badge badge-red">Quarantined</span>
              </div>
              <div class="d-right">
                <button class="btn btn-allow btn-sm" onclick="unquarantine('${ip}')">Unquarantine</button>
              </div>
            </div>`;
        }).join('');
    } catch (e) {
        console.error('loadQuarantine', e);
    }
}

async function unquarantine(ip) {
    try {
        await fetch(`${API}/quarantine/${ip}`, { method: 'DELETE' });
        showToast(`Unquarantined ${ip}`);
        loadQuarantine();
    } catch (e) {
        showToast(`Failed to unquarantine ${ip}`, true);
    }
}
// Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
// Custom Actions (Automations & Webhooks)
// Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

function toggleActionFields() {
  const type = document.getElementById('action-type').value;
  document.getElementById('action-fields-webhook').style.display = type === 'webhook' ? 'block' : 'none';
  document.getElementById('action-fields-shell').style.display = type === 'shell' ? 'block' : 'none';
  document.getElementById('action-fields-html').style.display = type === 'html' ? 'block' : 'none';
}

async function loadActions() {
  const el = document.getElementById('list-actions');
  try {
    const res = await fetch(`${API}/actions`);
    if (!res.ok) throw new Error('Failed to load actions');
    const actions = await res.json();
    if (actions.length === 0) {
      el.innerHTML = '<div class="empty-state">No custom actions active.</div>';
      return;
    }
    el.innerHTML = actions.map(a => `
      <div class="d-item" style="display:flex; align-items:center; justify-content:space-between; padding:12px">
        <div style="flex:1">
          <div style="font-weight:600; font-size:15px; color:var(--text)">${a.domain}</div>
          <div style="font-size:12px; color:var(--text-muted); margin-top:6px; display:flex; gap:8px; align-items:center">
            <span class="badge ${a.action_type === 'webhook' ? 'bg-blue' : a.action_type === 'shell' ? 'bg-red' : 'bg-green'}">${a.action_type.toUpperCase()}</span>
            ${a.token ? '<span style="color:var(--yellow); display:flex; align-items:center; gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Auth Required</span>' : ''}
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="deleteAction('${a.domain}')" title="Delete Action" style="padding:6px; color:var(--red)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>
    `).join('');
  } catch (err) {
    el.innerHTML = `<div class="empty-state" style="color:var(--red)">${err.message}</div>`;
  }
}

async function loadActionLogs() {
  const el = document.getElementById('list-action-logs');
  try {
    const res = await fetch(`${API}/actions/logs`);
    if (!res.ok) throw new Error('Failed to load logs');
    const logs = await res.json();
    if (logs.length === 0) {
      el.innerHTML = '<div class="empty-state">No executions logged yet.</div>';
      return;
    }
    el.innerHTML = logs.map(l => `
      <div class="d-item" style="padding:12px; border-bottom:1px solid var(--border)">
        <div style="flex:1">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px">
            <span style="font-weight:600; font-size:14px; color:var(--text)">${l.domain}</span>
            <span style="font-size:12px; color:var(--text-muted)">${new Date(l.triggered_at + 'Z').toLocaleString(undefined, {hour:'numeric', minute:'2-digit', second:'2-digit'})}</span>
          </div>
          <div style="font-size:13px; font-weight:500; display:flex; align-items:center; gap:6px; color:${l.outcome === 'success' ? 'var(--green)' : 'var(--red)'}">
            ${l.outcome === 'success' ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'}
            <span>${l.outcome.toUpperCase()}: <span style="color:var(--text-muted); font-weight:400">${l.detail || ''}</span></span>
          </div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    el.innerHTML = `<div class="empty-state" style="color:var(--red)">${err.message}</div>`;
  }
}

async function clearActionLogs() {
  if (!confirm('Are you sure you want to clear all execution logs?')) return;
  try {
    const res = await fetch(`${API}/actions/logs`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to clear logs');
    showToast('Execution logs cleared');
    loadActionLogs();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function submitAction() {
  const payload = {
    domain: document.getElementById('action-domain').value,
    action_type: document.getElementById('action-type').value,
    token: document.getElementById('action-token').value || null,
    success_msg: document.getElementById('action-success').value || null,
  };
  
  if (payload.action_type === 'webhook') {
    payload.method = document.getElementById('action-method').value;
    payload.payload_url = document.getElementById('action-url').value;
    if (!payload.payload_url) return showToast('Webhook URL is required', true);
  } else if (payload.action_type === 'shell') {
    payload.shell_command = document.getElementById('action-cmd').value;
    if (!payload.shell_command) return showToast('Shell command is required', true);
  } else if (payload.action_type === 'html') {
    payload.html_content = document.getElementById('action-html').value;
    if (!payload.html_content) return showToast('HTML content is required', true);
  }

  try {
    const res = await fetch(`${API}/actions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message);
      document.getElementById('form-action').reset();
      toggleActionFields();
      loadActions();
    } else {
      showToast(data.message, true);
    }
  } catch (e) {
    showToast(e.message, true);
  }
}

async function deleteAction(domain) {
  if (!confirm(`Delete action for ${domain}?`)) return;
  try {
    const res = await fetch(`${API}/actions/${encodeURIComponent(domain)}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      showToast(data.message);
      loadActions();
    } else {
      showToast(data.message, true);
    }
  } catch (e) {
    showToast(e.message, true);
  }
}

// Hook into view switching
const _origSwitchView = window.switchView || function(){};
window.switchView = function(viewId) {
  _origSwitchView(viewId);
  if (viewId === 'actions') {
    loadActions();
    loadActionLogs();
  }
};

function handleHtmlFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    document.getElementById('action-html').value = e.target.result;
    showToast(`Loaded ${file.name} successfully`);
  };
  reader.onerror = function() {
    showToast(`Failed to read ${file.name}`, true);
  };
  reader.readAsText(file);
}

