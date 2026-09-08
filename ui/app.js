// Encode every untrusted value at the HTML boundary. Use data attributes for event arguments.
function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('X-Aegis-Request', '1');
    const response = await window.fetch(url, {...options, headers, credentials:'same-origin'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if ((response.headers.get('content-type') || '').includes('application/json')) {
        const body = await response.clone().json();
        if (body && body.success === false) throw new Error(body.message || 'Request failed');
    }
    return response;
}
document.addEventListener('contextmenu', event => {
    const row = event.target.closest('[data-domain]');
    if (row) {event.preventDefault();openCtxMenu(event,row.dataset.domain);}
});

// ================================================================
// AegisDNS Dashboard — app.js
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
    document.body.classList.toggle('drawer-open', isOpen);
    document.getElementById('hamburger-btn')?.setAttribute('aria-expanded', String(isOpen));
}

document.addEventListener('DOMContentLoaded', async () => {
    setupNav();
    const initialView = location.hash.slice(1);
    if (document.getElementById(`view-${initialView}`)) navigateTo(initialView, false, false);
    document.querySelectorAll('.tab-form-row').forEach(row => {
        const label = row.querySelector('label.tab-form-label');
        const control = row.querySelector('input[id], select[id], textarea[id]');
        if (label && control && !label.htmlFor) label.htmlFor = control.id;
    });

    // 1. Detect our own IP first so we can auto-select our device
    try {
        const d = await fetchAPI(`/me`);
        if (d && d.ip) myIp = d.ip;
    } catch (_) {}

    // 2. Load device list
    await loadDevices();

    // 3. Auto-select our device by default
    if (myIp) {
        const sel = document.getElementById('device-selector');
        if (sel) {
            for (const opt of sel.options) {
                if (opt.value === myIp) { opt.selected = true; break; }
            }
            currentDevice = sel.value;
        }
    }

    // 4. Initial data load
    startSyncLoop();
    initLiveFeed();

    // Device selector change
    document.getElementById('device-selector').addEventListener('change', e => {
        currentDevice = e.target.value;
        syncPolicyDeviceDrop();
        forceRefresh();
        initLiveFeed();
    });
});

// ── Navigation ───────────────────────────────────────────────────────────────
function setupNav() {
    document.querySelectorAll('[data-view]').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            navigateTo(link.getAttribute('data-view'));
        });
    });
    window.addEventListener('hashchange', () => {
        const view = location.hash.slice(1);
        if (document.getElementById(`view-${view}`)) navigateTo(view, false);
    });
}

function navigateTo(view, updateHash = true, refresh = true) {
    const titles = { dashboard:'Dashboard', live:'Query log', policy:'Rules', blocklists:'Blocklists', schedules:'Schedules', tools:'Tools', devices:'Network', actions:'Automations', upstream:'Upstream DNS' };
    if (!document.getElementById(`view-${view}`)) return;
    currentView = view;
    document.querySelectorAll('[data-view]').forEach(link => {
        const active = link.getAttribute('data-view') === view;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    document.querySelectorAll('.view').forEach(el => el.classList.toggle('active', el.id === `view-${view}`));
    const title = document.getElementById('page-title');
    if (title) title.textContent = titles[view] || '';
    const devicePicker = document.querySelector('.device-select-wrap');
    if (devicePicker) devicePicker.style.display = (view === 'dashboard' || view === 'live') ? 'flex' : 'none';
    if (document.querySelector('.sidebar')?.classList.contains('open')) toggleSidebar();
    if (updateHash && location.hash !== `#${view}`) history.pushState(null, '', `#${view}`);
    window.scrollTo({top: 0, behavior: 'instant'});
    if (refresh) forceRefresh();
}

// ── Per-view refresh ──────────────────────────────────────────────────────────
let syncTimer  = null;
let isSyncing  = false;

// Robust fetch wrapper with timeout and error handling
async function fetchAPI(endpoint, options = {}) {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), options.timeoutMs || 8000);
    const requestOptions = { ...options, signal: controller.signal };
    delete requestOptions.timeoutMs;
    try {
        const res = await apiFetch(`${API}${endpoint}`, requestOptions);
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        clearTimeout(timeoutId);
        console.warn(`API Error [${endpoint}]:`, err);
        if (options.method && options.method !== "GET") throw err;
        return null;
    }
}

async function refreshView() {
    if (currentView === 'dashboard') {
        await Promise.allSettled([
            loadStats(),
            loadTopDomains(),
            loadTopBlocked(),
            loadTopClients(),
            loadSafeSearch()
        ]);
    } else if (currentView === 'policy') {
        await Promise.allSettled([loadPolicy(), loadSchedules(), loadDevicesForDrops()]);
    } else if (currentView === 'blocklists') {
        await loadBlocklistsPage();
    } else if (currentView === 'devices') {
        await Promise.allSettled([loadQuarantine(), loadDevices(), loadDhcpConfig()]);
    } else if (currentView === 'tools') {
        await loadTelegramConfig();
    } else if (currentView === 'actions') {
        await Promise.allSettled([loadActions(), loadActionLogs()]);
    } else if (currentView === 'upstream') {
        await loadUpstreamConfig();
    }
}

async function startSyncLoop() {
    if (isSyncing) return;
    isSyncing = true;
    try {
        await refreshView();
    } catch (e) {
        console.error('Sync loop error:', e);
    } finally {
        isSyncing = false;
        syncTimer = setTimeout(startSyncLoop, 10000);
    }
}

function forceRefresh() {
    if (syncTimer) clearTimeout(syncTimer);
    isSyncing = false;
    startSyncLoop();
}


// ── Helpers ───────────────────────────────────────────────────────────────────
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

let registeredDevices = [];

function deviceLabel(ip) {
    if (!ip || !ip.trim()) return 'Unknown';
    if (ip === '127.0.0.1' || ip === '::1') return 'Server (localhost)';
    const d = registeredDevices.find(x => x.ip === ip);
    if (d) return d.name;
    return ip;
}

// domainRow: builds a favicon + domain name row.
// baseDomain is already the registrable root from the server (PSL-normalized).
function domainRow(domain, right, badgeHtml = '') {
    return `<div class="d-row" data-domain="${esc(domain)}">
      <div class="d-left">
        <img src="/api/favicon" class="d-favicon" loading="lazy" data-onerror="ui44">
        <span class="d-name" title="${esc(domain)}">${esc(domain)}</span>
        ${badgeHtml}
      </div>
      <div class="d-right">${right}</div>
    </div>`;
}

function showToast(msg, err = false) {
    const t = document.getElementById('_toast');
    if (!t) return;

    const icon = err
        ? `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--red)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`
        : `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

    t.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div>${esc(msg)}</div>
    `;

    t.className = '';
    void t.offsetWidth; // trigger reflow
    t.className = err ? 'toast-err show' : 'toast-ok show';

    clearTimeout(t._tid);
    t._tid = setTimeout(() => { t.classList.remove('show'); }, 3500);
}

function sanitize(v) {
    let d = (v || '').trim().toLowerCase();
    if (d.startsWith('https://')) d = d.slice(8);
    if (d.startsWith('http://'))  d = d.slice(7);
    d = d.split('/')[0].split('?')[0];
    if (d.startsWith('www.')) d = d.slice(4);
    return d;
}

// ── Device Selectors ──────────────────────────────────────────────────────────

async function loadDevices() {
    try {
        const devices = await fetchAPI(`/devices`);
        if (!devices) return;
        registeredDevices = devices;
        populateDeviceSelects(devices);
        const netDevEl = document.getElementById('net-stat-devices');
        if (netDevEl) netDevEl.textContent = devices.length;
        const hostDev  = devices.find(d => d.name && (d.name.includes('Host') || d.name.includes('Server')));
        const netIpEl  = document.getElementById('net-stat-ip');
        if (netIpEl && hostDev) netIpEl.textContent = hostDev.ip;

        const devList = document.getElementById('list-devices-all');
        if (devList) {
            if (!devices.length) {
                devList.innerHTML = '<div class="empty-state">No devices registered.<br><code class="empty-command">aegis device add &lt;ip&gt; &lt;name&gt;</code></div>';
            } else {
                devList.innerHTML = devices.map(d => `<div class="d-row">
                  <div class="d-left">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>
                    <div>
                      <div class="d-name">${esc(d.name)}</div>
                      <div class="device-address">${esc(d.ip)}</div>
                    </div>
                  </div>
                  <div class="d-right">
                    <select class="form-select profile-select" data-ip="${esc(d.ip)}" data-onchange="ui45">
                      <option value="default" ${d.profile === 'default' ? 'selected' : ''}>Default</option>
                      <option value="strict"  ${d.profile === 'strict'  ? 'selected' : ''}>Strict</option>
                      <option value="bypass"  ${d.profile === 'bypass'  ? 'selected' : ''}>Bypass</option>
                    </select>
                    <button class="btn btn-ghost btn-sm danger-text" data-ip="${esc(d.ip)}" data-onclick="ui46" title="Remove device">Remove</button>
                  </div>
                </div>`).join('');
            }
        }
    } catch (e) { console.error('loadDevices', e); }
}

async function loadDevicesForDrops() {
    try {
        const devices = await fetchAPI(`/devices`);
        if (!devices) return;
        populateDeviceSelects(devices);
        syncPolicyDeviceDrop();
    } catch (e) { console.error('loadDevicesForDrops', e); }
}

function populateDeviceSelects(devices) {
    const topSel = document.getElementById('device-selector');
    const polSel = document.getElementById('policy-device');
    const schSel = document.getElementById('sched-device');
    const expSel = document.getElementById('export-ip');

    const buildOpts = (includeAll = true, allLabel = 'All Devices') => {
        let h = `<option value="">${allLabel}</option>`;
        devices.forEach(d => {
            if (!d.ip || !d.ip.trim()) return;
            h += `<option value="${esc(d.ip)}">${esc(d.name)}</option>`;
        });
        return h;
    };

    if (topSel) {
        const prev = topSel.value;
        topSel.innerHTML = buildOpts(true, 'All Devices');
        if (myIp && !prev) {
            for (const opt of topSel.options) { if (opt.value === myIp) { opt.selected = true; break; } }
        } else if (prev) {
            topSel.value = prev;
        }
        currentDevice = topSel.value;
    }
    if (polSel) { const v = polSel.value; polSel.innerHTML = buildOpts(true, 'Global – All Devices'); if (v) polSel.value = v; }
    if (schSel) { const v = schSel.value; schSel.innerHTML = buildOpts(true, 'Global – All Devices'); if (v) schSel.value = v; }
    if (expSel) { const v = expSel.value; expSel.innerHTML = buildOpts(true, 'All Devices'); if (v) expSel.value = v; }
}

function syncPolicyDeviceDrop() {
    const polSel = document.getElementById('policy-device');
    if (polSel && currentDevice) polSel.value = currentDevice;
}

// ── Stats ──────────────────────────────────────────────────────────────────────

let totalQueries = 0, totalBlocked = 0, avgLatency = 0;

async function loadStats() {
    try {
        const d = await fetchAPI(`/stats${qs()}`);
        if (!d) return;
        totalQueries = d.queries_today  || 0;
        totalBlocked = d.blocked_today  || 0;
        avgLatency   = d.avg_latency_ms || 0;

        setText('stat-queries',  fmt(totalQueries));
        setText('stat-blocked',  fmt(totalBlocked));
        const rate = totalQueries > 0
            ? ((totalBlocked / totalQueries) * 100).toFixed(1) + '%'
            : '0.0%';
        setText('stat-rate',    rate);
        setText('stat-latency', (avgLatency).toFixed(1));
    } catch (e) { console.error('loadStats', e); }
}

function getRowLimit() {
    return window.innerWidth < 640 ? 5 : 8;
}

// ── Top Domains ───────────────────────────────────────────────────────────────

function topRow(title, count, total, isBlocked, isDevice = false) {
    const pct = total > 0 ? ((count / total) * 100).toFixed(2) : '0.00';
    const colorClass = isBlocked ? 'red' : 'blue';
    const deviceSvg = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiM4ODgiIHN0cm9rZS13aWR0aD0iMiI+PHJlY3QgeD0iNSIgeT0iMiIgd2lkdGg9IjE0IiBoZWlnaHQ9IjIwIiByeD0iMiIvPjxsaW5lIHgxPSIxMiIgeTE9IjE4IiB4Mj0iMTIuMDEiIHkyPSIxOCIvPjwvc3ZnPg==";
    const icon = isDevice ? deviceSvg : `/api/favicon`;
    const imgHtml = `<img src="${icon}" class="d-favicon" loading="lazy" data-onerror="ui44">`;
    return `<div class="ag-row">
  <div class="ag-row-left">
    ${imgHtml}
    <span class="ag-domain" title="${esc(title)}">${esc(title)}</span>
  </div>
  <div class="ag-row-right">
    <span class="ag-count" style="color:var(--${colorClass})">${fmt(count)}</span>
    <span class="ag-pct">${pct}%</span>
    <div class="ag-bar"><div class="ag-bar-fill" style="width:${pct}%; background:var(--${colorClass})"></div></div>
  </div>
</div>`;
}

async function loadTopDomains() {
    try {
        const data = await fetchAPI(`/top-domains${qs()}`);
        if (!data) return;

        const limit = getRowLimit();
        const top   = (data.top_domains   || []).slice(0, limit);

        setHtml('list-top-domains',
            top.length
                ? top.map(d => topRow(d.domain, d.count, totalQueries, false)).join('')
                : '<div class="empty-state">No requests today yet.</div>');

        ['list-top-domains'].forEach(pid => {
            const el = document.getElementById(pid);
            if (!el) return;
            el.querySelectorAll('.ag-row, .d-row').forEach(row => {
                const domain = row.querySelector('.ag-domain, .d-name')?.textContent?.trim();
                if (domain) {
                    row.addEventListener('contextmenu', e => { e.preventDefault(); openCtxMenu(e, domain); });
                }
            });
        });

    } catch (e) { console.error('loadTopDomains', e); }
}

async function classifyDomain(domain, category) {
    try {
        await apiFetch(`${API}/classify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, category })
        });
        const msg = category === 'reset'
            ? `Reset classification for ${domain}`
            : `Marked ${domain} as ${category}`;
        showToast(msg);
        loadTopDomains();
    } catch (e) { showToast('Failed to classify domain', true); }
}

// ── Context Menu ──────────────────────────────────────────────────────────────
let ctxDomain = '';

function openCtxMenu(e, domain) {
    ctxDomain = domain;
    const menu = document.getElementById('ctx-menu');
    if (!menu) return;
    menu.style.display = 'block';
    // Position near cursor, keep within viewport
    const vw = window.innerWidth, vh = window.innerHeight;
    const mw = 210, mh = 180;
    const x = e.clientX + mw > vw ? vw - mw - 8 : e.clientX + 4;
    const y = e.clientY + mh > vh ? vh - mh - 8 : e.clientY + 4;
    menu.style.left = x + 'px';
    menu.style.top  = y + 'px';
}

function closeCtxMenu() {
    const menu = document.getElementById('ctx-menu');
    if (menu) menu.style.display = 'none';
    ctxDomain = '';
}

function ctxClassify(category) {
    if (!ctxDomain) return;
    classifyDomain(ctxDomain, category);
    closeCtxMenu();
}

async function ctxBlock() {
    if (!ctxDomain) return;
    try {
        const body = {domain:ctxDomain, device_id:currentDevice || null};
        await apiFetch(`${API}/deny`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        showToast(`Blocked ${ctxDomain}`);
        loadTopDomains();
    } catch { showToast('Failed to block domain', true); }
    closeCtxMenu();
}

async function ctxAllow() {
    if (!ctxDomain) return;
    try {
        const body = {domain:ctxDomain, device_id:currentDevice || null};
        await apiFetch(`${API}/allow`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        showToast(`Allowed ${ctxDomain}`);
        loadTopDomains();
    } catch { showToast('Failed to allow domain', true); }
    closeCtxMenu();
}

// Close context menu on any click outside or Escape
document.addEventListener('click', e => {
    const menu = document.getElementById('ctx-menu');
    if (menu && !menu.contains(e.target)) closeCtxMenu();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeCtxMenu(); });

// Also attach right-click on top-blocked list
function attachBlockedCtx() {
    const el = document.getElementById('list-top-blocked');
    if (!el) return;
    el.querySelectorAll('.d-row').forEach(row => {
        const domain = row.querySelector('.d-name')?.textContent?.trim();
        if (domain) row.addEventListener('contextmenu', e => { e.preventDefault(); openCtxMenu(e, domain); });
    });
}

// ── Top Blocked ───────────────────────────────────────────────────────────────
async function loadTopBlocked() {
    try {
        const data = await fetchAPI(`/top-blocked${qs()}`);
        if (!data) return;
        if (!data.length) { setHtml('list-top-blocked', '<div class="empty-state">No blocked queries today.</div>'); return; }
        const limit = getRowLimit();
        setHtml('list-top-blocked', data.slice(0, limit).map(d =>
            topRow(d.domain, d.count, totalBlocked, true)
        ).join(''));
        attachBlockedCtx();
    } catch (e) { console.error('loadTopBlocked', e); }
}

async function loadTopClients() {
    try {
        const devices = await fetchAPI(`/devices`);
        if (!devices || !devices.length) {
            setHtml('list-top-clients', '<div class="empty-state">No clients registered.</div>');
            return;
        }
        // Fetch per-device stats in parallel to get real query counts
        const withCounts = await Promise.all(devices.map(async d => {
            const s = await fetchAPI(`/stats?device_id=${encodeURIComponent(d.ip)}`);
            return { name: d.name || d.ip, ip: d.ip, count: s ? (s.queries_today || 0) : 0 };
        }));
        const sorted = withCounts.filter(c => c.count > 0).sort((a, b) => b.count - a.count);
        if (!sorted.length) {
            setHtml('list-top-clients', '<div class="empty-state">No queries recorded for any client today.</div>');
            return;
        }
        const grandTotal = sorted.reduce((sum, c) => sum + c.count, 0);
        setHtml('list-top-clients', sorted.map(c => topRow(c.name, c.count, grandTotal, false, true)).join(''));
    } catch (e) { console.error('loadTopClients', e); }
}

// ── Safe Search ───────────────────────────────────────────────────────────────
async function loadSafeSearch() {
    try {
        const d = await fetchAPI(`/safesearch`);
        if (!d) return;
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
        const r = await apiFetch(`${API}/safesearch`, {
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

// ── Blocklists ────────────────────────────────────────────────────────────────
async function addBlocklist() {
    const name       = document.getElementById('bl-name').value.trim();
    const source_url = document.getElementById('bl-url').value.trim();
    if (!name || !source_url) return;
    try {
        const r = await apiFetch(`${API}/blocklists`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, source_url })
        });
        if (r.ok) {
            showToast(`Added blocklist: ${name}`);
            document.getElementById('bl-name').value = '';
            document.getElementById('bl-url').value  = '';
            loadBlocklistsPage();
        } else {
            showToast('Failed to add blocklist', true);
        }
    } catch (e) { showToast('Error adding blocklist', true); }
}

async function deleteBlocklist(name) {
    if (!confirm(`Remove blocklist: ${name}?`)) return;
    try {
        const r = await apiFetch(`${API}/blocklists/${encodeURIComponent(name)}`, { method: 'DELETE' });
        if (r.ok) {
            showToast(`Removed blocklist: ${name}`);
            loadBlocklistsPage();
        } else {
            showToast('Failed to remove blocklist', true);
        }
    } catch (e) { showToast('Error removing blocklist', true); }
}

async function loadBlocklistsPage() {
    try {
        const data = await fetchAPI(`/lists`);
        if (!data) return;
        const tbody = document.querySelector('#tbl-blocklists tbody');
        if (!tbody) return;
        if (!data.length) { tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No blocklists configured.</td></tr>'; return; }
        tbody.innerHTML = data.map(l => {
            const isEnabled = l.enabled !== false; // assuming true if missing
            const timeStr = l.last_updated ? new Date(l.last_updated).toLocaleString() : 'Never';
            return `
          <tr>
            <td class="table-name">${esc(l.name)}</td>
            <td class="num">${fmt(l.rule_count)}</td>
            <td><span class="badge ${isEnabled ? 'badge-green' : 'badge-gray'}">${isEnabled ? 'Enabled' : 'Disabled'}</span></td>
            <td class="table-time">${timeStr}</td>
          </tr>`;
        }).join('');
    } catch (e) { console.error('loadBlocklistsPage', e); }
}

// ── Policy Rules ──────────────────────────────────────────────────────────────
async function loadPolicy() {
    try {
        const r = await apiFetch(`${API}/policy`);
        policyRules = await r.json() || { allowed:[], denied:[], device_allowed:{}, device_denied:{} };
        renderPolicies();
    } catch (e) { console.error('loadPolicy', e); }
}

function renderPolicies() {
    const dev = currentDevice;

    let allowedList = (policyRules.allowed || []).map(d => ({ domain: d, isGlobal: true }));
    let deniedList  = (policyRules.denied  || []).map(d => ({ domain: d, isGlobal: true }));

    if (dev) {
        const devAllowed = (policyRules.device_allowed?.[dev] || []).map(d => ({ domain: d, isGlobal: false }));
        const devDenied  = (policyRules.device_denied?.[dev]  || []).map(d => ({ domain: d, isGlobal: false }));
        const merge = (globals, devices) => {
            const map = new Map();
            globals.forEach(x => map.set(x.domain, x));
            devices.forEach(x => map.set(x.domain, x));
            return Array.from(map.values());
        };
        allowedList = merge(allowedList, devAllowed);
        deniedList  = merge(deniedList,  devDenied);
    }

    const makeList = (items, flipAction) => {
        if (!items.length) return '<div class="empty-state">No domains in this list.</div>';
        return items.map(item => {
            const badge = `<span class="badge ${item.isGlobal ? 'badge-gray' : 'badge-blue'}">${item.isGlobal ? 'Global' : 'Device'}</span>`;
            return domainRow(item.domain,
                `<div class="d-right row-actions">
                  <button class="btn btn-sm btn-ghost" data-domain="${esc(item.domain)}" data-action="${esc(flipAction)}" data-onclick="ui48">${flipAction === 'allow' ? 'Allow' : 'Block'}</button>
                  <button class="btn btn-sm btn-ghost danger-text" data-domain="${esc(item.domain)}" data-global="${item.isGlobal}" data-onclick="ui49">Remove</button>
                </div>`,
                dev ? badge : '');
        }).join('');
    };

    setHtml('list-allowed', makeList(allowedList, 'deny'));
    setHtml('list-denied',  makeList(deniedList,  'allow'));
}

async function submitPolicyForm() {
    const input = document.getElementById('policy-input');
    const select = document.getElementById('policy-action');
    if (!input || !select) return;
    const action = select.value;
    await submitPolicy(action, input.value);
    input.value = '';
}

async function submitPolicy(action, domainArg) {
    const input  = document.getElementById('policy-input');
    const raw    = domainArg || (input ? input.value : '');
    const domain = sanitize(raw);
    if (!domain) return;

    const polSel  = document.getElementById('policy-device');
    const device_id = polSel ? (polSel.value || null) : null;
    const body = { domain };
    if (device_id) body.device_id = device_id;

    try {
        const r = await apiFetch(`${API}/${action}`, {
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
    if (device_id && !isGlobal) body.device_id = device_id;
    try {
        const r = await apiFetch(`${API}/policy/remove`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message || `Removed ${domain}`);
        loadPolicy();
    } catch (e) { showToast('Failed to remove policy', true); }
}

// ── Schedules ──────────────────────────────────────────────────────────────────
async function loadSchedules() {
    const timezone = await fetchAPI('/timezone');
    const timezoneLabel = document.getElementById('schedule-timezone');
    if (timezoneLabel) timezoneLabel.textContent = `Schedule timezone: ${timezone?.timezone || 'server local time'}`;
    try {
        const data = await fetchAPI(`/schedules`);
        if (!data) return;
        if (!data.length) { setHtml('list-schedules', '<div class="empty-state">No schedules configured.</div>'); return; }
        const dmap = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
        const html = data.map(s => {
            const sh   = String(Math.floor(s.start_minutes/60)).padStart(2,'0');
            const sm   = String(s.start_minutes%60).padStart(2,'0');
            const eh   = String(Math.floor(s.end_minutes/60)).padStart(2,'0');
            const em   = String(s.end_minutes%60).padStart(2,'0');
            const dstr = s.days.length===7 ? 'Every day' : s.days.map(d=>dmap[d]).join(', ');
            const isAllow = (s.action||'').toLowerCase() === 'allow';
            return `<div class="d-row sched-row">
              <div class="d-left block">
                <div class="schedule-summary">
                  <span class="badge ${isAllow?'badge-green':'badge-red'}">${esc(s.action)}</span>
                  <strong class="schedule-domain">${esc(s.domain)}</strong>
                  ${s.device_id ? `<span class="badge badge-blue">${esc(s.device_id)}</span>` : '<span class="badge badge-gray">Global</span>'}
                </div>
                <div class="sched-meta">${sh}:${sm} – ${eh}:${em} &nbsp;·&nbsp; ${dstr}</div>
              </div>
              <div class="d-right">
                <label class="toggle" title="${s.enabled?'Disable':'Enable'}">
                  <input type="checkbox" ${s.enabled?'checked':''} data-id="${esc(s.id)}" data-onchange="ui50">
                  <span class="toggle-track"></span>
                </label>
                <button class="btn btn-sm btn-deny" data-id="${esc(s.id)}" data-onclick="ui51">Delete</button>
              </div>
            </div>`;
        }).join('');
        setHtml('list-schedules', html);
    } catch (e) { console.error('loadSchedules', e); }
}

async function submitSchedule() {
    const domain = sanitize(document.getElementById('sched-domain').value);
    if (!domain) { showToast('Enter a domain', true); return; }
    const action    = document.getElementById('sched-action').value;
    const device_id = document.getElementById('sched-device').value || null;
    const start     = document.getElementById('sched-start').value.split(':');
    const end       = document.getElementById('sched-end').value.split(':');
    const days = [];
    document.querySelectorAll('input[name="sched-day"]:checked').forEach(cb => days.push(parseInt(cb.value)));
    if (!days.length) { showToast('Select at least one day', true); return; }
    const sh = start[0].padStart(2,'0'), sm = start[1].padStart(2,'0');
    const eh = end[0].padStart(2,'0'),   em = end[1].padStart(2,'0');
    const label = `${action.toUpperCase()} ${domain} (${sh}:${sm}–${eh}:${em})`;
    const body  = { domain, action, days, start_hour:parseInt(sh), start_min:parseInt(sm), end_hour:parseInt(eh), end_min:parseInt(em), device_id, label };
    try {
        const r = await apiFetch(`${API}/schedules`, {
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
        await apiFetch(`${API}/schedules/${id}/toggle`, {
            method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({enabled})
        });
        loadSchedules();
    } catch (e) { showToast('Failed to toggle schedule', true); loadSchedules(); }
}

async function deleteSchedule(id) {
    if (!confirm('Delete this schedule?')) return;
    try {
        await apiFetch(`${API}/schedules/${id}`, {method:'DELETE'});
        showToast('Schedule deleted');
        loadSchedules();
    } catch (e) { showToast('Failed to delete', true); }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
async function submitDiagnose() {
    const domain = sanitize(document.getElementById('diag-input').value);
    if (!domain) return;
    const el = document.getElementById('diag-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'Analyzing…';
    try {
        const r = await apiFetch(`${API}/diagnose`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})
        });
        const d   = await r.json();
        const cls = d.policy_result === 'BLOCKED' ? 'result-blocked' : 'result-allowed';
        el.className = `result-box ${cls}`;
        el.innerHTML = [
            ['Domain', `<code>${esc(d.domain)}</code>`],
            ['Result', `<strong>${esc(d.policy_result)}</strong>`],
            ['Reason', esc(d.reason)],
            ['Source', esc(d.source)],
            ['Action', esc(d.action_suggested)],
        ].map(([k,v]) => `<div class="result-row"><span class="result-key">${k}</span><span class="result-val">${v}</span></div>`).join('');
    } catch (e) { el.className = 'result-box result-blocked'; el.textContent = 'Diagnostic failed.'; }
}

// ── Risk Check ────────────────────────────────────────────────────────────────
async function submitRiskCheck() {
    const domain = sanitize(document.getElementById('risk-input').value);
    if (!domain) return;
    const el = document.getElementById('risk-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'Analyzing…';
    try {
        const r = await apiFetch(`${API}/risk`, {
            method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain})
        });
        const d = await r.json();
        const cls      = d.score >= 70 ? 'result-blocked' : d.score >= 40 ? 'result-warn' : 'result-allowed';
        const barColor = d.score >= 70 ? '#dc2626' : d.score >= 40 ? '#d97706' : '#059669';
        const factors  = (d.factors||[]).map(f=>`<li>${esc(f)}</li>`).join('');
        el.className   = `result-box ${cls}`;
        el.innerHTML = `
          <div class="result-row"><span class="result-key">Domain</span><code class="result-val">${esc(domain)}</code></div>
          <div class="result-row"><span class="result-key">Score</span><span class="result-val"><strong>${Math.max(0,Math.min(100,Number(d.score)||0))}/100</strong> — ${esc(d.level)}</span></div>
          <div style="margin:.5rem 0;height:5px;background:#e5e7eb;border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${Math.max(0,Math.min(100,Number(d.score)||0))}%;background:${barColor};border-radius:3px"></div>
          </div>
          <ul style="margin:.4rem 0 0 1.1rem;font-size:.78rem;color:#6b7280">${factors}</ul>`;
    } catch (e) { el.className = 'result-box result-blocked'; el.textContent = 'Risk analysis failed.'; }
}

// ── Data Management ───────────────────────────────────────────────────────────
async function deleteLogs() {
    const sel    = document.getElementById('log-timeframe');
    const tfText = sel.options[sel.selectedIndex].text;
    if (!confirm(`Delete ${tfText}? This cannot be undone.`)) return;
    try {
        const r = await apiFetch(`${API}/logs`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timeframe: sel.value })
        });
        const d = await r.json();
        showToast(d.message, !d.success);
        if (d.success) loadStats();
    } catch (e) { showToast('Failed to delete logs', true); }
}

// ── Export Logs ───────────────────────────────────────────────────────────────
function exportLogs(format) {
    const days   = document.getElementById('export-days').value;
    const status = document.getElementById('export-status').value;
    const ip     = document.getElementById('export-ip').value;
    window.location.href = `${API}/export/logs?days=${days}&status=${status}&ip=${ip}&format=${format}`;
}

// ── Devices & Quarantine ──────────────────────────────────────────────────────
async function loadQuarantine() {
    try {
        const data = await fetchAPI(`/quarantine`);
        if (!data) return;
        const netQEl = document.getElementById('net-stat-quarantine');
        if (netQEl) netQEl.textContent = data.length;
        const container = document.getElementById('list-quarantine');
        if (!container) return;
        if (!data.length) { container.innerHTML = '<div class="empty-state" style="padding:24px 20px">No devices under DNS rate restriction.</div>'; return; }
        container.innerHTML = data.map(ip => `<div class="d-row">
          <div class="d-left">
            <span class="d-name">${esc(ip)}</span>
            <span style="color:var(--red); font-size:12px; font-weight:500; margin-left:8px">Quarantined</span>
          </div>
          <div class="d-right">
            <button class="btn btn-ghost btn-sm" data-ip="${esc(ip)}" data-onclick="ui52">Restore</button>
          </div>
        </div>`).join('');
    } catch (e) { console.error('loadQuarantine', e); }
}

async function unquarantine(ip) {
    try {
        await apiFetch(`${API}/quarantine/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        showToast(`Unquarantined ${ip}`);
        loadQuarantine();
    } catch (e) { showToast(`Failed to unquarantine ${ip}`, true); }
}

async function removeDevice(ip) {
    if (!confirm('Remove this device?')) return;
    try {
        await apiFetch(`${API}/devices/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        loadDevices();
    } catch(e) { showToast('Error removing device', true); }
}

async function setDeviceProfile(ip, profile) {
    try {
        await apiFetch(`${API}/devices/${encodeURIComponent(ip)}/profile`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({profile})
        });
        showToast('Profile updated');
        loadDevices();
    } catch(e) { showToast('Error updating profile', true); }
}

async function promptAddDevice() {
    const ip   = prompt('Enter Device IP (e.g., 100.113.224.82):');
    if (!ip) return;
    const name = prompt('Enter Friendly Name (e.g., Harshil\'s Phone):');
    if (!name) return;
    try {
        const r   = await apiFetch(`${API}/devices`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, name})
        });
        const res = await r.json();
        showToast(res.message, !res.success);
        loadDevices();
    } catch(e) { showToast('Error adding device', true); }
}

// ── Custom Actions ─────────────────────────────────────────────────────────────
function toggleActionFields() {
    const type = document.getElementById('action-type').value;
    document.getElementById('action-fields-webhook').style.display = type === 'webhook' ? 'block' : 'none';
    document.getElementById('action-fields-shell').style.display   = type === 'shell'   ? 'block' : 'none';
    document.getElementById('action-fields-html').style.display    = type === 'html'    ? 'block' : 'none';
}

async function loadActions() {
    const el = document.getElementById('list-actions');
    try {
        const res     = await apiFetch(`${API}/actions`);
        if (!res.ok) throw new Error('Failed to load actions');
        const actions = await res.json();
        if (!actions.length) { el.innerHTML = '<div class="empty-state">No custom actions active.</div>'; return; }
        el.innerHTML = actions.map(a => `
          <div class="d-item action-item">
            <div class="action-copy">
              <div class="action-domain">${esc(a.domain)}</div>
              <div class="action-meta">
                <span class="badge ${a.action_type==='webhook'?'badge-blue':a.action_type==='shell'?'badge-red':'badge-green'}">${esc(a.action_type.toUpperCase())}</span>
                ${a.token ? '<span class="auth-required"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>Token required</span>' : ''}
              </div>
            </div>
            <button class="btn btn-ghost btn-sm danger-text" data-domain="${esc(a.domain)}" data-onclick="ui53" title="Delete automation">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>`).join('');
    } catch (err) { el.innerHTML = `<div class="empty-state error-state">${esc(err.message)}</div>`; }
}

async function loadActionLogs() {
    const el = document.getElementById('list-action-logs');
    try {
        const res  = await apiFetch(`${API}/actions/logs`);
        if (!res.ok) throw new Error('Failed to load logs');
        const logs = await res.json();
        if (!logs.length) { el.innerHTML = '<div class="empty-state">No executions logged yet.</div>'; return; }
        el.innerHTML = logs.map(l => `
          <div class="d-item action-log-item">
            <div class="action-copy">
              <div class="action-log-head">
                <span class="action-domain">${esc(l.domain)}</span>
                <span class="action-time">${new Date(l.triggered_at + 'Z').toLocaleString(undefined,{hour:'numeric',minute:'2-digit',second:'2-digit'})}</span>
              </div>
              <div class="action-outcome ${l.outcome==='success'?'is-success':'is-error'}">
                ${l.outcome==='success'
                    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>'
                    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'}
                <span>${esc(l.outcome)}: <span class="action-detail">${esc(l.detail || '')}</span></span>
              </div>
            </div>
          </div>`).join('');
    } catch (err) { el.innerHTML = `<div class="empty-state error-state">${esc(err.message)}</div>`; }
}

async function clearActionLogs() {
    if (!confirm('Clear all execution logs?')) return;
    try {
        const res = await apiFetch(`${API}/actions/logs`, { method: 'DELETE' });
        if (!res.ok) throw new Error('Failed to clear logs');
        showToast('Execution logs cleared');
        loadActionLogs();
    } catch (err) { showToast(err.message, true); }
}

async function submitAction() {
    const payload = {
        domain:      document.getElementById('action-domain').value,
        action_type: document.getElementById('action-type').value,
        token:       document.getElementById('action-token').value || null,
        success_msg: document.getElementById('action-success').value || null,
    };
    if (payload.action_type === 'webhook') {
        payload.method      = document.getElementById('action-method').value;
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
        const res  = await apiFetch(`${API}/actions`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)
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
    } catch (e) { showToast(e.message, true); }
}

async function deleteAction(domain) {
    if (!confirm(`Delete action for ${domain}?`)) return;
    try {
        const res  = await apiFetch(`${API}/actions/${encodeURIComponent(domain)}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) { showToast(data.message); loadActions(); }
        else { showToast(data.message, true); }
    } catch (e) { showToast(e.message, true); }
}

function handleHtmlFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload  = e => { document.getElementById('action-html').value = e.target.result; showToast(`Loaded ${file.name}`); };
    reader.onerror = () => showToast(`Failed to read ${file.name}`, true);
    reader.readAsText(file);
}

// ── Live Feed ─────────────────────────────────────────────────────────────────
let liveFeedQueries = [];
let liveFeedES      = null;

async function initLiveFeed() {
    const data = await fetchAPI(`/recent${qs()}`);
    if (data) {
        liveFeedQueries = data.slice(0, 500);
        renderLiveFeed();
    }
    if (liveFeedES) liveFeedES.close();
    liveFeedES = new EventSource(`${API}/live-feed`);
    liveFeedES.onmessage = e => {
        try {
            const q = JSON.parse(e.data);
            if (currentDevice && currentDevice !== q.client_ip) return;
            liveFeedQueries.unshift(q);
            if (liveFeedQueries.length > 500) liveFeedQueries.pop();
            renderLiveFeed();
        } catch(err) { console.error('SSE JSON Error', err); }
    };
}

let liveFeedFilter = 'all';
let isLivePaused = false;

function setLiveFilter(filter) {
    liveFeedFilter = filter;
    ['all','allowed','blocked','cached'].forEach(f => {
        const btn = document.getElementById('lf-' + f);
        if (btn) btn.classList.toggle('active', f === filter);
    });
    renderLiveFeed();
}

function filterLiveFeed() { renderLiveFeed(); }

function toggleLivePause() {
    isLivePaused = !isLivePaused;
    const btn = document.getElementById('live-pause-btn');
    if (isLivePaused) {
        if (btn) {
            btn.textContent = 'Resume';
            btn.style.color = 'var(--blue)';
        }
    } else {
        if (btn) {
            btn.textContent = 'Pause';
            btn.style.color = 'var(--text2)';
        }
        renderLiveFeed();
    }
}

function clearLiveLogs() {
    liveFeedQueries = [];
    renderLiveFeed();
}

function renderLiveFeed() {
    if (isLivePaused) return;
    const el = document.getElementById('list-recent-queries');
    if (!el) return;

    if (!liveFeedQueries.length) {
        el.innerHTML = '<tr><td colspan="4" class="empty-state">Waiting for queries...</td></tr>';
        return;
    }

    const countBadge = document.getElementById('recent-query-count');
    if (countBadge) countBadge.textContent = `${liveFeedQueries.length}`;

    const searchTerm = (document.getElementById('live-search')?.value || '').toLowerCase();
    const filtered = liveFeedQueries.filter(q => {
        if (liveFeedFilter !== 'all') {
            const s = q.status === 'cache_hit' ? 'cached' : q.status;
            if (s !== liveFeedFilter) return false;
        }
        if (searchTerm && !q.domain.toLowerCase().includes(searchTerm)) return false;
        return true;
    });

    if (!filtered.length) {
        el.innerHTML = '<tr><td colspan="4" class="empty-state">No matching queries</td></tr>';
        return;
    }

    // Capture scroll before wiping DOM
    const tblWrap = el.closest('div');
    const isScrolled = tblWrap && tblWrap.scrollTop > 50;
    const st = tblWrap ? tblWrap.scrollTop : 0;

    const newHtml = filtered.map(q => {
        const tStr  = q.timestamp || new Date().toISOString();
        const time  = new Date(tStr.endsWith('Z') ? tStr : tStr + 'Z')
                        .toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
        const isBlocked = q.status === 'blocked';
        const isCached  = q.status === 'cache_hit';
        const statusLabel = isBlocked ? 'Blocked' : (isCached ? 'Cached' : 'Allowed');
        const statusClass = isBlocked ? 'blocked' : (isCached ? 'cached' : 'allowed');

        return `<tr class="query-row query-${statusClass}" data-domain="${esc(q.domain)}">
          <td>
            <div class="query-domain">
              <img src="/api/favicon" class="d-favicon" loading="lazy" data-onerror="ui44">
              <span class="d-name" title="${esc(q.domain)}">${esc(q.domain)}</span>
            </div>
          </td>
          <td class="query-device">${esc(deviceLabel(q.client_ip))}</td>
          <td class="query-time">${time}</td>
          <td class="query-status align-right"><span class="status-pill status-pill-${statusClass}">${statusLabel}</span></td>
        </tr>`;
    }).join('');

    el.innerHTML = newHtml;
    if (tblWrap && !isScrolled) tblWrap.scrollTop = 0; else if (tblWrap) tblWrap.scrollTop = st;
}

// ── Telegram Settings ─────────────────────────────────────────────────────────
async function loadTelegramConfig() {
    try {
        const cfg = await fetchAPI(`/telegram`);
        if (!cfg) return;
        const tokenInput = document.getElementById('tg-bot-token');
        tokenInput.value = '';
        tokenInput.placeholder = cfg.bot_token_configured ? 'Saved (enter a new token to replace it)' : '123456789:ABCdef...';
        document.getElementById('tg-chat-id').value          = cfg.chat_id    || '';
        document.getElementById('tg-threshold').value        = cfg.threat_threshold || 70;
        document.getElementById('tg-notify-blocked').checked = cfg.notify_on_block  || false;
        document.getElementById('tg-enabled').checked        = cfg.enabled          || false;
        const badge = document.getElementById('tg-status-badge');
        if (cfg.enabled && cfg.bot_token_configured && cfg.chat_id) {
            badge.style.color = 'var(--green)';
            badge.textContent = 'Active';
        } else {
            badge.style.color = 'var(--text3)';
            badge.textContent = 'Not Configured';
        }
    } catch (e) { console.error('Error loading Telegram config', e); }
}

async function saveTelegramConfig() {
    const cfg = {
        enabled:          document.getElementById('tg-enabled').checked,
        bot_token:        document.getElementById('tg-bot-token').value.trim(),
        chat_id:          document.getElementById('tg-chat-id').value.trim(),
        threat_threshold: Math.max(1, Math.min(100, parseInt(document.getElementById('tg-threshold').value, 10) || 70)),
        notify_on_block:  document.getElementById('tg-notify-blocked').checked
    };
    try {
        const r   = await apiFetch(`${API}/telegram`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(cfg)
        });
        const res = await r.json();
        showToast(res.message, !res.success);
        loadTelegramConfig();
    } catch (e) { showToast('Failed to save Telegram config', true); }
}

async function testTelegram() {
    try {
        const r   = await apiFetch(`${API}/telegram/test`, { method: 'POST' });
        const res = await r.json();
        showToast(res.message, !res.success);
    } catch (e) { showToast('Failed to send test message', true); }
}

async function autoDetectChatId() {
    const token = document.getElementById('tg-bot-token').value.trim();
    if (!token) { showToast('Please enter your Bot Token first', true); return; }
    showToast('Checking for messages…');
    try {
        // Call our backend proxy — browser can't reach api.telegram.org directly (CORS)
        const r    = await apiFetch(`${API}/telegram/detect`, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({token})
        });
        const data = await r.json();
        if (!data.ok) {
            showToast(data.description || 'Invalid Bot Token or Telegram error', true);
            return;
        }
        if (!data.result || !data.result.length) {
            showToast('No messages found. Send any message to your bot first, then try again.', true);
            return;
        }
        // Walk updates newest-first to find a chat id
        let chatId = null;
        for (const update of [...data.result].reverse()) {
            chatId = update.message?.chat?.id
                  ?? update.channel_post?.chat?.id
                  ?? update.my_chat_member?.chat?.id
                  ?? null;
            if (chatId !== null) break;
        }
        if (chatId !== null) {
            document.getElementById('tg-chat-id').value = String(chatId);
            showToast(`Chat ID detected: ${chatId}`);
        } else {
            showToast('Could not find a Chat ID in recent updates. Send a message to your bot and retry.', true);
        }
    } catch (e) { showToast('Failed to contact the AegisDNS backend', true); }
}

// ── Restart ───────────────────────────────────────────────────────────────────
async function restartServer() {
    const btn = document.getElementById('restart-btn');
    if (btn) btn.classList.add('restarting');
    try {
        const r = await apiFetch(`${API}/restart`, { method: 'POST' });
        const d = await r.json();
        showToast(d.message || 'Restarting…');
        // Wait for daemon to come back, then reload
        setTimeout(async () => {
            for (let i = 0; i < 20; i++) {
                try {
                    const check = await fetchAPI('/stats', { timeoutMs: 1000 });
                    if (check) { location.reload(); return; }
                } catch (_) {}
                await new Promise(r => setTimeout(r, 500));
            }
            if (btn) btn.classList.remove('restarting');
            showToast('Restart may have failed — check the container', true);
        }, 1500);
    } catch (e) {
        if (btn) btn.classList.remove('restarting');
        showToast('Failed to reach the restart endpoint', true);
    }
}

// ── DHCP Server ───────────────────────────────────────────────────────────────
async function loadDhcpConfig() {
    try {
        const cfg = await fetchAPI(`/dhcp`);
        if (!cfg) return;
        document.getElementById('dhcp-enabled').checked   = cfg.enabled || false;
        document.getElementById('dhcp-router-ip').value   = cfg.router_ip || '';
        document.getElementById('dhcp-start-ip').value    = cfg.start_ip || '';
        document.getElementById('dhcp-end-ip').value      = cfg.end_ip || '';
        document.getElementById('dhcp-subnet').value      = cfg.subnet_mask || '';
        document.getElementById('dhcp-server-ip').value   = cfg.server_ip || '';
    } catch (e) { console.error('Error loading DHCP config', e); }
}

async function saveDhcpConfig() {
    const cfg = {
        enabled:          document.getElementById('dhcp-enabled').checked,
        router_ip:        document.getElementById('dhcp-router-ip').value.trim(),
        start_ip:         document.getElementById('dhcp-start-ip').value.trim(),
        end_ip:           document.getElementById('dhcp-end-ip').value.trim(),
        subnet_mask:      document.getElementById('dhcp-subnet').value.trim(),
        server_ip:        document.getElementById('dhcp-server-ip').value.trim(),
        lease_duration_secs: 43200
    };
    try {
        const r   = await apiFetch(`${API}/dhcp`, {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(cfg)
        });
        const res = await r.json();
        showToast(res.message, !res.success);
        if (res.success) {
            setTimeout(restartServer, 1000);
        }
    } catch (e) { showToast('Failed to save DHCP config', true); }
}

// ================================================================
// Upstream DNS Configuration
// ================================================================
let lastUpstreamConfigStr = "";

async function loadUpstreamConfig() {
    try {
        const config = await fetchAPI('/upstream');
        if (!config) return;
        const configStr = JSON.stringify(config);

        if (lastUpstreamConfigStr === configStr) {
            return; // Server state hasn't changed, don't clobber unsaved UI changes
        }

        document.getElementById('upstream-enabled-toggle').checked = config.enabled;

        const modeRadios = document.getElementsByName('upstream-mode');
        for (const radio of modeRadios) {
            if (radio.value === config.mode) {
                radio.checked = true;
            }
        }

        document.getElementById('upstream-resolvers-list').value = (config.resolvers || []).join('\n');
        toggleUpstream();

        lastUpstreamConfigStr = configStr;
    } catch (e) {
        console.error("Failed to load upstream config", e);
    }
}

async function saveUpstreamConfig() {
    const enabled = document.getElementById('upstream-enabled-toggle').checked;

    let mode = 'fallback';
    const modeRadios = document.getElementsByName('upstream-mode');
    for (const radio of modeRadios) {
        if (radio.checked) {
            mode = radio.value;
            break;
        }
    }

    const lines = document.getElementById('upstream-resolvers-list').value.split('\n');
    const resolvers = lines.map(l => l.trim()).filter(l => l.length > 0);

    try {
        const result = await fetchAPI('/upstream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled, mode, resolvers })
        });
        showToast(result.message || "Upstream DNS configuration saved");
        lastUpstreamConfigStr = ""; // Force a reload
        await loadUpstreamConfig();
    } catch (e) {
        showToast("Failed to save: " + e.message, true);
    }
}

function toggleUpstream() {
    const enabled = document.getElementById('upstream-enabled-toggle').checked;
    document.getElementById('upstream-settings-panel').style.display = enabled ? 'block' : 'none';
}

// Static handler registry: no inline JavaScript or dynamic code evaluation.
const uiHandlers = {
  ui0: function(event) { toggleSidebar() },
  ui1: function(event) { restartServer() },
  ui3: function(event) { loadTopClients() },
  ui4: function(event) { loadTopDomains() },
  ui5: function(event) { loadTopBlocked() },
  ui6: function(event) { filterLiveFeed() },
  ui7: function(event) { setLiveFilter('all') },
  ui8: function(event) { setLiveFilter('allowed') },
  ui9: function(event) { setLiveFilter('blocked') },
  ui10: function(event) { setLiveFilter('cached') },
  ui11: function(event) { toggleLivePause() },
  ui12: function(event) { clearLiveLogs() },
  ui13: function(event) { toggleSafeSearch() },
  ui14: function(event) { submitPolicyForm() },
  ui15: function(event) { addBlocklist() },
  ui16: function(event) { loadBlocklistsPage() },
  ui17: function(event) { submitSchedule() },
  ui18: function(event) { loadSchedules() },
  ui19: function(event) { autoDetectChatId() },
  ui20: function(event) { testTelegram() },
  ui21: function(event) { saveTelegramConfig() },
  ui22: function(event) { exportLogs('json') },
  ui23: function(event) { exportLogs('csv') },
  ui24: function(event) { submitDiagnose() },
  ui25: function(event) { submitRiskCheck() },
  ui26: function(event) { deleteLogs() },
  ui27: function(event) { event.preventDefault(); submitAction() },
  ui28: function(event) { toggleActionFields() },
  ui29: function(event) { handleHtmlFileUpload(event) },
  ui30: function(event) { document.getElementById('action-html-file').click() },
  ui31: function(event) { loadActions() },
  ui32: function(event) { clearActionLogs() },
  ui33: function(event) { loadActionLogs() },
  ui34: function(event) { promptAddDevice() },
  ui35: function(event) { loadQuarantine() },
  ui36: function(event) { saveDhcpConfig() },
  ui37: function(event) { saveUpstreamConfig() },
  ui38: function(event) { toggleUpstream() },
  ui39: function(event) { ctxClassify('infrastructure') },
  ui40: function(event) { ctxClassify('destination') },
  ui41: function(event) { ctxClassify('reset') },
  ui42: function(event) { ctxBlock() },
  ui43: function(event) { ctxAllow() },
  ui44: function(event) { this.hidden=true },
  ui45: function(event) { setDeviceProfile(this.dataset.ip, this.value) },
  ui46: function(event) { removeDevice(this.dataset.ip) },
  ui48: function(event) { submitPolicy(this.dataset.action,this.dataset.domain) },
  ui49: function(event) { removePolicy(this.dataset.domain,this.dataset.global === 'true') },
  ui50: function(event) { toggleSchedule(this.dataset.id,this.checked) },
  ui51: function(event) { deleteSchedule(this.dataset.id) },
  ui52: function(event) { unquarantine(this.dataset.ip) },
  ui53: function(event) { deleteAction(this.dataset.domain) },
};
document.addEventListener('change', event => {
    const target = event.target.closest?.('[data-onchange]');
    const handler = target && uiHandlers[target.getAttribute('data-onchange')];
    if (handler && handler.call(target, event) === false) event.preventDefault();
}, false);
document.addEventListener('click', event => {
    const target = event.target.closest?.('[data-onclick]');
    const handler = target && uiHandlers[target.getAttribute('data-onclick')];
    if (handler && handler.call(target, event) === false) event.preventDefault();
}, false);
document.addEventListener('error', event => {
    const target = event.target.closest?.('[data-onerror]');
    const handler = target && uiHandlers[target.getAttribute('data-onerror')];
    if (handler && handler.call(target, event) === false) event.preventDefault();
}, true);
document.addEventListener('input', event => {
    const target = event.target.closest?.('[data-oninput]');
    const handler = target && uiHandlers[target.getAttribute('data-oninput')];
    if (handler && handler.call(target, event) === false) event.preventDefault();
}, false);
document.addEventListener('submit', event => {
    const target = event.target.closest?.('[data-onsubmit]');
    const handler = target && uiHandlers[target.getAttribute('data-onsubmit')];
    if (handler && handler.call(target, event) === false) event.preventDefault();
}, false);
