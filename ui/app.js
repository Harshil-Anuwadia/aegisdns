// ================================================================
// AegisDNS Dashboard — app.js  (stable, professional)
// ================================================================

const API = '/api';
let currentView   = 'dashboard';
let currentDevice = '';   // IP string or '' for all
let myIp          = '';   // auto-detected client IP
let policyRules   = { allowed:[], denied:{}, device_allowed:{}, device_denied:{} };

// ── Init ──────────────────────────────────────────────────────
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

// ── My Device Banner ──────────────────────────────────────────
function updateMyDeviceBanner() {
    const banner = document.getElementById('my-device-banner');
    const ipEl   = document.getElementById('my-device-ip');
    if (!banner) return;
    if (currentDevice && currentDevice === myIp) {
        banner.style.display = 'flex';
        if (ipEl) ipEl.textContent = myIp;
    } else if (!currentDevice && myIp) {
        // Showing all — still show a banner mentioning their device
        banner.style.display = 'none';
    } else {
        banner.style.display = 'none';
    }
}

// ── Navigation ────────────────────────────────────────────────
function setupNav() {
    const titles = { dashboard:'Dashboard', policy:'Policy Rules', blocklists:'Blocklists', schedules:'Schedules', tools:'Tools' };
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

// ── Per-view refresh ──────────────────────────────────────────
function refreshView() {
    if (currentView === 'dashboard') {
        loadStats(); loadTopDomains(); loadTopBlocked(); loadThreatStatus();
        loadSafeSearch(); loadBlocklistsDash();
    } else if (currentView === 'policy') {
        loadPolicy(); loadDevicesForDrops();
    } else if (currentView === 'blocklists') {
        loadBlocklistsPage();
    } else if (currentView === 'schedules') {
        loadSchedules(); loadDevicesForDrops();
    }
}

// ── Helpers ───────────────────────────────────────────────────
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

// ── Device Selectors ──────────────────────────────────────────
async function loadDevices() {
    try {
        const r = await fetch(`${API}/devices`);
        const devices = await r.json() || [];
        populateDeviceSelects(devices);
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
        let h = includeAll ? '<option value="">All Devices</option>' : '<option value="">Global — All Devices</option>';
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

// ── Stats ─────────────────────────────────────────────────────
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
    } catch (e) { console.error('loadStats', e); }
}

// ── Top Domains ───────────────────────────────────────────────
async function loadTopDomains() {
    try {
        const r = await fetch(`${API}/top-domains${qs()}`);
        const data = await r.json() || [];
        if (!data.length) { setHtml('list-top-domains', '<div class="empty-state">No queries recorded yet.</div>'); return; }
        setHtml('list-top-domains', data.map(d =>
            domainRow(d.domain, `<span class="d-count">${fmt(d.count)}</span>`)
        ).join(''));
    } catch (e) { console.error('loadTopDomains', e); }
}

// ── Top Blocked ───────────────────────────────────────────────
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

// ── Threat Status ─────────────────────────────────────────────
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

// ── Safe Search ───────────────────────────────────────────────
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

// ── Blocklists ────────────────────────────────────────────────
async function loadBlocklistsDash() {
    try {
        const r = await fetch(`${API}/lists`);
        const data = await r.json() || [];
        if (!data.length) { setHtml('list-blocklists-dash', '<div class="empty-state">No blocklists configured.</div>'); return; }
        setHtml('list-blocklists-dash', data.map(l => `
          <div class="d-row">
            <div class="d-left">
              <span class="badge ${l.enabled ? 'badge-green' : 'badge-gray'}">${l.enabled ? 'Active' : 'Off'}</span>
              <span class="d-name">${l.name}</span>
            </div>
            <span class="d-count">${fmt(l.rule_count)} rules</span>
          </div>`).join(''));
    } catch (e) { console.error('loadBlocklistsDash', e); }
}

async function loadBlocklistsPage() {
    try {
        const r = await fetch(`${API}/lists`);
        const data = await r.json() || [];
        const tbody = document.querySelector('#tbl-blocklists tbody');
        if (!tbody) return;
        if (!data.length) { tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No blocklists.</td></tr>'; return; }
        tbody.innerHTML = data.map(l => `
          <tr>
            <td><span class="badge ${l.enabled ? 'badge-green' : 'badge-gray'}">${l.enabled ? 'Active' : 'Off'}</span></td>
            <td>${l.name}</td>
            <td class="num">${fmt(l.rule_count)}</td>
          </tr>`).join('');
    } catch (e) { console.error('loadBlocklistsPage', e); }
}

// ── Policy Rules ──────────────────────────────────────────────
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

// ── Schedules ─────────────────────────────────────────────────
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
                <div class="sched-meta">${sh}:${sm} – ${eh}:${em} &nbsp;&middot;&nbsp; ${dstr}</div>
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
    const label = `${action.toUpperCase()} ${domain} (${sh}:${sm}–${eh}:${em})`;
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

// ── Diagnostics ───────────────────────────────────────────────
async function submitDiagnose() {
    const domain = sanitize(document.getElementById('diag-input').value);
    if (!domain) return;
    const el = document.getElementById('diag-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'Analyzing…';
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

// ── Risk Check ────────────────────────────────────────────────
async function submitRiskCheck() {
    const domain = sanitize(document.getElementById('risk-input').value);
    if (!domain) return;
    const el = document.getElementById('risk-result');
    el.hidden = false; el.className = 'result-box result-info'; el.textContent = 'Analyzing…';
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

// ── Fallback ──────────────────────────────────────────────────
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
