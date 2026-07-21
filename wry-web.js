// wry-web.js - wry合金防护 v3 Web 监控面板
// v2 变更（2026-07-04）：
//   1. 强制开启密码仅存储在后端，不暴露在前端 HTML 中
//   2. 强制开启按钮：后端验证密码后立即启用 RDP + 写 force_open.json
//   3. 强制取消：后端验证密码后删除 force_open.json
//   4. 端口状态用防火墙规则状态判断（更准确）
//   5. UI 优化：按钮状态动态联动、强制开启倒计时显示

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, exec } = require('child_process');

const FORCE_OPEN_DURATION_MS = 5 * 60 * 1000;
// 运行数据目录（SYSTEM 用户时回退到实际用户目录）
function getDataDir() {
    const homedir = os.homedir();
    if (!homedir.toLowerCase().includes('system32')) {
        return path.join(homedir, 'Documents');
    }
    const usersDir = 'C:\\Users';
    try {
        for (const name of fs.readdirSync(usersDir)) {
            if (['Public', 'Default', 'Default User', 'All Users'].includes(name)) continue;
            const docs = path.join(usersDir, name, 'Documents');
            if (fs.existsSync(docs) && fs.statSync(docs).isDirectory()) {
                return docs;
            }
        }
    } catch (_) {}
    return path.join(homedir, 'Documents');
}
const DATA_DIR = getDataDir();

// 「强制开启」密码：默认 147369，可用环境变量 RDP_GUARD_PASSWORD 覆盖。
const FORCE_OPEN_PASSWORD = process.env.RDP_GUARD_PASSWORD || '147369';
const FORCE_OPEN_FILE = path.join(DATA_DIR, 'rdp_force_open.json');

const STATE_FILE         = path.join(DATA_DIR, 'rdp_guard_state.json');
const LOG_FILE           = path.join(DATA_DIR, 'rdp_block.log');
const ATTACK_HISTORY_FILE = path.join(DATA_DIR, 'rdp_attack_history.json');
const SNAPSHOT_FILE = path.join(DATA_DIR, 'rdp_snapshots.json');
const HTML_FILE = __dirname + '\\wry-web.html';
const PORT = 19888;
const TZ = 'Asia/Shanghai';

function readJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return fallback; }
}

function atomicWrite(filePath, data) {
    const tmp = filePath + '.tmp.' + process.pid + '.' + Date.now() + '.tmp';
    try {
        fs.writeFileSync(tmp, data, 'utf8');
        fs.renameSync(tmp, filePath);
    } catch (e) {
        try { fs.unlinkSync(filePath); } catch (_) {}
        try { fs.writeFileSync(filePath, data, 'utf8'); } catch (_2) {}
    }
}

// 解码 PowerShell 输出（自动检测 UTF-16LE / UTF-8 / GB18030）
function decodePsOutput(buf) {
    if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
        return new TextDecoder('utf-16le').decode(buf.subarray(2));
    }
    const asUtf8 = new TextDecoder('utf-8', { fatal: false }).decode(buf);
    try { JSON.parse(asUtf8.trim()); return asUtf8; } catch (_) {}
    if (/[一-鿿]|True|False|Enabled|Disabled/i.test(asUtf8)) return asUtf8;
    return new TextDecoder('gb18030', { fatal: false }).decode(buf);
}

function psRaw(cmd) {
    try {
        const buf = execSync(cmd, { encoding: 'buffer', timeout: 15000, windowsHide: true, shell: 'powershell.exe' });
        return decodePsOutput(buf);
    } catch (_) { return ''; }
}

// 异步版：不阻塞事件循环，用于后台缓存刷新
function psAsync(cmd) {
    return new Promise((resolve) => {
        exec(cmd, { timeout: 15000, windowsHide: true, shell: 'powershell.exe', encoding: 'buffer' }, (err, stdout) => {
            if (err || !stdout) { resolve(''); return; }
            try { resolve(decodePsOutput(stdout)); } catch (_) { resolve(''); }
        });
    });
}

function formatTime(date) {
    return date.toLocaleString('zh-CN', { timeZone: TZ });
}

function getRDPOpenCount() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try { return parseInt(out.trim(), 10) || 0; } catch (_) { return 0; }
}

function getRDPClosedCount() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled False | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try { return parseInt(out.trim(), 10) || 0; } catch (_) { return 0; }
}

function enableRDPRules() {
    // 尝试启用原有规则
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled False | Enable-NetFirewallRule; ' +
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count'
    );
    let enabledCount = 0;
    try {
        const lines = out.trim().split('\n');
        enabledCount = parseInt(lines[lines.length - 1].trim(), 10) || 0;
    } catch (_) {}
    // 如果没有规则成功启用，创建兜底规则
    if (enabledCount === 0) {
        psRaw("New-NetFirewallRule -DisplayName 'wry合金防护-兜底RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Group '@FirewallAPI.dll,-28752'");
        enabledCount = 1;
    }
    return enabledCount;
}

function disableRDPRules() {
    const out = psRaw(
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Disable-NetFirewallRule; ' +
        'Get-NetFirewallRule -Group \'@FirewallAPI.dll,-28752\' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count'
    );
    try {
        const lines = out.trim().split('\n');
        return parseInt(lines[lines.length - 1].trim(), 10) || 0;
    } catch (_) { return 0; }
}

function getState() {
    return readJson(STATE_FILE, { blockedAt: null, lastFailCount: 0, lastTotal: 0, blockedIPs: [] });
}

function getForceOpen() {
    const fo = readJson(FORCE_OPEN_FILE, null);
    if (!fo || !fo.until) return { active: false };
    const remaining = fo.until - Date.now();
    if (remaining <= 0) {
        try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
        return { active: false };
    }
    return { active: true, since: fo.since, until: fo.until, remainingMs: remaining };
}

function getRecentLogs() {
    try {
        const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(l => l.trim());
        return lines.slice(-50).reverse().map(l => {
            let type = 'info';
            if (l.includes('触发防护') || l.includes('\uD83D\uDD12')) type = 'danger';
            else if (l.includes('已恢复') || l.includes('\uD83D\uDD10') || l.includes('\uD83D\uDD13')) type = 'success';
            else if (l.includes('\u26A0') || l.includes('LAN') || l.includes('强制开启')) type = 'warning';
            return { text: l, type };
        });
    } catch (_) { return []; }
}

// 健康检查：防火墙状态、guard 运行状态
function getHealth() {
    const warnings = [];

    // 1. 检查 Windows 防火墙是否启用（当前网络配置文件）
    const fwOut = psRaw('Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false } | Select-Object -ExpandProperty Name');
    if (fwOut && fwOut.trim()) {
        const disabled = fwOut.trim().split('\n').map(s => s.trim()).filter(Boolean);
        if (disabled.length > 0) {
            warnings.push({ level: 'critical', msg: 'Windows 防火墙已关闭: ' + disabled.join(', ') + '。防护规则无效，RDP 端口完全裸露！' });
        }
    }

    // 2. 检查 guard 快照是否最近（5 分钟内有更新说明 guard 在运行）
    try {
        const snapshots = readJson(SNAPSHOT_FILE, []);
        if (snapshots.length > 0) {
            const last = snapshots[snapshots.length - 1];
            const age = (Date.now() - last.ts) / 1000;
            if (age > 300) {
                warnings.push({ level: 'warning', msg: `Guard 超过 ${Math.floor(age/60)} 分钟未更新快照，可能未正常运行` });
            }
        } else {
            warnings.push({ level: 'warning', msg: '无 Guard 快照数据，可能从未运行过' });
        }
    } catch (_) {}

    // 3. 检查 RDP 端口是否在监听
    try {
        const netstat = psRaw('Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count');
        const listenCount = parseInt(netstat.trim(), 10) || 0;
        const status = cache.status;
        if (status && status.status === 'BLOCKED' && listenCount > 0) {
            warnings.push({ level: 'warning', msg: '状态显示已封禁，但 RDP 端口仍在监听' });
        }
    } catch (_) {}

    return { ok: warnings.length === 0, warnings };
}

function getHistory() {
    const history = readJson(ATTACK_HISTORY_FILE, []);
    return history.slice(-30).reverse().map(h => ({
        ts: h.ts,
        time: h.time,
        total: h.total,
        ipCounts: h.ipCounts || {},
        userCounts: h.userCounts || {},
        statusCounts: h.statusCounts || {},
    }));
}

function getStatus() {
    const state = getState();
    const openCount = getRDPOpenCount();
    const closedCount = getRDPClosedCount();
    const total = openCount + closedCount;
    let portState = 'unknown';
    if (total > 0) portState = openCount > 0 ? 'open' : 'blocked';
    const blockedAt = state.blockedAt ? new Date(state.blockedAt) : null;
    let blockedRemaining = null;
    if (blockedAt) {
        const elapsed = (Date.now() - blockedAt.getTime()) / 60000;
        const remaining = Math.max(0, Math.ceil(5 - elapsed));
        if (remaining > 0) blockedRemaining = remaining;
    }
    // forceOpen
    const forceOpen = getForceOpen();
    let status = 'NORMAL';
    let forceOpenRemaining = null;
    let forceOpenUntil = null;
    if (forceOpen.active) {
        status = 'FORCE_OPEN';
        forceOpenRemaining = forceOpen.remainingMs;
        forceOpenUntil = formatTime(new Date(forceOpen.until));
    } else if (blockedAt && blockedRemaining) {
        status = 'BLOCKED';
    }
    return { status, portState, openCount, closedCount, total, blockedAt, blockedRemaining, forceOpenRemaining, forceOpenUntil, lastFailCount: state.lastFailCount, blockedIPs: state.blockedIPs || [], threshold: 3, lookback: 60 };
}

function loadHtml() {
    try { return fs.readFileSync(HTML_FILE, 'utf8'); } catch (_) { return '<h1>wry合金防护 v3</h1><p>HTML 文件未找到</p>'; }
}

// ===== 互斥标志 =====
let forceOpenInProgress = false;

// ===== 后台缓存：异步采集，HTTP 请求零延迟 =====
const cache = { status: null, logs: [], history: [], forceOpen: null, health: { ok: true, warnings: [] }, ts: 0 };
const CACHE_INTERVAL = 15000;  // 15秒刷新

async function refreshStatusAsync() {
    try {
        const [openOut, closedOut] = await Promise.all([
            psAsync("Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled True | Measure-Object | Select-Object -ExpandProperty Count"),
            psAsync("Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled False | Measure-Object | Select-Object -ExpandProperty Count"),
        ]);
        const openCount = parseInt((openOut || '').trim(), 10) || 0;
        const closedCount = parseInt((closedOut || '').trim(), 10) || 0;
        const total = openCount + closedCount;
        let portState = 'unknown';
        if (total > 0) portState = openCount > 0 ? 'open' : 'blocked';

        const state = readJson(STATE_FILE, { blockedAt: null, lastFailCount: 0 });
        const blockedAt = state.blockedAt ? new Date(state.blockedAt) : null;
        let blockedRemaining = null;
        if (blockedAt) {
            const elapsed = (Date.now() - blockedAt.getTime()) / 60000;
            const remaining = Math.max(0, Math.ceil(5 - elapsed));
            if (remaining > 0) blockedRemaining = remaining;
        }
        const fo = readJson(FORCE_OPEN_FILE, null);
        let status = 'NORMAL', forceOpenRemaining = null, forceOpenUntil = null;
        if (fo && fo.until && fo.until > Date.now()) {
            status = 'FORCE_OPEN';
            forceOpenRemaining = fo.until - Date.now();
            forceOpenUntil = formatTime(new Date(fo.until));
        } else if (blockedAt && blockedRemaining) {
            status = 'BLOCKED';
        }
        cache.status = { status, portState, openCount, closedCount, total, blockedAt, blockedRemaining, forceOpenRemaining, forceOpenUntil, lastFailCount: state.lastFailCount || 0, blockedIPs: state.blockedIPs || [], threshold: 3, lookback: 60 };
        cache.forceOpen = fo && fo.until > Date.now() ? { active: true, since: fo.since, until: fo.until, remainingMs: fo.until - Date.now() } : { active: false };
    } catch (_) {}
    try { cache.logs = getRecentLogs(); } catch (_) {}
    try { cache.history = getHistory(); } catch (_) {}
    try { cache.health = getHealth(); } catch (_) {}
    cache.ts = Date.now();
}

// 快速初始填充（不含 PowerShell，秒级可用）
function quickInitCache() {
    const state = readJson(STATE_FILE, { blockedAt: null, lastFailCount: 0 });
    const fo = readJson(FORCE_OPEN_FILE, null);
    let status = 'NORMAL';
    const blockedAt = state.blockedAt ? new Date(state.blockedAt) : null;
    if (fo && fo.until && fo.until > Date.now()) status = 'FORCE_OPEN';
    else if (blockedAt && Date.now() - blockedAt.getTime() < 5 * 60 * 1000) status = 'BLOCKED';
    cache.status = { status, portState: 'unknown', openCount: -1, closedCount: -1, total: -1, blockedRemaining: null, lastFailCount: state.lastFailCount || 0, blockedIPs: state.blockedIPs || [], threshold: 3, lookback: 60 };
    cache.forceOpen = fo && fo.until > Date.now() ? { active: true, since: fo.since, until: fo.until, remainingMs: fo.until - Date.now() } : { active: false };
    try { cache.logs = getRecentLogs(); } catch (_) {}
    try { cache.history = getHistory(); } catch (_) {}
    cache.ts = Date.now();
}

// 初始填充
quickInitCache();
// 后台异步刷新（含 PowerShell 防火墙规则查询）
setTimeout(refreshStatusAsync, 2000);
setInterval(refreshStatusAsync, CACHE_INTERVAL);

const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1:' + PORT);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        // 将初始缓存数据注入 <body> 最前，转义 </ 防止提前关闭 script 标签
        const preload = JSON.stringify({ s: cache.status, h: cache.history, l: cache.logs, health: cache.health })
            .replace(RegExp('</','g'), '<\\/');  // 防止 </script> 等标签误关闭
        const html = loadHtml().replace('<body>', '<body><script>window.__PRELOAD__=' + preload + ';</script>');
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
        res.end(html); return;
    }

    const sendJson = (data, status) => {
        res.writeHead(status || 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
    };

    if (req.method === 'GET' && url.pathname === '/api/status') {
        sendJson(cache.status); return;
    }

    if (req.method === 'GET' && url.pathname === '/api/force-open') {
        const fo = cache.forceOpen || getForceOpen();
        if (!fo || !fo.active) { sendJson({ active: false }); return; }
        sendJson({ active: true, since: new Date(fo.since).toLocaleString('zh-CN', { timeZone: TZ }), until: new Date(fo.until).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: fo.remainingMs }); return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-open') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            if (forceOpenInProgress) { sendJson({ ok: false, error: '操作进行中，请稍候' }, 429); return; }
            forceOpenInProgress = true;
            try {
                const fo = getForceOpen();
                if (fo.active) { sendJson({ ok: false, error: '强制开启已生效，无需重复开启', until: new Date(fo.until).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: fo.remainingMs }); return; }
                const restored = enableRDPRules();
                const now = Date.now();
                atomicWrite(FORCE_OPEN_FILE, JSON.stringify({ since: now, until: now + FORCE_OPEN_DURATION_MS }));
                let state = getState();
                if (state.blockedAt) { state.blockedAt = null; state.lastFailCount = 0; atomicWrite(STATE_FILE, JSON.stringify(state, null, 2)); }
                sendJson({ ok: true, since: new Date(now).toLocaleString('zh-CN', { timeZone: TZ }), until: new Date(now + FORCE_OPEN_DURATION_MS).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: FORCE_OPEN_DURATION_MS, restored });
                cache.ts = 0; setTimeout(() => refreshStatusAsync(), 2000);
            } finally {
                forceOpenInProgress = false;
            }
        });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-close') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            const closed = disableRDPRules();
            let state = getState();
            state.blockedAt = new Date().toISOString();
            atomicWrite(STATE_FILE, JSON.stringify(state, null, 2));
            // 清除 force-open 状态，防止 guard 下次运行时覆盖
            try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
            sendJson({ ok: true, closed, message: 'RDP 端口已手动关闭，5 分钟后自动恢复' });
            cache.ts = 0; setTimeout(() => refreshStatusAsync(), 2000);
        });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/force-cancel') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            const fo = getForceOpen();
            if (!fo.active) { sendJson({ ok: false, error: '强制开启未激活，无需取消' }); return; }
            // 仅取消「强制开启」覆盖，不关闭端口——交还控制权给 guard，
            // guard 下一轮按真实状态接管（若仍在遭攻击将重新关闭端口，否则保持开启）。
            try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
            sendJson({ ok: true, message: '已取消强制开启，guard 将在下一轮按真实状态接管（若正遭攻击将重新关闭端口）' });
            cache.ts = 0; setTimeout(() => refreshStatusAsync(), 2000);
        });
        return;
    }

    if (req.method === 'GET' && url.pathname === '/api/logs') { sendJson(cache.logs); return; }
    if (req.method === 'GET' && url.pathname === '/api/log')  { sendJson(cache.logs); return; }
    if (req.method === 'GET' && url.pathname === '/api/history') { sendJson(cache.history); return; }
    if (req.method === 'GET' && url.pathname === '/api/health') { sendJson(cache.health || { ok: true, warnings: [] }); return; }

    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
    console.log('\uD83D\uDEE1 wry\u5408\u91D1\u9632\u62A4 Web \u76D1\u63A7\u5DF2\u542F\u52A8: http://127.0.0.1:' + PORT + '（仅本机可访问）');
});
