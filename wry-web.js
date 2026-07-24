// wry-web.js - wry合金防护 v3 Web 监控面板
// v2 变更（2026-07-04）：
//   1. 强制开启密码仅存储在后端，不暴露在前端 HTML 中
//   2. 强制开启按钮：后端验证密码后立即启用 RDP + 写 force_open.json
//   3. 强制取消：后端验证密码后删除 force_open.json
//   4. 端口状态用防火墙规则状态判断（更准确）
//   5. UI 优化：按钮状态动态联动、强制开启倒计时显示
// v3.8 变更（2026-07-21）：启动自清理遗留的「wry合金防护-兜底RDP」重复规则；
//   启用规则仅在整组为空（原厂规则被误删）时才新建兜底规则，避免重复堆积
// v3.9 变更（2026-07-22）：RDP 规则启用/禁用改为批量异步执行 + 60s 超时，
//   避免多次 spawn powershell 导致请求超时/连接丢失；缓存刷新改用可靠的整组查询
// v3.10 变更（2026-07-22）：启用/禁用与结果校验在同一 PowerShell 会话内完成，
//   避免跨会话查询延迟导致误判开启/关闭失败

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, exec } = require('child_process');

const FORCE_OPEN_DURATION_MS = 5 * 60 * 1000;
const REOPEN_MINUTES = 5;        // 攻击封禁后自动恢复时间（分钟）
const THRESHOLD = 5;             // 触发关闭端口的同 IP 失败次数阈值
const LOOKBACK = 30;             // 回溯时间窗口（秒）
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

function psRaw(cmd, timeoutMs) {
    try {
        const buf = execSync(cmd, { encoding: 'buffer', timeout: timeoutMs || 30000, windowsHide: true, shell: 'powershell.exe' });
        return decodePsOutput(buf);
    } catch (_) { return ''; }
}

// 异步版：不阻塞事件循环，用于后台缓存刷新
function psAsync(cmd, timeoutMs) {
    return new Promise((resolve) => {
        exec(cmd, { timeout: timeoutMs || 30000, windowsHide: true, shell: 'powershell.exe', encoding: 'buffer' }, (err, stdout) => {
            if (err || !stdout) { resolve(''); return; }
            try { resolve(decodePsOutput(stdout)); } catch (_) { resolve(''); }
        });
    });
}

function formatTime(date) {
    return date.toLocaleString('zh-CN', { timeZone: TZ });
}

// 取出 RDP 组全部入站 Allow 规则及其 Enabled 状态。
// 关键：不在这里用 -Enabled 过滤——当 0 条匹配时 Get-NetFirewallRule -Enabled X 会直接抛错，
// 被 psRaw 吞掉后返回 ''，导致「禁用成功(剩0)」与「查询失败(也是0)」无法区分。
// 改为一次性取出后在 JS 里判断 Enabled，0 条时也只是返回空数组，不会报错。
function getRDPRulesRaw() {
    const out = psRaw(
        "Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    );
    let arr = [];
    try { arr = JSON.parse(out); } catch (_) { return []; }
    if (!Array.isArray(arr)) arr = (arr && arr.Name) ? [arr] : [];
    return arr.map(r => ({ name: r.Name, enabled: r.Enabled === true || r.Enabled === 'True' || r.Enabled === 1 || r.Enabled === '1' }));
}

function getRDPOpenCount() {
    try { return getRDPRulesRaw().filter(r => r.enabled).length; } catch (_) { return 0; }
}

function getRDPClosedCount() {
    try { return getRDPRulesRaw().filter(r => !r.enabled).length; } catch (_) { return 0; }
}

async function getRDPRulesAsync() {
    const out = await psAsync("Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow | Select-Object Name,Enabled | ConvertTo-Json -Compress", 30000);
    let arr = [];
    try { arr = JSON.parse(out); } catch (_) { return []; }
    if (!Array.isArray(arr)) arr = (arr && arr.Name) ? [arr] : [];
    return arr.map(r => ({ name: r.Name, enabled: r.Enabled === true || r.Enabled === 'True' || r.Enabled === 1 || r.Enabled === '1' }));
}

// 在同一 PowerShell 会话内完成规则启用/禁用并立即校验结果，
// 避免跨会话查询延迟/缓存导致误判，也避免多次 spawn powershell 超时
async function runFirewallMutation(type, rules) {
    if (rules.length === 0) return { mutated: 0, openCount: getRDPOpenCount() };
    const names = rules.map(r => r.name.replace(/'/g, "''"));
    const action = type === 'Enable' ? 'Enable-NetFirewallRule' : 'Disable-NetFirewallRule';
    const cmdParts = names.map(n => `${action} -Name '${n}'`);
    const verify = "Start-Sleep -Milliseconds 600; $open = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow | Where-Object { $_.Enabled -eq 'True' } | Measure-Object | Select-Object -ExpandProperty Count; $open";
    const script = cmdParts.join('; ') + '; ' + verify;
    const out = await psAsync(script, 60000);
    const openCount = parseInt((out || '').trim(), 10) || 0;
    return { mutated: rules.length, openCount };
}

async function enableRDPRules() {
    const rules = getRDPRulesRaw().filter(r => !r.enabled);
    let mutated = 0;
    let openCount = getRDPOpenCount();
    if (rules.length > 0) {
        const res = await runFirewallMutation('Enable', rules);
        mutated = res.mutated;
        openCount = res.openCount;
    }
    // 兜底：仅当整组规则都不存在（原厂 RDP 规则被误删）时才新建一条
    if (getRDPRulesRaw().length === 0) {
        await psAsync("New-NetFirewallRule -DisplayName 'wry合金防护-兜底RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Group '@FirewallAPI.dll,-28752'", 60000);
        mutated++;
        openCount = 1;
    }
    return { mutated, openCount };
}

async function disableRDPRules() {
    const rules = getRDPRulesRaw().filter(r => r.enabled);
    if (rules.length === 0) return { mutated: 0, openCount: getRDPOpenCount() };
    return await runFirewallMutation('Disable', rules);
}

// 清理测试/历史遗留的兜底规则：仅当原厂 RDP 规则（RemoteDesktop-*）仍存在时才移除，
// 防止重复堆积（每次「启用失败」会新建一条同名兜底规则）。需 SYSTEM 权限才能 Remove。
function cleanupFallbackRules() {
    try {
        const hasOriginal = getRDPRulesRaw().some(r => r.name && r.name.startsWith('RemoteDesktop'));
        if (!hasOriginal) return 0;
        const out = psRaw("Get-NetFirewallRule -DisplayName 'wry合金防护-兜底RDP' | Select-Object Name | ConvertTo-Json -Compress");
        let arr = [];
        try { arr = JSON.parse(out); } catch (_) { return 0; }
        if (!Array.isArray(arr)) arr = (arr && arr.Name) ? [arr] : [];
        if (arr.length === 0) return 0;
        const script = arr.map(r => `Remove-NetFirewallRule -Name '${String(r.Name).replace(/'/g, "''")}'`).join('; ');
        psRaw(script, 60000);
        return arr.length;
    } catch (_) { return 0; }
}

function getState() {
    return readJson(STATE_FILE, { blockedAt: null, closeReason: null, lastFailCount: 0, lastTotal: 0, blockedIPs: [] });
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

function shanghaiDateStr(ts) {
    // 返回 Asia/Shanghai 时区的日期字符串 YYYY-MM-DD（用于按天归并与每日 0:00 重置）
    try { return new Date(ts).toLocaleDateString('en-CA', { timeZone: 'Asia/Shanghai' }); }
    catch (_) { return new Date(ts).toISOString().slice(0, 10); }
}
function isTodayTs(ts) {
    return shanghaiDateStr(ts) === shanghaiDateStr(Date.now());
}

// 仅返回“今天”（Asia/Shanghai）的攻击事件，按时间倒序；每日 0:00 自然重置
function getHistory() {
    const history = readJson(ATTACK_HISTORY_FILE, []);
    const today = history
        .filter(h => h.ts && isTodayTs(h.ts))
        .sort((a, b) => b.ts - a.ts);
    return today.map(h => ({
        ts: h.ts,
        time: h.time,
        total: h.total,
        ipCounts: h.ipCounts || {},
        userCounts: h.userCounts || {},
        statusCounts: h.statusCounts || {},
    }));
}

// 根据防火墙规则计数 + 状态文件 + 强制开启文件，推导统一的面板状态机
function deriveStatus({ openCount, closedCount, state, forceOpen }) {
    const total = openCount + closedCount;
    let portState = 'unknown';
    if (total > 0) portState = openCount > 0 ? 'open' : 'blocked';
    const blockedAt = state && state.blockedAt ? new Date(state.blockedAt) : null;
    const closeReason = (state && state.closeReason) || 'attack';
    let status = 'NORMAL';
    let blockedRemaining = null;
    let blockedRemainingMs = null;
    let forceOpenRemaining = null;
    let forceOpenUntil = null;
    if (forceOpen && forceOpen.active) {
        status = 'FORCE_OPEN';
        forceOpenRemaining = forceOpen.remainingMs;
        forceOpenUntil = formatTime(new Date(forceOpen.until));
    } else if (blockedAt) {
        const elapsedMs = Date.now() - blockedAt.getTime();
        if (closeReason === 'manual') {
            status = 'MANUAL_CLOSED';        // 用户手动关闭：保持关闭，绝不自动恢复
        } else {
            status = 'BLOCKED';              // 攻击封禁：倒计时自动恢复
            const remainingMs = Math.max(0, REOPEN_MINUTES * 60000 - elapsedMs);
            blockedRemainingMs = remainingMs;
            blockedRemaining = Math.ceil(remainingMs / 60000);
        }
    }
    return {
        status, portState, openCount, closedCount, total,
        blockedAt, blockedRemaining, blockedRemainingMs,
        forceOpenRemaining, forceOpenUntil,
        lastFailCount: (state && state.lastFailCount) || 0,
        blockedIPs: (state && state.blockedIPs) || [],
        closeReason,
        threshold: THRESHOLD, lookback: LOOKBACK,
    };
}

function getStatus() {
    return deriveStatus({
        openCount: getRDPOpenCount(),
        closedCount: getRDPClosedCount(),
        state: getState(),
        forceOpen: getForceOpen(),
    });
}

function loadHtml() {
    try { return fs.readFileSync(HTML_FILE, 'utf8'); } catch (_) { return '<h1>wry合金防护 v3</h1><p>HTML 文件未找到</p>'; }
}

// ===== 互斥标志 =====
let forceOpenInProgress = false;
let closeInProgress = false;

// ===== 后台缓存：异步采集，HTTP 请求零延迟 =====
const cache = { status: null, logs: [], history: [], forceOpen: null, health: { ok: true, warnings: [] }, ts: 0 };
const CACHE_INTERVAL = 15000;  // 15秒刷新

let refreshInProgress = false;
async function refreshStatusAsync() {
    if (refreshInProgress) return;
    refreshInProgress = true;
    try {
        const rules = await getRDPRulesAsync();
        const openCount = rules.filter(r => r.enabled).length;
        const closedCount = rules.filter(r => !r.enabled).length;
        const state = getState();
        const fo = getForceOpen();
        cache.status = deriveStatus({ openCount, closedCount, state, forceOpen: fo });
        cache.forceOpen = fo.active ? { active: true, since: fo.since, until: fo.until, remainingMs: fo.remainingMs } : { active: false };
        try { cache.logs = getRecentLogs(); } catch (_) {}
        try { cache.history = getHistory(); } catch (_) {}
        try { cache.health = getHealth(); } catch (_) {}
        cache.ts = Date.now();
    } finally {
        refreshInProgress = false;
    }
}

// 快速初始填充（不含 PowerShell，秒级可用）
function quickInitCache() {
    const state = getState();
    const fo = getForceOpen();
    cache.status = deriveStatus({ openCount: -1, closedCount: -1, state, forceOpen: fo });
    cache.forceOpen = fo.active ? { active: true, since: fo.since, until: fo.until, remainingMs: fo.remainingMs } : { active: false };
    try { cache.logs = getRecentLogs(); } catch (_) {}
    try { cache.history = getHistory(); } catch (_) {}
    cache.ts = Date.now();
}

// 初始填充
quickInitCache();
// 启动时清理遗留的兜底规则（仅 SYSTEM 身份下能 Remove），保持规则列表干净
try {
    const removed = cleanupFallbackRules();
    if (removed > 0) console.log(`已清理 ${removed} 条遗留兜底规则`);
} catch (_) {}
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
        req.on('end', async () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            if (forceOpenInProgress) { sendJson({ ok: false, error: '操作进行中，请稍候' }, 429); return; }
            forceOpenInProgress = true;
            try {
                const fo = getForceOpen();
                if (fo.active) { sendJson({ ok: false, error: '强制开启已生效，无需重复开启', until: new Date(fo.until).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: fo.remainingMs }); return; }
                const { mutated: restored, openCount } = await enableRDPRules();
                // 验证：开启后必须至少有一条 RDP 规则处于启用状态，否则视为失败
                if (openCount === 0) {
                    sendJson({ ok: false, error: '开启失败：无法启用任何 RDP 规则（可能权限不足或被系统保护）' }, 500);
                    return;
                }
                const now = Date.now();
                atomicWrite(FORCE_OPEN_FILE, JSON.stringify({ since: now, until: now + FORCE_OPEN_DURATION_MS }));
                let state = getState();
                if (state.blockedAt) { state.blockedAt = null; state.closeReason = null; state.lastFailCount = 0; atomicWrite(STATE_FILE, JSON.stringify(state, null, 2)); }
                sendJson({ ok: true, since: new Date(now).toLocaleString('zh-CN', { timeZone: TZ }), until: new Date(now + FORCE_OPEN_DURATION_MS).toLocaleString('zh-CN', { timeZone: TZ }), remainingMs: FORCE_OPEN_DURATION_MS, restored });
                cache.ts = 0; setTimeout(() => refreshStatusAsync(), 2000);
            } finally {
                forceOpenInProgress = false;
            }
        });
        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/close') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', async () => {
            let json = {};
            try { json = JSON.parse(body); } catch (_) {}
            if (!json.password) { sendJson({ ok: false, error: '请提供密码' }, 400); return; }
            if (json.password !== FORCE_OPEN_PASSWORD) { sendJson({ ok: false, error: '密码错误' }, 401); return; }
            if (closeInProgress) { sendJson({ ok: false, error: '操作进行中，请稍候' }, 429); return; }
            closeInProgress = true;
            try {
                const { mutated: closed, openCount: stillOpen } = await disableRDPRules();
                // 验证：禁用后必须没有任何 RDP 规则处于启用状态，否则视为失败
                if (stillOpen > 0) {
                    sendJson({ ok: false, error: `关闭失败：仍有 ${stillOpen} 条 RDP 规则处于启用状态（可能权限不足或被系统保护）` }, 500);
                    return;
                }
                const now = new Date();
                let state = getState();
                // 手动关闭：标记为 manual，guard 不会自动恢复，端口保持关闭直到用户强制开启
                state.blockedAt = now.toISOString();
                state.closeReason = 'manual';
                state.blockedIPs = [];
                state.lastFailCount = 0;
                atomicWrite(STATE_FILE, JSON.stringify(state, null, 2));
                // 清除可能存在的强制开启状态
                try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
                const closeMsg = closed > 0
                    ? `RDP 端口已关闭（已禁用 ${closed} 条规则，不会自动恢复，需强制开启才能重新打开）`
                    : `RDP 端口当前已处于关闭状态（不会自动恢复，需强制开启才能重新打开）`;
                sendJson({ ok: true, closed, message: closeMsg });
                cache.ts = 0; setTimeout(() => refreshStatusAsync(), 2000);
            } finally {
                closeInProgress = false;
            }
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
