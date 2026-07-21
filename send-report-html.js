// send-report-html.js - wry合金防护 半天可视化安全报告
// 8:00 报告覆盖 00:00-11:59（上半天） | 20:00 报告覆盖 12:00-23:59（下半天）
// 也可手动指定 --period=am|pm
// UTC 时间 → 上海时间转换
const nodemailer = require('nodemailer');
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// 与 rdp-guard.js 保持一致：封禁（关闭端口）后自动恢复时长（分钟）
const REOPEN_MINUTES = 5;

// [FIX 2026-07-04] 添加数据文件路径常量
const ATTACK_HISTORY_FILE = os.homedir() + '\\Documents\\rdp_attack_history.json';
const SNAPSHOT_FILE = os.homedir() + '\\Documents\\rdp_snapshots.json';

// ============= 配置区（敏感信息通过环境变量 / rdp_guard_mail.json 设置）=============
// 读取顺序：环境变量 > rdp_guard_mail.json（DATA_DIR 下）> 内置默认值
const MAIL_CFG_FILE = os.homedir() + '\\Documents\\rdp_guard_mail.json';
function loadMailConfig() {
    let file = {};
    try { file = JSON.parse(fs.readFileSync(MAIL_CFG_FILE, 'utf8')); } catch (_) {}
    const secureRaw = process.env.SMTP_SECURE !== undefined ? process.env.SMTP_SECURE
                    : (file.secure !== undefined ? file.secure : true);
    return {
        host:   process.env.SMTP_HOST  || file.host  || 'smtp.yeah.net',
        port:   parseInt(process.env.SMTP_PORT || file.port || '465', 10),
        secure: (secureRaw === true || secureRaw === 'true' || secureRaw === 1),
        user:   process.env.SMTP_USER  || file.user  || 'jianhx_claw@yeah.net',
        pass:   process.env.SMTP_PASS  || file.pass  || '',
        to:     process.env.REPORT_TO_EMAIL || file.to || 'jianhx189@163.com',
    };
}
// ==================================

// 决定报告覆盖哪半天
function getReportPeriod() {
    const arg = (process.argv.find(a => a.startsWith('--period=')) || '').split('=')[1];
    const now = new Date();
    // 转为上海时间
    const shanghai = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
    const hour = shanghai.getHours();
    if (arg === 'am' || arg === 'pm') return { period: arg, now: shanghai };
    return { period: hour < 12 ? 'am' : 'pm', now: shanghai };
}

// ============================================================================
// 数据源 1：Windows Security Event ID 4625（日志直接查询）
// ============================================================================
function getEventsFromSecurityLog() {
    let text;
    try {
        const buf = execSync(
            'wevtutil qe Security /f:text /q:"*[System[EventID=4625]]" /c:10000 /rd:true',
            { encoding: 'buffer', maxBuffer: 200 * 1024 * 1024, windowsHide: true }
        );
        text = new TextDecoder('gb18030', { fatal: false }).decode(buf);
    } catch (e) {
        console.warn('⚠ wevtutil 查询失败（可能权限不足或日志为空）：', e.message);
        text = '';
    }
    const blocks = text.split(/^Event\[\d+\]\s*$/m).filter(b => b.trim());
    return { blocks, source: 'SecurityLog', count: blocks.length };
}

// ============================================================================
// 数据源 2：attack_history.json（guard 触发防护时的持久化记录）
// [FIX 2026-07-04] 当 Security 日志为空时，从持久化记录回填
// ============================================================================
function getEventsFromHistory(periodStart, periodEnd, todayStr) {
    const result = { events: [], ips: {}, users: {}, statuses: {}, hours: {} };
    try {
        const history = JSON.parse(fs.readFileSync(ATTACK_HISTORY_FILE, 'utf8'));
        for (const h of history) {
            const t = new Date(h.time || new Date(h.ts).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }));
            const d = `${t.getFullYear()}-${String(t.getMonth()+1).padStart(2,'0')}-${String(t.getDate()).padStart(2,'0')}`;
            const hk = t.getHours();
            // 过滤当前半天
            if (d !== todayStr) continue;
            if (hk < periodStart || hk > periodEnd) continue;
            result.hours[hk] = (result.hours[hk] || 0) + (h.total || 0);
            if (h.ipCounts) {
                for (const [ip, cnt] of Object.entries(h.ipCounts)) {
                    result.ips[ip] = (result.ips[ip] || 0) + cnt;
                }
            }
            // attack_history 不含 user/status 细节，跳过
            result.events.push({ ip: Object.keys(h.ipCounts || {})[0] || null, _fromHistory: true });
        }
    } catch (_) {}
    return result;
}

// ============================================================================
// 数据源 3：snapshots.json（每 5 分钟的探测快照）
// [FIX 2026-07-04] 补充 Security 日志轮转后的数据空白
// ============================================================================
function getEventsFromSnapshots(periodStart, periodEnd, todayStr) {
    const result = { events: [], ips: {}, users: {}, statuses: {}, hours: {} };
    try {
        const snapshots = JSON.parse(fs.readFileSync(SNAPSHOT_FILE, 'utf8'));
        for (const s of snapshots) {
            const t = new Date(s.ts);
            const d = `${t.getFullYear()}-${String(t.getMonth()+1).padStart(2,'0')}-${String(t.getDate()).padStart(2,'0')}`;
            const hk = t.getHours();
            if (d !== todayStr) continue;
            if (hk < periodStart || hk > periodEnd) continue;
            result.hours[hk] = (result.hours[hk] || 0) + (s.total || 0);
            if (s.ipCounts) {
                for (const [ip, cnt] of Object.entries(s.ipCounts)) {
                    result.ips[ip] = (result.ips[ip] || 0) + cnt;
                }
            }
        }
    } catch (_) {}
    return result;
}

// ============================================================================
// 合并三个数据源
// ============================================================================
function getEvents() {
    const { blocks, source: logSource, count: blockCount } = getEventsFromSecurityLog();
    console.log(`📋 Security 日志查询结果：${blockCount} 条（来源：${logSource}）`);

    const { period, now: nowShanghai } = getReportPeriod();
    const todayStr = `${nowShanghai.getFullYear()}-${String(nowShanghai.getMonth()+1).padStart(2,'0')}-${String(nowShanghai.getDate()).padStart(2,'0')}`;

    let periodStartHour, periodEndHour, periodLabel;
    if (period === 'am') {
        periodStartHour = 0; periodEndHour = 11; periodLabel = '上半天';
    } else {
        periodStartHour = 12; periodEndHour = 23; periodLabel = '下半天';
    }

    // 从 Security 日志解析
    const winEvents = [];
    const winIPs = {};
    const winUsers = {};
    const winStatuses = {};
    const winHours = {};

    for (const b of blocks) {
        const dm = b.match(/Date:\s*(\S+)/);
        if (!dm) continue;
        const eventTime = new Date(dm[1]);
        const sh = new Date(eventTime.toLocaleString('en-US', { timeZone: 'Asia/Shanghai' }));
        const eventDate = `${sh.getFullYear()}-${String(sh.getMonth()+1).padStart(2,'0')}-${String(sh.getDate()).padStart(2,'0')}`;
        const eventHour = sh.getHours();

        if (eventDate !== todayStr) continue;
        if (eventHour < periodStartHour || eventHour > periodEndHour) continue;

        let ip = null, user = null, status = null, lt = null;

        let m = b.match(/源网络地址:\s*([\d\.:a-fA-F]+)/) || b.match(/Source Network Address:\s*([\d\.:a-fA-F]+)/);
        if (m && m[1] !== '-') ip = m[1];

        m = b.match(/登录失败的帐户:[\s\S]*?帐户名:\s*(\S+)/) || b.match(/Account For Which Logon Failed:[\s\S]*?Account Name:\s*(\S+)/);
        if (m && m[1].trim() && m[1].trim() !== '-') user = m[1].trim();

        m = b.match(/子状态:\s*(0x[0-9A-Fa-f]+)/) || b.match(/Sub Status:\s*(0x[0-9A-Fa-f]+)/);
        if (m) status = m[1];

        m = b.match(/登录类型:\s*(\d+)/) || b.match(/Logon Type:\s*(\d+)/);
        if (m) lt = m[1];

        if (ip) winIPs[ip] = (winIPs[ip] || 0) + 1;
        if (user) winUsers[user] = (winUsers[user] || 0) + 1;
        if (status) winStatuses[status] = (winStatuses[status] || 0) + 1;
        winHours[eventHour] = (winHours[eventHour] || 0) + 1;
        winEvents.push({ ip, user, status, lt, shanghaiTime: sh });
    }

    // [FIX 2026-07-04] Security 日志为空时，从 attack_history + snapshots 回填
    if (winEvents.length === 0) {
        console.log('📋 Security 日志为空，尝试从 attack_history.json + snapshots.json 回填…');
        const fromHistory = getEventsFromHistory(periodStartHour, periodEndHour, todayStr);
        const fromSnapshots = getEventsFromSnapshots(periodStartHour, periodEndHour, todayStr);

        // 合并 IP 计数（snapshots 的数据更完整）
        const mergedIPs = { ...winIPs };
        for (const [ip, cnt] of Object.entries(fromSnapshots.ips)) {
            mergedIPs[ip] = (mergedIPs[ip] || 0) + cnt;
        }
        for (const [ip, cnt] of Object.entries(fromHistory.ips)) {
            mergedIPs[ip] = (mergedIPs[ip] || 0) + cnt;
        }

        const mergedHours = { ...winHours };
        for (const [h, cnt] of Object.entries(fromSnapshots.hours)) {
            mergedHours[h] = (mergedHours[h] || 0) + cnt;
        }
        for (const [h, cnt] of Object.entries(fromHistory.hours)) {
            mergedHours[h] = (mergedHours[h] || 0) + cnt;
        }

        const totalFromFallback = Object.values(mergedIPs).reduce((a, b) => a + b, 0);
        console.log(`   attack_history 回填：${Object.keys(fromHistory.ips).length} 个 IP`);
        console.log(`   snapshots 回填：${Object.keys(fromSnapshots.ips).length} 个 IP，共 ${Object.values(fromSnapshots.hours).reduce((a, b) => a + b, 0)} 次`);
        console.log(`   回填后总事件数：${totalFromFallback}（警告：此数据可能因日志轮转不完整）`);

        // 用回填数据覆盖（Security 日志为空才用）
        Object.assign(winIPs, mergedIPs);
        Object.assign(winHours, mergedHours);
        winEvents.push(...fromHistory.events, ...fromSnapshots.events);
    }

    return { winEvents, winIPs, winUsers, winStatuses, winLogonTypes: {}, winHours,
             periodStartHour, periodEndHour, periodLabel, todayStr,
             dataSource: winEvents.length > 0 && blockCount > 0 ? 'SecurityLog' : 'fallback' };
}

// 读取真实的「封禁」状态。
// 重要：guard 采用的是「关闭 RDP 端口」模型（禁用所有 RDP 入站 Allow 规则），
// 并不会创建名为 "RDP BruteForce Block *" 的防火墙规则。因此这里不能去查防火墙规则，
// 必须直接读 rdp_guard_state.json 的 blockedAt / blockedIPs。
function getActualBlockState() {
    const stateFile = os.homedir() + '\\Documents\\rdp_guard_state.json';
    try {
        const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        if (st.blockedAt) {
            const elapsedMin = (Date.now() - new Date(st.blockedAt).getTime()) / 60000;
            const remaining = Math.max(0, Math.ceil(REOPEN_MINUTES - elapsedMin));
            return { closed: remaining > 0, remainingMin: remaining, blockedIPs: st.blockedIPs || [] };
        }
    } catch (_) {}
    return { closed: false, remainingMin: 0, blockedIPs: [] };
}

function getRecentLogs() {
    const logFile = os.homedir() + '\\Documents\\rdp_block.log';
    try {
        const content = fs.readFileSync(logFile, 'utf8');
        const lines = content.split('\n').filter(l => /\d{4}\/\d{1,2}\/\d{1,2}/.test(l.trim()));
        return lines.slice(-15);
    } catch { return []; }
}

function getGuardState() {
    const stateFile = os.homedir() + '\\Documents\\rdp_guard_state.json';
    try { return JSON.parse(fs.readFileSync(stateFile, 'utf8')); }
    catch { return null; }
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// 192.168.3.88 是本机唯一外网入口（跳板机），黑客与个人访问都走它，
// 因此与 guard 一致，把它按「外部」对待，而不是误判成内网。
const DETECT_IP = '192.168.3.88';
function isExternalIP(ip) {
    if (ip === DETECT_IP) return true;
    return !/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);
}

function riskLevel(count) {
    if (count >= 100) return { color: '#e74c3c', label: '高危', icon: '🔴' };
    if (count >= 50) return { color: '#e67e22', label: '中危', icon: '🟠' };
    if (count >= 10) return { color: '#f39c12', label: '低危', icon: '🟡' };
    return { color: '#27ae60', label: '观察', icon: '🟢' };
}

// ============ 主流程 ============
const data = getEvents();
const blockState = getActualBlockState();
const blockedIPs = blockState.blockedIPs;
const recentLogs = getRecentLogs();
const guardState = getGuardState();

const now = new Date();
const nowStr = now.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
const periodStartStr = `${String(data.periodStartHour).padStart(2,'0')}:00`;
const periodEndStr = `${String(data.periodEndHour).padStart(2,'0')}:59`;
const windowStartStr = `${data.todayStr} ${periodStartStr}`;
const windowEndStr = `${data.todayStr} ${periodEndStr}`;
const hostname = os.hostname();
const dateStr = data.todayStr;
const isFallback = data.dataSource !== 'SecurityLog';

const winFailTotal = data.winEvents.length;
const winIPEntires = Object.entries(data.winIPs).sort((a, b) => b[1] - a[1]);
const winUserEntries = Object.entries(data.winUsers).sort((a, b) => b[1] - a[1]);
const extIPs = winIPEntires.filter(([ip]) => isExternalIP(ip));

// 小时分布柱状图（只显示当前半天的小时）
let hourBars = '';
const maxHour = Math.max(...Object.values(data.winHours), 1);
for (let h = data.periodStartHour; h <= data.periodEndHour; h++) {
    const cnt = data.winHours[h] || 0;
    if (cnt === 0) continue;
    const pct = Math.max(2, (cnt / maxHour * 100)).toFixed(0);
    const barColor = cnt >= 50 ? '#e74c3c' : cnt >= 20 ? '#f39c12' : '#3498db';
    hourBars += `<div style="display:flex;align-items:center;gap:8px;margin:3px 0;">
        <span style="width:36px;text-align:right;color:#94a0b8;font-size:11px;font-family:monospace;">${String(h).padStart(2,'0')}:00</span>
        <div style="flex:1;background:#f0f3f7;border-radius:4px;height:16px;position:relative;overflow:hidden;">
            <div style="width:${pct}%;height:100%;background:${barColor};border-radius:4px;transition:width 0.3s;"></div>
        </div>
        <span style="width:36px;color:#5a6c7d;font-size:12px;font-weight:600;text-align:right;">${cnt}</span>
    </div>`;
}

// IP 表格
let failRows = '';
if (winIPEntires.length === 0) {
    failRows = '<tr><td colspan="4" style="text-align:center;color:#94a0b8;padding:30px 16px;font-size:14px;">本时段无失败登录记录 🛡️</td></tr>';
} else {
    for (const [ip, count] of winIPEntires) {
        const rl = riskLevel(count);
        const ext = isExternalIP(ip);
        const blocked = blockedIPs.includes(ip);
        failRows += `<tr>
            <td style="padding:12px 16px;border-bottom:1px solid #eef1f5;font-family:'Courier New',monospace;font-size:13px;color:#2c3e50;">
                ${escapeHtml(ip)}
                <span style="font-size:10px;padding:1px 6px;border-radius:8px;margin-left:4px;${ext ? 'background:#ffeaea;color:#e74c3c;' : 'background:#eef5ff;color:#3498db;'}">${ext ? '外网' : '内网'}</span>
            </td>
            <td style="padding:12px 16px;border-bottom:1px solid #eef1f5;font-weight:700;color:${rl.color};font-size:15px;">${count}</td>
            <td style="padding:12px 16px;border-bottom:1px solid #eef1f5;">
                <span style="background:${rl.color};color:white;padding:3px 12px;border-radius:10px;font-size:11px;font-weight:600;">${rl.icon} ${rl.label}</span>
            </td>
            <td style="padding:12px 16px;border-bottom:1px solid #eef1f5;">
                ${blocked ? '<span style="color:#e74c3c;font-weight:600;">● 已封禁</span>' : '<span style="color:#bdc3c7;">—</span>'}
            </td>
        </tr>`;
    }
}

// 用户名
let userRows = '';
if (winUserEntries.length === 0) {
    userRows = '<div style="text-align:center;color:#94a0b8;padding:20px;font-size:13px;">无记录</div>';
} else {
    const knownUsers = ['administrator', 'admin', 'wry', 'pro', 'guest'];
    userRows = '<table style="width:100%;border-collapse:collapse;font-size:13px;"><thead><tr style="background:#f8f9fb;"><th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">用户名</th><th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">次数</th><th style="padding:8px 12px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">类型</th></tr></thead><tbody>';
    for (const [u, c] of winUserEntries.slice(0, 15)) {
        const isKnown = knownUsers.includes(u.toLowerCase());
        userRows += `<tr>
            <td style="padding:8px 12px;border-bottom:1px solid #eef1f5;font-family:monospace;${isKnown ? 'color:#e74c3c;font-weight:700;' : 'color:#2c3e50;'}">${escapeHtml(u)}${isKnown ? ' ⚠' : ''}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #eef1f5;font-weight:700;">${c}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #eef1f5;">${isKnown ? '<span style="color:#e74c3c;font-size:12px;">真实账户</span>' : '<span style="color:#95a5a6;font-size:12px;">字典猜测</span>'}</td>
        </tr>`;
    }
    userRows += '</tbody></table>';
    if (winUserEntries.length > 15) {
        userRows += `<div style="text-align:center;color:#94a0b8;font-size:12px;padding:8px;">还有 ${winUserEntries.length - 15} 个用户名未显示...</div>`;
    }
}

const subMap = { '0xC0000064': '未知用户名', '0xC000006A': '密码错误', '0xC0000234': '账户锁定', '0xC0000072': '账户禁用', '0xC000006F': '登录时间外', '0xC0000070': '工作站限制' };
let statusRows = '';
const statusEntries = Object.entries(data.winStatuses).sort((a, b) => b[1] - a[1]);
if (statusEntries.length === 0) {
    statusRows = '<div style="text-align:center;color:#94a0b8;padding:12px;font-size:13px;">无数据</div>';
} else {
    statusRows = '<table style="width:100%;font-size:13px;">';
    for (const [s, c] of statusEntries) {
        statusRows += `<tr>
            <td style="padding:6px 12px;font-family:monospace;color:#2c3e50;">${s}</td>
            <td style="padding:6px 12px;font-weight:700;color:#2c3e50;">${c}</td>
            <td style="padding:6px 12px;color:#7f8c8d;font-size:12px;">${subMap[s] || '—'}</td>
        </tr>`;
    }
    statusRows += '</table>';
}

let blockRows = '';
if (blockState.closed) {
    blockRows = `<div style="background:#fff5f5;border:1px solid #f5c6cb;border-radius:8px;padding:16px;color:#e74c3c;font-size:13px;line-height:1.7;">
        🚫 RDP 端口当前<b>关闭中</b>（防护激活，约 ${blockState.remainingMin} 分钟后自动恢复）。
        ${blockedIPs.length ? '触发 IP：' + blockedIPs.map(escapeHtml).join('、') : '触发 IP 未在状态文件中记录'}
    </div>`;
} else if (blockedIPs.length === 0) {
    blockRows = '<div style="text-align:center;color:#27ae60;padding:16px;font-size:13px;">🛡️ 当前无封禁，系统正常运行</div>';
} else {
    blockRows = '<div style="display:flex;flex-wrap:wrap;gap:8px;padding:4px 0;">';
    for (const ip of blockedIPs) {
        blockRows += `<span style="background:#fff5f5;color:#e74c3c;border:1px solid #f5c6cb;padding:5px 14px;border-radius:20px;font-family:monospace;font-size:13px;font-weight:600;">🚫 ${escapeHtml(ip)}</span>`;
    }
    blockRows += `</div><div style="color:#94a0b8;font-size:12px;padding:8px 0;">共 ${blockedIPs.length} 个 IP 被记录为最近一次封禁的触发源</div>`;
}

let logRows = '';
if (recentLogs.length === 0) {
    logRows = '<div style="text-align:center;color:#94a0b8;padding:16px;font-size:13px;">暂无操作日志</div>';
} else {
    for (const log of recentLogs) {
        const isAlert = /触发防护|告警|封禁/.test(log);
        const isRecover = /恢复|清除/.test(log);
        const color = isAlert ? '#e74c3c' : isRecover ? '#27ae60' : '#7f8c8d';
        logRows += `<div style="font-family:'Courier New',monospace;font-size:11px;color:${color};padding:4px 0;border-bottom:1px solid #f5f7fa;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(log.trim())}</div>`;
    }
}

const guardActive = guardState && guardState.blockedAt;
const guardHtml = guardActive
    ? `<div style="background:linear-gradient(135deg,#fff5f5,#ffe8e8);border-left:4px solid #e74c3c;border-radius:8px;padding:16px 20px;margin:0 0 20px 0;">
         <div style="display:flex;align-items:center;gap:8px;">
             <span style="font-size:18px;">🚨</span>
             <span style="color:#e74c3c;font-weight:700;font-size:15px;">防护已激活 — RDP 访问已关闭</span>
         </div>
         <div style="margin-top:8px;font-size:13px;color:#7f3545;">触发时间: ${guardState.blockedAt} · 封禁IP: ${(guardState.blockedIPs || []).join(', ') || '无'}</div>
       </div>`
    : `<div style="background:linear-gradient(135deg,#f0fff4,#e8ffe8);border-left:4px solid #27ae60;border-radius:8px;padding:16px 20px;margin:0 0 20px 0;">
         <div style="display:flex;align-items:center;gap:8px;">
             <span style="font-size:18px;">✅</span>
             <span style="color:#27ae60;font-weight:700;font-size:15px;">防护待命 — RDP 访问正常</span>
         </div>
         <div style="margin-top:8px;font-size:13px;color:#2a6b3a;">最近60秒失败次数: ${guardState ? guardState.lastFailCount || 0 : 0}</div>
       </div>`;

const threatLevel = winFailTotal > 100 ? 'high' : winFailTotal > 20 ? 'mid' : 'low';
const threatColor = threatLevel === 'high' ? '#e74c3c' : threatLevel === 'mid' ? '#f39c12' : '#27ae60';
const threatLabel = threatLevel === 'high' ? '高危' : threatLevel === 'mid' ? '中危' : '低危';

const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wry合金防护 — 安全报告</title>
</head>
<body style="margin:0;padding:0;background:#e9ecf1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;">
<div style="max-width:640px;margin:0 auto;padding:24px 12px;">

<div style="background:linear-gradient(135deg,#0f1e3d 0%,#1a3a6e 50%,#234e8a 100%);border-radius:20px 20px 0 0;padding:36px 40px 28px;position:relative;overflow:hidden;">
<div style="position:absolute;top:-30px;right:-20px;font-size:120px;opacity:0.06;">🛡️</div>
<div style="display:flex;align-items:center;gap:14px;margin-bottom:6px;">
<span style="font-size:30px;">🛡️</span>
<span style="font-size:22px;font-weight:800;color:white;letter-spacing:1px;">wry合金防护</span>
</div>
<div style="color:rgba(255,255,255,0.65);font-size:13px;font-weight:400;">RDP 安全监控系统 · ${escapeHtml(hostname)}</div>
<div style="margin-top:14px;display:inline-block;background:rgba(255,255,255,0.15);backdrop-filter:blur(10px);border-radius:8px;padding:4px 14px;">
<span style="color:white;font-size:13px;font-weight:600;">${dateStr} · ${data.periodLabel}</span>
</div>
</div>

<div style="background:white;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #eef1f5;">
<div>
<div style="color:#94a0b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;">统计窗口</div>
<div style="color:#2c3e50;font-size:13px;font-weight:600;margin-top:2px;">${windowStartStr} → ${windowEndStr}</div>
</div>
<div style="text-align:right;">
<div style="color:#94a0b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;">威胁等级</div>
<div style="margin-top:2px;"><span style="background:${threatColor};color:white;padding:3px 14px;border-radius:12px;font-size:13px;font-weight:700;">${threatLabel}</span></div>
</div>
</div>

${guardHtml}

${isFallback ? `<div style="background:#fffbe6;border-left:4px solid #f39c12;border-radius:8px;padding:12px 20px;margin:0 0 20px 0;font-size:12px;color:#7a5e00;">
    ⚠️ <strong>数据降级警告</strong>：Security 事件日志已轮转，本报告中的失败数据来自 attack_history + snapshots 快照，
    详细 IP/用户名/状态码 不可用。真实攻击记录请查看 Web 面板（http://localhost:19888）。
</div>` : ''}

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;">
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${winFailTotal > 50 ? '#e74c3c' : winFailTotal > 10 ? '#f39c12' : '#27ae60'};">${winFailTotal}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">${data.periodLabel}失败次数</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:#234e8a;">${winIPEntires.length}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">攻击源 IP 数</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${extIPs.length > 0 ? '#e74c3c' : '#27ae60'};">${extIPs.length}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">外网 IP 数</div>
</div>
<div style="background:linear-gradient(135deg,#f8f9fb,#eef1f6);border-radius:14px;padding:18px;text-align:center;border:1px solid #eef1f5;">
<div style="font-size:32px;font-weight:800;color:${blockedIPs.length > 0 ? '#e74c3c' : '#27ae60'};">${blockedIPs.length}</div>
<div style="color:#94a0b8;font-size:12px;margin-top:4px;font-weight:500;">当前封禁 IP</div>
</div>
</div>
</div>

${winFailTotal > 0 ? `<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">📊 攻击时间分布（${periodStartStr} - ${periodEndStr}）</div>
${hourBars}
</div>` : ''}

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">🔍 失败登录 IP 统计</div>
<table style="width:100%;border-collapse:collapse;font-size:14px;">
<thead><tr style="background:#f8f9fb;">
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">IP 地址</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">次数</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">风险</th>
<th style="padding:10px 16px;text-align:left;color:#94a0b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">状态</th>
</tr></thead>
<tbody>${failRows}</tbody>
</table>
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">👤 被尝试的用户名</div>
${userRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:12px;">📋 状态码分布</div>
${statusRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:16px;">🚫 当前封禁状态</div>
${blockRows}
</div>

<div style="background:white;padding:24px 40px;border-bottom:1px solid #eef1f5;">
<div style="font-size:15px;font-weight:700;color:#2c3e50;margin-bottom:12px;">📜 最近操作日志</div>
${logRows}
</div>

<div style="background:#0f1e3d;padding:24px 40px;border-radius:0 0 20px 20px;">
<div style="display:flex;justify-content:space-between;align-items:center;">
<div>
<div style="color:rgba(255,255,255,0.9);font-size:14px;font-weight:700;">🛡️ wry合金防护</div>
<div style="color:rgba(255,255,255,0.5);font-size:11px;margin-top:4px;">每分钟检测 · 阈值3次/60秒 · 自动封禁5分钟</div>
</div>
<div style="text-align:right;">
<div style="color:rgba(255,255,255,0.4);font-size:11px;">${nowStr}</div>
<div style="color:rgba(255,255,255,0.3);font-size:10px;margin-top:2px;">${escapeHtml(hostname)}</div>
</div>
</div>
</div>

</div>
</body></html>`;

async function sendEmail(htmlBody, subject) {
    const cfg = loadMailConfig();
    if (!cfg.pass) {
        console.warn('⚠ 未配置 SMTP 密码（环境变量 SMTP_PASS 或 ' + MAIL_CFG_FILE + ' 的 pass 字段），跳过本次邮件。防护仍在正常运行。');
        process.exit(0);
    }
    const transporter = nodemailer.createTransport({
        host: cfg.host, port: cfg.port, secure: cfg.secure,
        auth: { user: cfg.user, pass: cfg.pass }
    });
    return await transporter.sendMail({
        from: `"wry合金防护" <${cfg.user}>`,
        to: cfg.to,
        subject,
        html: htmlBody
    });
}

// 无威胁时的简短「安全通报」（降低噪音，保留每日心跳）
function buildClearEmail() {
    return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="margin:0;background:#e9ecf1;font-family:-apple-system,'Microsoft YaHei',sans-serif;">
<div style="max-width:520px;margin:0 auto;padding:28px 16px;">
<div style="background:linear-gradient(135deg,#0f1e3d,#234e8a);border-radius:18px;padding:32px 36px;color:white;">
<div style="font-size:30px;">🛡️</div>
<div style="font-size:20px;font-weight:800;margin-top:8px;letter-spacing:1px;">wry合金防护 · 安全通报</div>
<div style="color:rgba(255,255,255,0.65);font-size:13px;margin-top:4px;">${escapeHtml(hostname)} · ${dateStr} ${data.periodLabel}</div>
</div>
<div style="background:white;border-radius:0 0 18px 18px;padding:28px 36px;">
<div style="display:flex;align-items:center;gap:10px;color:#27ae60;font-weight:700;font-size:16px;">✅ 本时段无异常</div>
<div style="color:#5a6c7d;font-size:14px;line-height:1.7;margin-top:14px;">
统计窗口：${windowStartStr} → ${windowEndStr}<br>
失败登录次数：<strong style="color:#2c3e50;">0</strong><br>
当前封禁 IP：<strong style="color:#2c3e50;">0</strong><br>
防护状态：<strong style="color:#27ae60;">待命 · RDP 正常</strong>
</div>
<div style="margin-top:18px;padding:14px 16px;background:#f0fff4;border-left:4px solid #27ae60;border-radius:8px;font-size:13px;color:#2a6b3a;">
系统持续每分钟监控 RDP 失败登录（阈值 3 次/60 秒），无需人工干预。下次通报：08:00 / 20:00。
</div>
</div>
<div style="text-align:center;color:#94a0b8;font-size:11px;padding:16px;">${nowStr} · 自动生成</div>
</div>
</body></html>`;
}

(async () => {
    try {
        const noThreat = winFailTotal === 0 && blockedIPs.length === 0 && !guardActive;
        let body, subject;
        if (noThreat) {
            subject = `🛡️ wry合金防护 安全通报 ${dateStr} ${data.periodLabel} — 本时段无异常`;
            body = buildClearEmail();
            console.log('🟢 本时段无威胁，发送简短安全通报');
        } else {
            subject = `🛡️ wry合金防护 ${dateStr} ${data.periodLabel} — ${winFailTotal}次失败 · ${threatLabel}`;
            body = html;
            console.log('🔴 检测到威胁/活动，发送完整报告');
        }
        const info = await sendEmail(body, subject);
        console.log('✅ 报告邮件发送成功！');
        console.log('时间:', nowStr);
        console.log('半天:', data.periodLabel, '(', windowStartStr, '→', windowEndStr, ')');
        console.log('失败:', winFailTotal, '| IP:', winIPEntires.length, '| 封禁:', blockedIPs.length);
        console.log('数据来源:', isFallback ? '⚠️ 回填（Security日志已轮转，由attack_history+snapshots补充）' : '✅ Security事件日志');
    } catch (err) {
        console.error('❌ 发送失败:', err.message);
        process.exit(1);
    }
})();
