// rdp-guard.js - wry合金防护 v3
// 
// 新逻辑（v2）：
//   - 无 IP 黑名单，攻击时直接关闭 RDP 端口（禁用防火墙规则）
//   - 5 分钟后自动恢复（启用防火墙规则）
//   - 内网 IP（除 192.168.3.88）跳过检测，直接放行
//   - forceOpen：用户手动强制开启 RDP，有效期 5 分钟
//
// 数据文件：
//   - Documents/rdp_guard_state.json    防护状态（blockedAt / forceOpenUntil）
//   - Documents/rdp_block.log           操作日志
//   - Documents/rdp_force_open.json    强制开启状态
//   - Documents/rdp_attack_history.json 攻击历史
//   - Documents/rdp_snapshots.json     定时快照（验证脚本是否运行）
//   - Documents/rdp_guard.lock         进程锁（防止并发）
//
// 状态机：
//   blockedAt=null && forceOpenUntil=null → NORMAL（监控中）
//   blockedAt!=null                       → BLOCKED（端口关闭，倒计时恢复）
//   forceOpenUntil!=null                  → FORCE_OPEN（端口开启，倒计时关闭）

const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ============================================================================
// 常量配置
// ============================================================================
const THRESHOLD            = 3;       // 触发关闭端口的同 IP 失败次数阈值
const LOOKBACK_SECONDS     = 60;     // 回溯时间窗口（秒）
const REOPEN_MINUTES       = 5;      // 端口关闭后自动恢复时间（分钟）
const FORCE_OPEN_DURATION   = 5 * 60 * 1000;  // forceOpen 有效期（毫秒）
const LOG_MAX_LINES        = 500;    // 日志最大保留行数
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;  // 快照间隔（5分钟）

// 内网 IP 范围（192.168.3.88 参与检测，其他内网 IP 全部放行）
const PRIVATE_RANGES = [
    { start: '10.0.0.0',      end: '10.255.255.255' },
    { start: '172.16.0.0',    end: '172.31.255.255' },
    { start: '192.168.0.0',   end: '192.168.255.255' },
];
const DETECT_IP = '192.168.3.88';   // 跳板机 IP，参与检测和封禁

// 运行数据目录（SYSTEM 用户时回退到实际用户目录）
function getDataDir() {
    const homedir = os.homedir();
    // 非 SYSTEM 用户直接用 homedir/Documents
    if (!homedir.toLowerCase().includes('system32')) {
        return path.join(homedir, 'Documents');
    }
    // SYSTEM 用户：找第一个有 Documents 的用户目录
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
    // 兜底
    return path.join(homedir, 'Documents');
}
const DATA_DIR = getDataDir();

// 文件路径
const LOG_FILE           = path.join(DATA_DIR, 'rdp_block.log');
const STATE_FILE         = path.join(DATA_DIR, 'rdp_guard_state.json');
const LOCK_FILE          = path.join(DATA_DIR, 'rdp_guard.lock');
const FORCE_OPEN_FILE    = path.join(DATA_DIR, 'rdp_force_open.json');
const ATTACK_HISTORY_FILE = path.join(DATA_DIR, 'rdp_attack_history.json');
const SNAPSHOT_FILE      = path.join(DATA_DIR, 'rdp_snapshots.json');
const BACKFILL_DONE_FILE  = path.join(DATA_DIR, 'rdp_guard_backfill.lock');

// ============================================================================
// 工具函数
// ============================================================================

// 原子写入：先写 .tmp 再 rename，NTFS rename 是原子操作，规避并发写文件损坏
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

// 安全 JSON 读取
function safeReadJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return fallback; }
}

// 追加日志 + 自动轮转
function writeLog(msg) {
    const ts = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const line = `${ts} ${msg}\n`;
    try {
        fs.appendFileSync(LOG_FILE, line, 'utf8');
        const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n');
        if (lines.length > LOG_MAX_LINES + 10) {
            const kept = lines.slice(-LOG_MAX_LINES);
            atomicWrite(LOG_FILE, kept.join('\n') + '\n');
        }
    } catch (_) {}
}

// 判断 IP 是否为内网放行范围（192.168.3.88 不在此列，需参与检测）
function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip === DETECT_IP) return false;  // 跳板机参与检测，不放行
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;
    const n = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

    for (const r of PRIVATE_RANGES) {
        const s = r.start.split('.').reduce((acc, p, i) => acc | (parseInt(p) << (24 - i * 8)), 0);
        const e = r.end.split('.').reduce((acc, p, i) => acc | (parseInt(p) << (24 - i * 8)), 0);
        if (n >= s && n <= e) return true;
    }
    return false;
}

// ============================================================================
// 进程锁（排他文件，防止并发执行）
// ============================================================================

const EXCLUSIVE_LOCK = LOCK_FILE + '.acquired';

function tryAcquireLock() {
    try {
        // 检查是否有残留锁（进程异常退出未清理）
        if (fs.existsSync(EXCLUSIVE_LOCK)) {
            try {
                const content = fs.readFileSync(EXCLUSIVE_LOCK, 'utf8').trim();
                const pid = parseInt(content, 10);
                if (pid && Number.isFinite(pid)) {
                    process.kill(pid, 0); // 探测进程是否存活
                    // 进程还在，锁有效
                    return false;
                }
            } catch (_) {}
            // 进程已死，清理残留锁
            try { fs.unlinkSync(EXCLUSIVE_LOCK); } catch (_) {}
            writeLog('[WARN] 清理残留锁文件，之前持有锁的进程已退出');
        }
        // 创建新锁
        fs.writeFileSync(EXCLUSIVE_LOCK, String(process.pid), { flag: 'wx' });
        return true;
    } catch (_) {
        return false;
    }
}

function releaseExclusiveLock() {
    try { fs.unlinkSync(EXCLUSIVE_LOCK); } catch (_) {}
}

// ============================================================================
// 持久化
// ============================================================================

function persistAttack(total, ipCounts, userCounts, statusCounts) {
    try {
        let history = safeReadJson(ATTACK_HISTORY_FILE, []);
        const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
        history = history.filter(h => h.ts > cutoff);
        const ts = Date.now();
        const exists = history.some(h => Math.abs(h.ts - ts) < 5000);
        if (!exists) {
            history.push({
                ts,
                time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
                total,
                ipCounts,
                userCounts: userCounts || {},
                statusCounts: statusCounts || {},
            });
            atomicWrite(ATTACK_HISTORY_FILE, JSON.stringify(history, null, 2));
        }
    } catch (e) {
        writeLog(`[ERROR] persistAttack 失败: ${e.message}`);
    }
}

function persistSnapshot(total, ipCounts) {
    try {
        let snapshots = safeReadJson(SNAPSHOT_FILE, []);
        const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
        snapshots = snapshots.filter(s => s.ts > cutoff);
        const last = snapshots[snapshots.length - 1];
        if (last && (Date.now() - last.ts) < SNAPSHOT_INTERVAL_MS) return;
        snapshots.push({ ts: Date.now(), total, ipCounts: ipCounts || {} });
        atomicWrite(SNAPSHOT_FILE, JSON.stringify(snapshots));
    } catch (e) {
        writeLog(`[ERROR] persistSnapshot 失败: ${e.message}`);
    }
}

function loadState() {
    return safeReadJson(STATE_FILE, { blockedAt: null });
}

function saveState(s) {
    atomicWrite(STATE_FILE, JSON.stringify(s, null, 2));
}

// ============================================================================
// PowerShell 执行（自动检测编码）
// ============================================================================

function ps(command) {
    try {
        const buf = execSync(command, {
            encoding: 'buffer', timeout: 20000, windowsHide: true, shell: 'powershell.exe'
        });
        // 1. UTF-16-LE（PowerShell 默认输出，有 BOM）
        if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
            return new TextDecoder('utf-16le').decode(buf.subarray(2));
        }
        // 2. UTF-8（JSON 输出 / ConvertTo-Json 等场景）
        const asUtf8 = new TextDecoder('utf-8', { fatal: false }).decode(buf);
        try {
            JSON.parse(asUtf8.trim());
            return asUtf8; // 合法 JSON，确认 UTF-8
        } catch (_) {}
        // 3. 检查 UTF-8 解码是否包含常见中文关键词或布尔值
        if (/[一-鿿]|True|False|Enabled|Disabled/i.test(asUtf8)) {
            return asUtf8;
        }
        // 4. 回退 GB18030
        return new TextDecoder('gb18030', { fatal: false }).decode(buf);
    } catch (e) {
        writeLog(`[WARN] ps 命令执行失败: ${command.substring(0, 80)} — ${e.message}`);
        return '';
    }
}

// ============================================================================
// 防火墙操作
// ============================================================================

// 获取所有 RDP 入站允许规则
function getRDPRules(enabled) {
    const flag = enabled ? 'True' : 'False';
    const out = ps(`Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled ${flag} | Select-Object Name,DisplayName | ConvertTo-Json -Compress`);
    let rules = [];
    try { rules = JSON.parse(out); } catch (_) {}
    return Array.isArray(rules) ? rules : (rules.Name ? [rules] : []);
}

// 禁用所有 RDP 入站允许规则（关闭端口）
function disableRDPRules() {
    const rules = getRDPRules(true);
    let count = 0;
    for (const r of rules) {
        ps(`Disable-NetFirewallRule -Name '${r.Name}'`);
        writeLog(`已禁用 RDP 规则: ${r.DisplayName || r.Name}`);
        count++;
    }
    return count;
}

// 启用所有 RDP 入站允许规则（开启端口）
// 如果原有规则被系统保护无法启用，自动创建兜底规则
function enableRDPRules() {
    const rules = getRDPRules(false);
    let count = 0;
    for (const r of rules) {
        const result = ps(`Enable-NetFirewallRule -Name '${r.Name}'`);
        if (result && result.includes('拒绝访问')) {
            writeLog(`[WARN] 无法启用规则 ${r.Name}（权限不足），将使用兜底规则`);
        } else {
            writeLog(`已恢复 RDP 规则: ${r.DisplayName || r.Name}`);
            count++;
        }
    }
    // 验证：确认至少有一条 RDP 规则处于启用状态
    const openCount = getRDPRules(true).length;
    if (openCount === 0) {
        writeLog('[WARN] 所有 RDP 规则均无法启用，创建兜底规则');
        ps(`New-NetFirewallRule -DisplayName 'wry合金防护-兜底RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Group '@FirewallAPI.dll,-28752'`);
        count++;
    }
    return count;
}

// 判断 RDP 端口当前是否开启（检查是否有 Allow 规则处于启用状态）
function isRDPOpen() {
    const rules = getRDPRules(true);
    return rules.length > 0;
}

// ============================================================================
// 日志分析
// ============================================================================

// 获取最近 N 秒的 4625 事件，过滤掉内网 IP（192.168.3.88 参与检测）
function getRecentFailures(seconds) {
    const since = new Date(Date.now() - seconds * 1000).toISOString();
    try {
        // 优先用 wevtutil，失败时回退到 PowerShell Get-WinEvent
        let text;
        try {
            const buf = execSync(
                `wevtutil qe Security /f:text /q:"*[System[EventID=4625]]" /c:500 /rd:true`,
                { encoding: 'buffer', maxBuffer: 100 * 1024 * 1024, windowsHide: true }
            );
            text = new TextDecoder('gb18030', { fatal: false }).decode(buf);
        } catch (wevtErr) {
            // wevtutil 失败，尝试 PowerShell Get-WinEvent
            writeLog(`[WARN] wevtutil 失败，回退到 Get-WinEvent: ${wevtErr.message.substring(0, 200)}`);
            try {
                text = execSync(
                    `powershell -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 | ForEach-Object { $e=$_; 'Event[0]'; '  Date: ' + $e.TimeCreated.ToString('o'); '  源网络地址: ' + $e.Properties[19].Value; '  登录失败的帐户:'; '    帐户名: ' + $e.Properties[5].Value; '  子状态: 0x' + $e.Properties[24].Value.ToString('X8') }"`,
                    { encoding: 'utf8', maxBuffer: 100 * 1024 * 1024, windowsHide: true, timeout: 20000 }
                );
            } catch (psErr) {
                writeLog(`[ERROR] Get-WinEvent 也失败: ${psErr.message.substring(0, 200)}`);
                return { total: 0, ipCounts: {}, userCounts: {}, statusCounts: {} };
            }
        }
        const blocks = text.split(/^Event\[\d+\]\s*$/m).filter(b => b.trim());

        const ipCounts = {};
        const userCounts = {};
        const statusCounts = {};
        let total = 0;

        for (const b of blocks) {
            const dm = b.match(/Date:\s*(\S+)/);
            if (!dm) continue;
            const eventTime = new Date(dm[1]);
            if (eventTime < new Date(Date.now() - seconds * 1000)) continue;

            const m = b.match(/源网络地址:\s*([\d\.:a-fA-F]+)/) || b.match(/Source Network Address:\s*([\d\.:a-fA-F]+)/);
            if (!m || !m[1] || m[1] === '-' || m[1] === '127.0.0.1' || m[1] === '::1') continue;

            const ip = m[1];
            if (isPrivateIP(ip)) continue;

            total++;
            ipCounts[ip] = (ipCounts[ip] || 0) + 1;

            // 提取用户名
            const um = b.match(/登录失败的帐户:[\s\S]*?帐户名:\s*(\S+)/) ||
                       b.match(/Account For Which Logon Failed:[\s\S]*?Account Name:\s*(\S+)/);
            if (um && um[1] && um[1] !== '-') userCounts[um[1]] = (userCounts[um[1]] || 0) + 1;

            // 提取状态码
            const sm = b.match(/子状态:\s*(0x[0-9A-Fa-f]+)/) || b.match(/Sub Status:\s*(0x[0-9A-Fa-f]+)/);
            if (sm) statusCounts[sm[1]] = (statusCounts[sm[1]] || 0) + 1;
        }
        return { total, ipCounts, userCounts, statusCounts };
    } catch (e) {
        writeLog(`[ERROR] getRecentFailures 失败: ${e.message}`);
        return { total: 0, ipCounts: {}, userCounts: {}, statusCounts: {} };
    }
}

// ============================================================================
// 主流程
// ============================================================================

async function main() {
    // ---- 排他锁（原子文件，防止并发执行）----
    if (!tryAcquireLock()) {
        // 另一个实例正在运行，静默退出
        process.exit(0);
    }
    // 同时写 PID 记录（供 watchdog/debug 使用）
    try { fs.writeFileSync(LOCK_FILE, String(process.pid) + ':' + Date.now(), 'utf8'); } catch (_) {}

    try {
        // ---- forceOpen 检查（优先级最高）----
        // forceOpen 时：不阻止任何检测行为，但确保 RDP 规则是开启的
        let forceOpenUntil = null;
        try {
            const fo = safeReadJson(FORCE_OPEN_FILE, null);
            if (fo && fo.until) {
                const remaining = fo.until - Date.now();
                if (remaining > 0) {
                    forceOpenUntil = fo.until;
                    const min = Math.ceil(remaining / 60000);
                    writeLog(`⏸️ forceOpen 生效中（剩余 ${min} 分钟），确保 RDP 端口开启`);
                    // 确保 RDP 规则已启用
                    const open = isRDPOpen();
                    if (!open) {
                        const count = enableRDPRules();
                        writeLog(`⚡ forceOpen 强制启用 RDP（恢复 ${count} 条规则）`);
                    }
                    // 如果当前是封禁状态 → 立即解除
                    const state = loadState();
                    if (state.blockedAt) {
                        const count = enableRDPRules();
                        state.blockedAt = null;
                        saveState(state);
                        writeLog(`⚡ forceOpen 立即解除封禁，恢复 RDP（恢复 ${count} 条规则）`);
                    }
                    persistSnapshot(0, {});
                    unlock(); process.exit(0);
                } else {
                    try { fs.unlinkSync(FORCE_OPEN_FILE); } catch (_) {}
                    writeLog('forceOpen 已到期');
                }
            }
        } catch (_) {}

        // ---- 状态检查：当前是封禁状态吗？----
        let state = loadState();

        if (state.blockedAt) {
            const blockedTime = new Date(state.blockedAt);
            const elapsedMin = (Date.now() - blockedTime.getTime()) / 60000;
            if (elapsedMin >= REOPEN_MINUTES) {
                // 封禁到期，自动恢复
                const count = enableRDPRules();
                state.blockedAt = null;
                saveState(state);
                writeLog(`RDP 端口已自动恢复（关闭 ${REOPEN_MINUTES} 分钟后）`);
            } else {
                const remaining = Math.ceil(REOPEN_MINUTES - elapsedMin);
                writeLog(`RDP 端口封禁中（剩余 ${remaining} 分钟），跳过检测`);
            }
            persistSnapshot(0, {});
            unlock(); process.exit(0);
        }

        // ---- 正常状态：检测攻击 ----
        const { total, ipCounts, userCounts, statusCounts } = getRecentFailures(LOOKBACK_SECONDS);
        persistSnapshot(total, ipCounts);

        // 无攻击：确保 RDP 端口是开启的
        if (total === 0) {
            if (!isRDPOpen()) {
                const count = enableRDPRules();
                writeLog(`无攻击事件，RDP 端口未开启，已自动恢复（${count} 条规则）`);
            }
            unlock(); process.exit(0);
        }

        // 有攻击，但 RDP 端口已是开启状态才触发封禁
        const rdpOpen = isRDPOpen();
        if (!rdpOpen) {
            writeLog(`RDP 端口已关闭，跳过检测（可能是手动关闭或 forceOpen）`);
            unlock(); process.exit(0);
        }

        // 找超过阈值的 IP
        const triggeredIPs = Object.entries(ipCounts)
            .filter(([, c]) => c >= THRESHOLD)
            .map(([ip]) => ip);

        if (triggeredIPs.length === 0) {
            unlock(); process.exit(0);
        }

        // ---- 触发封禁：关闭 RDP 端口 ----
        writeLog(`⚠️ 检测到暴力破解！最近${LOOKBACK_SECONDS}秒内 ${total} 次失败，` +
            `攻击 IP: ${triggeredIPs.join(', ')}，关闭 RDP 端口`);

        persistAttack(total, ipCounts, userCounts, statusCounts);

        // 禁用所有 RDP 入站规则
        const disabledCount = disableRDPRules();

        // 更新状态
        state.blockedAt = new Date().toISOString();
        saveState(state);

        writeLog(`RDP 端口已关闭（禁用 ${disabledCount} 条规则），` +
            `${REOPEN_MINUTES} 分钟后自动恢复`);

    } catch (e) {
        writeLog(`[ERROR] guard 异常: ${e.message}`);
    }

    unlock();
}

function unlock() {
    try { fs.unlinkSync(LOCK_FILE); } catch (_) {}
    releaseExclusiveLock();
}

main().catch(e => {
    writeLog(`[ERROR] main 未捕获异常: ${e.message}`);
    unlock();
    process.exit(1);
});
