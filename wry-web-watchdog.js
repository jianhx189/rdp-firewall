// wry-web-watchdog.js - 守护 wry-web.js，每分钟检查端口并重启；源码更新时自动重新部署
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

const PORT = 19888;
const WEB_SCRIPT = path.join(__dirname, 'wry-web.js');
const STAMP_FILE = path.join(__dirname, 'wry-web.deploystamp');

// 解析 Node 路径：使用稳定安装 D:\app\nodejs\node.exe（不依赖 QClaw），回退到 PATH
function resolveNode() {
    const candidates = [
        'D:\\app\\nodejs\\node.exe',
        process.execPath,
        'node',
    ];
    for (const c of candidates.filter(Boolean)) {
        try { if (fs.existsSync(c)) return c; } catch (_) {}
    }
    return 'node';
}
const NODE = resolveNode();
const LOCK_FILE = path.join(__dirname, 'wry-web.lock');
const LOG_FILE = path.join(__dirname, 'wry-web-watchdog.log');

function log(msg) {
    const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const line = `${stamp} [WATCHDOG] ${msg}`;
    console.log(line);
    try { fs.appendFileSync(LOG_FILE, line + '\n', 'utf8'); } catch (_) {}
}

function getLock() {
    try {
        if (!fs.existsSync(LOCK_FILE)) return null;
        return JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
    } catch { return null; }
}

function writeLock(pid) {
    fs.writeFileSync(LOCK_FILE, JSON.stringify({
        pid,
        ts: new Date().toISOString(),
        port: PORT,
        status: 'running'
    }), 'utf8');
}

function checkPort(port) {
    return new Promise(resolve => {
        const s = net.createConnection({ port, host: '127.0.0.1' });
        s.setTimeout(3000);
        s.on('connect', () => { s.destroy(); resolve(true); });
        s.on('timeout', () => { s.destroy(); resolve(false); });
        s.on('error', () => { s.destroy(); resolve(false); });
    });
}

// 取正在监听 19888 的进程 PID（通过 netstat -ano，避免 PowerShell 引号问题）
function getListenerPid() {
    try {
        const out = execSync('netstat -ano', { encoding: 'utf8', timeout: 8000, windowsHide: true });
        for (const line of out.split('\n')) {
            if (line.includes(':19888') && line.includes('LISTENING')) {
                const parts = line.trim().split(/\s+/);
                const pid = parts[parts.length - 1];
                if (/^\d+$/.test(pid)) return parseInt(pid, 10);
            }
        }
    } catch (_) {}
    return null;
}

function killPid(pid) {
    try {
        execSync(`taskkill /F /PID ${pid}`, { encoding: 'utf8', timeout: 8000, windowsHide: true });
        return true;
    } catch (_) { return false; }
}

// 取 web 源码（wry-web.js / wry-web.html）最新的修改时间，用于判断是否需重新部署
function webSourceMtime() {
    let m = 0;
    for (const f of [WEB_SCRIPT, path.join(__dirname, 'wry-web.html')]) {
        try { const s = fs.statSync(f); if (s.mtimeMs > m) m = s.mtimeMs; } catch (_) {}
    }
    return m;
}

function readStamp() {
    try { return parseFloat(fs.readFileSync(STAMP_FILE, 'utf8').trim()) || 0; } catch (_) { return 0; }
}
function writeStamp(m) {
    try { fs.writeFileSync(STAMP_FILE, String(Math.floor(m)), 'utf8'); } catch (_) {}
}

function startWeb() {
    log(`Starting: "${NODE}" "${WEB_SCRIPT}"`);
    try {
        const child = spawn(NODE, [WEB_SCRIPT], {
            detached: true,
            stdio: 'ignore',
            windowsHide: true
        });
        child.unref();
        writeLock(child.pid);
        writeStamp(webSourceMtime());
        log(`Started PID=${child.pid}`);
    } catch (e) {
        log(`ERROR: ${e.message}`);
    }
}

async function main() {
    const listening = await checkPort(PORT);
    const srcMtime = Math.floor(webSourceMtime());
    const stamp = readStamp();

    if (!listening) {
        log('Port 19888 not listening, starting web');
        startWeb();
        return;
    }

    // 端口在监听：若 web 源码已更新（mtime 比上次启动新），自动重启以应用新代码
    if (srcMtime > stamp) {
        const pid = getListenerPid();
        if (pid) {
            log(`Web source updated (mtime ${Math.floor(srcMtime)} > stamp ${Math.floor(stamp)}), restarting listener PID ${pid}`);
            killPid(pid);
            await new Promise(r => setTimeout(r, 1500));
        } else {
            log('Web source updated but listener PID not found, starting new instance');
        }
        startWeb();
        return;
    }

    log('Port 19888 listening, web server OK (source unchanged)');
}

main().catch(e => log(`FATAL: ${e.message}`));
