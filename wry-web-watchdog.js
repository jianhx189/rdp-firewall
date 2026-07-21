// wry-web-watchdog.js - 守护 wry-web.js，每分钟检查端口并重启
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

const PORT = 19888;
const WEB_SCRIPT = path.join(__dirname, 'wry-web.js');

// 按优先级解析 Node 可执行文件路径（避免写死 QClaw 版本号导致升级后失效）
function resolveNode() {
    const candidates = [];
    // 1. 任意版本的 QClaw 自带 node（随 QClaw 升级自动跟随）
    try {
        const qclawBase = 'C:\\Program Files\\QClaw';
        if (fs.existsSync(qclawBase)) {
            const versions = fs.readdirSync(qclawBase)
                .filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v))
                .sort()
                .reverse();
            for (const v of versions) {
                candidates.push(path.join(qclawBase, v, 'resources', 'node', 'node.exe'));
            }
        }
    } catch (_) {}
    // 2. 稳定手动安装
    candidates.push('D:\\app\\nodejs\\node.exe');
    candidates.push('C:\\Users\\jianh\\.workbuddy\\binaries\\node\\versions\\22.22.2\\node.exe');
    // 3. 当前进程 / PATH
    candidates.push(process.execPath, process.env.NODE_PATH, 'node');
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

// 验证锁中的 PID 是否真的在监听
function isProcessListening(pid) {
    return new Promise(resolve => {
        try {
            const s = net.connect(PORT, '127.0.0.1', () => {
                s.destroy();
                resolve(true);
            });
            s.setTimeout(1000);
            s.on('error', () => { s.destroy(); resolve(false); });
        } catch { resolve(false); }
    });
}

async function main() {
    const listening = await checkPort(PORT);

    if (listening) {
        log('Port 19888 is listening, web server OK');
        return; // 不改锁文件，只检查
    }

    log('Port 19888 not listening, need to restart');

    // 启动 web（后台 detached 模式）
    log(`Starting: "${NODE}" "${WEB_SCRIPT}"`);
    try {
        const child = spawn(NODE, [WEB_SCRIPT], {
            detached: true,
            stdio: 'ignore',
            windowsHide: true
        });
        child.unref();
        writeLock(child.pid);
        log(`Started PID=${child.pid}`);
    } catch (e) {
        log(`ERROR: ${e.message}`);
    }
}

main().catch(e => log(`FATAL: ${e.message}`));
