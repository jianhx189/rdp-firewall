// wry-web-watchdog.js - 守护 wry-web.js，每分钟检查端口并重启
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

const PORT = 19888;
const WEB_SCRIPT = path.join(__dirname, 'wry-web.js');

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
