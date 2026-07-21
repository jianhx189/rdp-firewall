// rdp-guard-tray.js - 前台循环运行版 guard
// 每 60 秒执行一次 rdp-guard.js，窗口关闭时由 bat 负责关闭 RDP
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const GUARD_SCRIPT = path.join(__dirname, 'rdp-guard.js');
const NODE = process.execPath;
const INTERVAL = 60000;

function log(msg) {
    const ts = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    console.log(`${ts} ${msg}`);
}

function runOnce() {
    return new Promise((resolve) => {
        const child = spawn(NODE, [GUARD_SCRIPT], {
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
        });
        child.stdout.on('data', d => process.stdout.write(d));
        child.stderr.on('data', d => process.stderr.write(d));

        const timeout = setTimeout(() => {
            log('[WARN] guard 执行超时 (120s)，强制终止');
            child.kill();
        }, 120000);

        child.on('close', (code) => {
            clearTimeout(timeout);
            resolve(code);
        });
        child.on('error', (err) => {
            clearTimeout(timeout);
            log(`[ERROR] guard 启动失败: ${err.message}`);
            resolve(1);
        });
    });
}

async function loop() {
    log('guard-tray 启动，每 60 秒检测一次');
    while (true) {
        try {
            await runOnce();
        } catch (e) {
            log(`[ERROR] guard 执行异常: ${e.message}`);
        }
        await new Promise(r => setTimeout(r, INTERVAL));
    }
}

// 清理排他锁（允许 scheduled task 的 guard 正常运行）
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

loop().catch(e => {
    log(`[FATAL] ${e.message}`);
    process.exit(1);
});
