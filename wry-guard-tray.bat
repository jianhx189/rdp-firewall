@echo off
chcp 65001 >nul
REM ============================================================
REM  wry合金防护 v3 - 关闭窗口即关闭防火墙
REM ============================================================
title wry合金防护 v3 [运行中 - 关闭此窗口将关闭防火墙]
cd /d E:\rdp-firewall-local

REM 解析 Node 路径：优先稳定安装 D:\app\nodejs\node.exe，其次 QClaw 任意版本自带 node，最后退回 PATH
set "NODE_EXE="
if exist "D:\app\nodejs\node.exe" set "NODE_EXE=D:\app\nodejs\node.exe"
if not defined NODE_EXE (
  for /d %%G in ("C:\Program Files\QClaw\*") do (
    if exist "%%G\resources\node\node.exe" set "NODE_EXE=%%G\resources\node\node.exe"
  )
)
if not defined NODE_EXE set "NODE_EXE=node"
set NODE="%NODE_EXE%"

echo.
echo  ================================
echo   wry合金防护 v3
echo  ================================
echo.
echo  [状态] 启动中...
echo.

REM 禁用计划任务（防止 guard 自动恢复端口）
schtasks /change /tn "wry合金防护" /disable >nul 2>&1
schtasks /change /tn "wry合金防护Web守护" /disable >nul 2>&1
echo  [OK] 已暂停计划任务

REM 后台启动 Web 面板
start "" /B %NODE% wry-web.js
echo  [OK] Web 面板: http://localhost:19888

REM 确保防火墙规则开启
powershell -NoProfile -Command "Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled False | Enable-NetFirewallRule" >nul 2>&1
echo  [OK] 防火墙已开启（RDP 可连接）

REM 前台运行 guard（阻塞）
echo  [OK] Guard 已启动
echo.
echo  ----------------------------------
echo   关闭此窗口 = 关闭防火墙（断开 RDP）
echo   重新打开此窗口 = 重新开启防火墙
echo  ----------------------------------
echo.

%NODE% rdp-guard-tray.js

REM ========== 窗口关闭后：关闭防火墙 ==========
powershell -NoProfile -Command "Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Action Allow -Enabled True | Disable-NetFirewallRule" >nul 2>&1

REM 恢复计划任务
schtasks /change /tn "wry合金防护" /enable >nul 2>&1
schtasks /change /tn "wry合金防护Web守护" /enable >nul 2>&1