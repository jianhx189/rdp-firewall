@echo off
chcp 65001 >/dev/null
REM ============================================================
REM wry合金防护 v3 - 开机自启脚本
REM ============================================================
REM 使用方式：
REM   1. 右键本文件 → 创建快捷方式
REM   2. 快捷方式 → 属性 → 高级 → 勾选“以管理员身份运行”
REM   3. 把快捷方式放进以下任一目录即可开机自启：
REM      ① C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup  （所有用户）
REM      ② %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup      （当前用户）
REM
REM 或者直接双击运行，手动启动一次
REM ============================================================
title wry合金防护 v3
echo.
echo  ================================
echo   wry合金防护 v3 - 开机自启
echo  ================================
echo.
cd /d %~dp0

REM 解析 Node 路径：优先稳定安装 D:\app\nodejs\node.exe，其次 QClaw 任意版本自带 node，最后退回 PATH
set "NODE_EXE="
if exist "D:\app\nodejs\node.exe" set "NODE_EXE=D:\app\nodejs\node.exe"
if not defined NODE_EXE (
  for /d %%G in ("C:\Program Files\QClaw\*") do (
    if exist "%%G\resources\node\node.exe" set "NODE_EXE=%%G\resources\node\node.exe"
  )
)
if not defined NODE_EXE set "NODE_EXE=node"
echo [+] Node: %NODE_EXE%

echo [+] 启动 guard...
start /b "" "%NODE_EXE%" rdp-guard.js
echo [+] 启动 web 面板...
start /b "" "%NODE_EXE%" wry-web.js
echo.
echo [OK] wry合金防护 v3 已启动！
echo     Web面板: http://localhost:19888
echo.
echo 按任意键退出...
pause >/dev/null