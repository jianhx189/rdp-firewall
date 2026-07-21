@echo off
chcp 65001 >nul
echo ============================================================
echo   wry 合金防护 v3.2 - 修复落地（需要管理员权限）
echo ============================================================
echo   本脚本将以 SYSTEM 权限一次性完成：
echo     1. 终止旧的 0.0.0.0 Web 面板（LAN 暴露的那个）
echo     2. 用 D:\app\nodejs\node.exe 重注册 3 个计划任务
echo        （guard / Web 看门狗 / 日报），不再依赖 QClaw
echo     3. 立即启动 guard 与 Web 看门狗
echo        新面板仅监听 127.0.0.1:19888，密码 147369
echo.
echo   请「右键 -> 以管理员身份运行」本文件。
echo ============================================================
echo.
pause
powershell -ExecutionPolicy Bypass -File "%~dp0wry-elevated-fix.ps1"
echo.
echo 执行完毕。详细结果见上方输出与：
echo   C:\Users\jianh\Documents\wry-fix-result.log
echo.
pause
