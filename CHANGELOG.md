# Changelog - wry合金防护

## v3.4 (2026-07-22) — 网页按钮逻辑理顺（两种状态、手动关闭持久化）

### 核心改动：按钮逻辑只剩两条清晰路径
- **无攻击（NORMAL，端口开放）**：界面只显示一个按钮 **「关闭 RDP 端口」**。点击 → 输入密码（147369）→ 后端 `disableRDPRules()` 立即禁用全部 RDP 入站 Allow 规则，端口**确实关闭**。
- **受到攻击（BLOCKED，端口关闭）**：状态栏**大字红色显示「⚠ 受到攻击，端口已关闭」**并带脉冲动画，下方显示**倒计时**（距自动恢复剩余分钟），只提供 **「强制开启 RDP」** 按钮。点击 → 输入密码校验 → 强制开启端口 **5 分钟**；5 分钟结束后若仍在遭攻击，guard 按规则重新关闭。
- 新增 **MANUAL_CLOSED**（用户手动关闭）与 **FORCE_OPEN**（强制开启中）两种界面态，按钮/提示随之联动：
  - FORCE_OPEN：显示强制开启倒计时 + 「立即关闭端口」（可提前结束）。
  - MANUAL_CLOSED：提示「已手动关闭，不会自动恢复」+ 「强制开启 RDP」重新打开。

### 手动关闭真正「持久」（修复之前被 guard 静默重开的隐患）
- 旧 `force-close` 把端口关 5 分钟后由 guard 自动重开，且 guard 的「无攻击→确保端口开放」逻辑会在 1 分钟内把手动关闭的端口重新打开，导致「关不掉」。
- 现手动关闭写入 `rdp_guard_state.json` 的 `blockedAt` + **`closeReason: 'manual'`**；guard 遇到 `manual` 状态时**保持关闭、绝不自动恢复**，并每分钟再次确认端口确实关闭。
- 重新打开的唯一途径是面板「强制开启 RDP」（密码校验），符合「要确实关闭」的诉求。

### 状态字段扩展（向后兼容）
- `rdp_guard_state.json` 新增 `closeReason`（`'attack'` | `'manual'`）；旧数据无该字段时按 `'attack'` 处理，不影响现有封禁展示。
- `wry-web.js` 新增统一状态推导 `deriveStatus()`，产出 `NORMAL / BLOCKED / FORCE_OPEN / MANUAL_CLOSED` 四态，并附带 `blockedRemainingMs`（平滑倒计时）、`closeReason`。
- 接口收敛：`/api/force-close`、`/api/force-cancel` 合并为 **`/api/close`**（手动持久关闭）；`/api/force-open` 在开启时清空 `blockedAt`/`closeReason`，交还控制权给 guard。

### 验证
- `node --check` 三个脚本全部通过；`deriveStatus` 单测 16/16 通过；临时端口+临时数据目录的端到端 HTTP 测试覆盖 NORMAL→MANUAL_CLOSED→FORCE_OPEN 全链路与密码校验。
- 看门狗（wry-rdp-web）按 mtime 自动重新部署，源码保存后 ≤1 分钟生效，无需手动操作。

## v3.3 (2026-07-21) — 网页统计仅限当天 + 看门狗自动部署

### 网页统计按天归并、每日 0:00 重置
- `wry-web.js` 的 `getHistory()` 改为**仅返回当天（Asia/Shanghai 时区）的攻击事件**（按 `ts` 过滤 + 时间倒序）。原逻辑返回最近 30 条跨天数据。
- 由此 `/api/history` 与页面预加载数据都变成「当天」，每天 0:00 自然归零（无需独立重置机制）。
- 前端 `wry-web.html`：
  - 「24h 失败总数」→ **「今日失败总数」**（直接对当天数据求和）；
  - 「今日攻击」计数改为直接取当天事件数；
  - 防护概览的「被爆破用户名数 / 攻击 IP 数 / 攻击事件数 / TOP10 / 最近记录」均随历史变为当天；
  - 「完整攻击历史」卡片标题改为「今日攻击历史」。

### 看门狗自动重新部署（无需手动操作）
- `wry-web-watchdog.js` 新增「源码更新自动重启」：每分钟运行时对比 `wry-web.js`/`wry-web.html` 的最新修改时间与 `wry-web.deploystamp` 标记，若源码更新则用 `taskkill` 杀掉旧监听进程并以新代码拉起（看门狗以 SYSTEM 提权运行，可终止 SYSTEM 身份的旧 Web）。
- 效果：后续任何 Web 代码改动保存后 ≤1 分钟自动生效，不必再手动点 `apply-fix.bat`。

## v3.2 (2026-07-21) — 按用户最新指示收敛

### 密码策略
- **强制开启密码固定为 `147369`**（保留环境变量 `RDP_GUARD_PASSWORD` 覆盖能力）。撤消 v3.1 的「随机生成 + 文件持久化」方案——用户明确选择简单固定口令。

### 彻底不依赖 QClaw
- 所有脚本（register-tasks.ps1 / wry-web-watchdog.js / wry-selfheal.ps1 / wry-guard-startup.bat / wry-guard-tray.bat）的 Node 路径改为**只用稳定安装 `D:\app\nodejs\node.exe`，缺失则回退 PATH**，不再扫描 QClaw 版本目录。
- 说明：源码位于 `C:\Users\jianh\.qclaw\workspace\rdp-firewall` 是 QClaw 创建的 workspace 目录（仅位置），运行时已无任何 QClaw 二进制依赖；`E:\rdp-firewall-local` 为完全独立的部署副本。

### 逻辑梳理（PM 视角，修复真正的自相矛盾）
- **邮件报告与实际防护模型对齐（最大 bug）**：原 `getBlockedIPs()` 去查名为 `RDP BruteForce Block *` 的防火墙规则，但 guard 实际采用「禁用全部 RDP 入站 Allow 规则＝关端口」模型、从不创建这类规则 → 查询永远为空，导致邮件「当前封禁 IP」恒为 0、威胁等级建立在不存在的数据上。改为 `getActualBlockState()` 直接读 `rdp_guard_state.json` 的 `blockedAt / blockedIPs`。
- **guard 封禁时记录触发 IP**：`rdp-guard.js` 在 `state` 写入 `blockedIPs`（触发源）与 `lastFailCount`，供面板/邮件展示真实原因。
- **内外网判定自洽**：`192.168.3.88` 是本机唯一外网入口（跳板机），guard 早已按外部攻击源检测，但邮件 `isExternalIP` 曾把它误判成「内网」。统一为按外部对待（新增 `DETECT_IP` 常量与之呼应）。
- **Web 面板 `force-close` / `force-cancel` 语义去重**：原两份逻辑完全复制粘贴（都 disable + 设 blockedAt + 删 forceOpen 文件）。现 `force-cancel` 仅取消「强制开启」覆盖、不关端口、交还控制权给 guard；`force-close` 保留「手动关端口 5 分钟」。

### 落地步骤（需管理员一次性执行）
- 本仓库代码已就绪，但「杀掉旧的 0.0.0.0 Web 面板、重注册 SYSTEM 计划任务、启动新面板」需要管理员令牌，无法在非提权环境自动完成。
- 以管理员身份运行 `apply-fix.bat`（或 `powershell -ExecutionPolicy Bypass -File .\wry-elevated-fix.ps1`）即可一键完成：终止旧面板 → 用 `D:\app\nodejs` 重注册 guard/Web看门狗/日报 三个任务 → 立即启动。结果写入 `C:\Users\jianh\Documents\wry-fix-result.log`。
- `register-tasks.ps1` 已重写为全 ASCII（避免中文任务名在 GBK 代码页下乱码导致注册失败），任务名改为 `wry-rdp-guard` / `wry-rdp-web` / `wry-rdp-report`，统一 SYSTEM 主体、不再依赖 QClaw。

## v3.1 (2026-07-21)

### 安全加固
- **Web 面板监听恢复为 127.0.0.1**：撤消 v3.0 之后某次误回退到 `0.0.0.0` 的改动，管理面板不再暴露到局域网
- **强制开启密码去硬编码**：移除默认弱密码 `147369`。优先级：环境变量 `RDP_GUARD_PASSWORD` → `DATA_DIR/rdp_guard_password.txt` → 首次启动随机生成并持久化（重启不变），仅记录一次到日志

### 可靠性（PM 视角核心修复）
- **Node 路径不再写死版本号**：所有脚本（register-tasks.ps1 / watchdog / startup.bat / tray.bat / selfheal）改为动态解析 `QClaw 任意版本 > D:\app\nodejs > workbuddy > PATH`，彻底解决「QClaw 升级后计划任务指向失效路径、防护静默失效」的问题
- **修复 startup.bat 被破坏的 node 路径**（反斜杠丢失导致无法启动）

### 邮件逻辑理顺
- SMTP 配置改从 `rdp_guard_mail.json`（+ 环境变量）读取；缺失密码时优雅跳过（进程退出 0），不再让计划任务崩溃
- 无威胁时段只发一封简短「安全通报」，不再每 12 小时硬塞 500 行大报告，降低噪音、保留心跳

## v3.0 (2026-07-07)

### 安全修复

- **Web 面板仅监听 localhost**：`0.0.0.0` → `127.0.0.1`，不再暴露到外网
- **SMTP 密码移至环境变量**：`SMTP_PASS` / `SMTP_USER` / `REPORT_TO_EMAIL`，代码不再硬编码凭据
- **启动脚本移除密码显示**

### Bug 修复

- **force-close 未清除 force-open 状态**：导致 guard 下次运行时立即覆盖关闭操作
- **force-open 并发重复提交**：新增互斥标志，防止并发请求重复执行
- **阈值不一致统一**：代码/前端/文档统一为 3 次/60 秒（之前前端和文档显示 10 次/300 秒）
- **快照间隔文档修正**：实际为 5 分钟，文档误写为"每小时"
- **跳板机描述修正**：192.168.3.88 参与检测（不放行），文档误写为"不参与检测"

### 稳定性改进

- **进程锁改用排他文件**：`fs.openSync('wx')` 原子创建，替代不可靠的 PID+时间戳方案
- **Watchdog Node 路径自适应**：按优先级尝试 QClaw 路径 → `process.execPath` → 环境变量 → PATH
- **PowerShell 编码检测改进**：优先 UTF-16-LE → UTF-8（JSON 检测）→ GB18030

## v2.0 (2026-07-06)

### 核心逻辑重写

- **移除 IP 黑名单**：不再封禁 IP，攻击时直接关闭 RDP 端口
- **5 分钟自动恢复**：关闭端口 5 分钟后自动重新开放
- **内网全放行**：10.x / 172.16-31.x / 192.168.x.x 完全跳过检测
- **跳板机独立**：192.168.3.88 完全不参与任何检测

### Web 面板重构

- **密码完全后端化**：验证逻辑在后端，前端无密码明文
- **强制开启真正生效**：`/api/force-open` 实际启用防火墙规则
- **强制关闭真正生效**：`/api/force-close` 实际禁用防火墙规则
- **状态实时联动**：按钮根据端口状态动态显示

### 界面美化

- 深色主题，卡片式布局
- 实时倒计时显示（强制开启剩余时间）
- 4 个标签页：防护概览 / 攻击历史 / 防火墙规则 / 操作日志
- 3 秒自动刷新 + 5 秒日志刷新

### 其他改进

- 修复 forceOpen 在封禁中不生效的 bug
- 修复 guard.bat 的 node 路径（v0.2.31 → v0.2.32.610）
- watchdog 使用完整 node 路径，避免 PATH 问题
- 全新启动脚本 `wry-web-admin.bat`（GBK 编码，可直接右键管理员运行）

### 迁移说明

v1 → v2 数据文件兼容（rdp_guard_state.json 结构不变）。旧版数据文件（rdp_guard_v2.json / rdp_guard_v2.log）不再使用。

## v2.0 (2026-07-06)

### 核心逻辑重写

- **移除 IP 黑名单**：不再封禁 IP，攻击时直接关闭 RDP 端口
- **5 分钟自动恢复**：关闭端口 5 分钟后自动重新开放
- **内网全放行**：10.x / 172.16-31.x / 192.168.x.x 完全跳过检测
- **跳板机独立**：192.168.3.88 完全不参与任何检测

### Web 面板重构

- **密码完全后端化**：验证逻辑在后端，前端无密码明文
- **强制开启真正生效**：`/api/force-open` 实际启用防火墙规则
- **强制关闭真正生效**：`/api/force-close` 实际禁用防火墙规则
- **状态实时联动**：按钮根据端口状态动态显示

### 界面美化

- 深色主题，卡片式布局
- 实时倒计时显示（强制开启剩余时间）
- 4 个标签页：防护概览 / 攻击历史 / 防火墙规则 / 操作日志
- 3 秒自动刷新 + 5 秒日志刷新

### 其他改进

- 修复 forceOpen 在封禁中不生效的 bug
- 修复 guard.bat 的 node 路径（v0.2.31 → v0.2.32.610）
- watchdog 使用完整 node 路径，避免 PATH 问题
- 全新启动脚本 `wry-web-admin.bat`（GBK 编码，可直接右键管理员运行）

### 迁移说明

v1 → v2 数据文件兼容（rdp_guard_state.json 结构不变）。旧版数据文件（rdp_guard_v2.json / rdp_guard_v2.log）不再使用。
