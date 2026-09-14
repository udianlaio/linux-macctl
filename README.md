<div align="center">

# 🧭 Linux-macctl

### Control Macs like infrastructure. Automate them like software.

**Secure automation & fleet control for macOS — from Linux.**<br>
**把一台 Linux 主机变成面向 macOS、浏览器、开发工作站与远程服务器的安全自动化控制中心。**<br>
**One Linux gateway. Macs, browsers, workstations and server workflows — under one policy-aware control plane.**

<p>
  <a href="https://github.com/udianlaio/linux-macctl/releases/latest"><img alt="Latest Release" src="https://img.shields.io/github/v/release/udianlaio/linux-macctl?display_name=tag&sort=semver&style=flat-square&logo=github"></a>
  <a href="https://github.com/udianlaio/linux-macctl/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/udianlaio/linux-macctl/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="https://github.com/udianlaio/linux-macctl/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/udianlaio/linux-macctl?style=flat-square"></a>
  <a href="https://github.com/udianlaio/linux-macctl/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/udianlaio/linux-macctl/total?style=flat-square&logo=github"></a>
  <a href="https://github.com/udianlaio/linux-macctl/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/udianlaio/linux-macctl?style=flat-square&logo=github"></a>
</p>

<p>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%E2%86%92%20macOS-111827?style=for-the-badge&logo=linux&logoColor=white">
  <img alt="Security" src="https://img.shields.io/badge/security-FAIL--CLOSED-16a34a?style=for-the-badge&logo=shield&logoColor=white">
  <img alt="Open Source" src="https://img.shields.io/badge/open%20source-Apache--2.0-2563eb?style=for-the-badge&logo=apache&logoColor=white">
</p>

**[⚡ 一键安装](#quick-start) · [✨ 能力总览](#capabilities) · [🏗️ 架构](#architecture) · [🛡️ 安全模型](#security) · [🗺️ Roadmap](#roadmap) · [📦 Releases](https://github.com/udianlaio/linux-macctl/releases)**

</div>

---

## Why Linux-macctl?

远程操作 Mac 并不难。真正难的是：**长期、可审计、可恢复、可扩展地操作它，同时不给自动化系统一张“无限权限通行证”。**

Linux-macctl 不是简单地把 SSH 命令包一层，也不是另一个远程桌面软件。它把远程执行、GUI 自动化、浏览器控制、文件传输、工作站管理、多目标编排和真实业务动作统一到一个具有 **Policy / Transaction / Audit / Recovery** 边界的控制平面里。

<table>
<tr>
<td width="25%" valign="top">
<h3>🛡️ Secure by default</h3>
<p>固定 SSH 信任、显式 host-key 核验、最小权限、敏感动作独立授权、未知动作 fail-closed。</p>
</td>
<td width="25%" valign="top">
<h3>🧠 AI-ready</h3>
<p>可以作为 AI Agent、ChatGPT、自动化平台或人工运维的底层执行面，而不是绑定某一种上层客户端。</p>
</td>
<td width="25%" valign="top">
<h3>🧩 One control plane</h3>
<p>Mac、Browser、Workstation、Linux Fleet、Artifacts、Messaging 使用统一状态、策略和审计模型。</p>
</td>
<td width="25%" valign="top">
<h3>🔁 Recoverable</h3>
<p>超时、崩溃、重复执行、网络异常和生命周期切换都有明确状态，不靠“应该成功了”猜结果。</p>
</td>
</tr>
</table>

> [!NOTE]
> **Linux-macctl 的核心目标不是“获得更多权限”，而是让自动化系统能够在明确边界内可靠地完成更多事情。**

---

<a id="quick-start"></a>

## ⚡ Quick Start

### 1. 一条命令安装

```bash
curl -fsSL https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh | sudo bash
```

安装器会自动完成：

- 获取当前稳定版 GitHub Release；
- 下载源码发行包并执行 **SHA-256 校验**；
- 安装到 `/opt/macctl`；
- 初始化 `/etc/macctl`、状态目录与审计目录；
- 生成独立的 Ed25519 SSH client key；
- 安装 `macctl / macctl-setup / macctl-upgrade / macctl-uninstall`；
- 可直接进入 Mac 首次配对流程。

只安装、不立即配对：

```bash
curl -fsSL https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh | sudo bash -s -- --no-pair
sudo macctl-setup
```

### 2. 在 Mac 上准备 Remote Login

在 macOS 打开：

**系统设置 → 通用 → 共享 → 远程登录**

首次配对时，Linux-macctl 会要求你在 **Mac 本机独立核对 SSH host key 指纹**。它不会使用 `accept-new`、不会关闭 `StrictHostKeyChecking`，也不会把“网络上出现了一台机器”当成可信设备。

### 3. 检查控制平面

```bash
sudo macctl version
sudo macctl ping
sudo macctl auth --fresh
sudo macctl status
sudo macctl doctor
```

升级：

```bash
sudo macctl-upgrade
```

卸载（默认保留配置、状态与 SSH key，方便恢复）：

```bash
sudo macctl-uninstall
```

> [!TIP]
> **一键安装负责 Linux gateway。** SSH/CLI 能力在完成 Mac 配对后即可使用；完整 GUI 自动化还需要部署 `MacCtl Helper`，并由用户在 macOS 中手工批准 Accessibility、Screen Recording、Automation 等 TCC 权限。

完整安装说明见 **[docs/INSTALL.md](docs/INSTALL.md)**。

---

<a id="capabilities"></a>

## ✨ What Linux-macctl can do

下面是当前公开版本所包含的主要控制能力。不同能力的“可执行”不等于“无限授权”：高影响动作、站点写入、账号安全操作和系统级变更仍然受独立 gate 控制。

### 🍎 1. macOS Remote Control

通过固定 OpenSSH 信任链控制远端 Mac，并统一进入 bounded runtime：

- 文件读取、写入、复制、移动、删除、stat、SHA-256；
- Mac ↔ Linux 精确字节文件传输；
- 进程列表、检查、信号与受控终止；
- `launchd` 状态读取与受控服务操作；
- Unified Logging / 系统日志查询；
- 网络接口、DNS、路由、连通性诊断；
- 存储、APFS、磁盘与系统状态读取；
- 电源、会话和登录状态诊断；
- 有界命令执行、timeout 和后代进程清理；
- 多 target 独立身份、known_hosts、transaction 与 audit namespace。

> [!IMPORTANT]
> reboot、shutdown、真实网络切换、安全策略修改、系统升级等高影响动作，不会因为“已经安装”而自动获得执行权限。

### 🖥️ 2. Native macOS GUI Automation

完整 GUI 路径由 macOS Helper + 系统原生能力组成：

- Accessibility / AX 元素定位；
- ScreenCaptureKit 屏幕采集；
- Apple Vision OCR；
- 鼠标点击与移动；
- 键盘、组合键、Unicode / 中文 / emoji 输入；
- NSPasteboard 剪贴板读写与恢复；
- Finder / System Events 等 Automation；
- exact selector / ranked selector；
- 歧义目标 fail-closed；
- 动作前重新解析目标，避免 stale UI reference；
- GUI 操作后的视觉 postcondition 验证。

macOS 的 Accessibility、Screen Recording、Automation 等 TCC 权限必须由用户在系统界面里人工批准。**Linux-macctl 不绕过 TCC。**

### 🌐 3. Browser Automation Engine

Linux-macctl 内置了面向生产自动化的浏览器控制层，而不是暴露一个无限制的 `eval()`：

- isolated Chrome profile；
- Chrome DevTools Protocol / WebSocket；
- Safari native AX + Vision fallback；
- exact-host URL allowlist；
- redirect / loopback 边界；
- DOM query / click / type；
- page extract / semantic analyze；
- wait conditions；
- select / focus / controlled key；
- search primitive；
- multi-tab / activate / close；
- history / reload；
- upload / exact-byte download；
- ScreenCaptureKit + Vision OCR fallback；
- session TTL、PID identity、action lock 和 orphan cleanup；
- password / hidden / token DOM value redaction；
- URL query / fragment redaction。

对于 authenticated production site，写操作必须进入 **site-specific scope**。Publish、Payment、Account Security、credential/cookie/session export 等不会因为浏览器已经可控就自动放行。

### 🧑‍💻 4. Production Workstation Control

Linux-macctl 不只把 Mac 当成“远程终端”，也可以把它作为真正的开发工作站进行资格检查与控制：

- C / C++；
- Swift；
- Python；
- Node.js；
- Go；
- Rust；
- Java / Maven；
- CMake / Ninja；
- Git；
- Docker / Colima；
- VS Code GUI；
- artifact exact round-trip；
- workstation inventory / doctor / qualification。

工具“存在”不会自动等于可用。Workstation qualification 会把 inventory 与 live evidence 分开。

### 🧭 5. Multi-Mac Fleet Control Plane

当前控制平面已经具备多目标模型：

- target registry；
- target-scoped health / qualification；
- target-scoped transaction / audit；
- fleet list / status / doctor / resolve / plan；
- metadata / tag 分组；
- 跨 target request replay 防护；
- 未知 target fail-closed。

> 新 Mac 的自动 bootstrap 属于环境相关能力；每一台新设备都必须重新建立独立 SSH identity 与 host-key trust，不能继承其他设备的可信状态。

### 🐧 6. Remote Linux Fleet & Root Operations

除了控制 Mac，Linux-macctl 也具备受控的远程 Linux 操作能力：

- 多服务器 registry；
- provider / region / role / environment / tags；
- bounded fleet concurrency；
- OpenSSH ControlMaster / ControlPersist；
- rate-limit-aware transport classification；
- 文件与 exact round-trip；
- process；
- systemd；
- journal / logs；
- package inspection；
- route / DNS / HTTPS diagnostics；
- scoped root operations；
- direct primary + emergency fallback transport model。

设计目标是让一台 Linux gateway 同时成为 **Mac control hub + Linux fleet control hub**。

### 💬 7. Delegated Messaging — WeChat

当前已经实现 **WeChat 绑定会话范围内**的委托消息控制：

- contact runtime allowlist；
- login-state detection；
- exact conversation binding；
- visible-history read；
- secure draft；
- controlled send；
- COMPOSER / HISTORY visual postcondition；
- message body 不进入 durable audit / receipt；
- SHA-256 duplicate suppression；
- send rate-limit；
- indeterminate send recovery。

这不是“接管全部微信联系人”。发送权限按绑定会话独立授权，消息正文与持久审计分离。

### 📦 8. Artifact & Attachment Control Plane

文件不是“传过去就算成功”。Linux-macctl 为 artifact 增加了独立的数据完整性模型：

- immutable artifact snapshot；
- SHA-256 exact-byte verification；
- ACL / grant；
- TTL / GC；
- MIME / OOXML validation；
- upload / download；
- presentation / delivery session；
- idempotency / correlation；
- host receipt；
- exact-original verification；
- secret-like artifact fail-closed。

### 🔁 9. Lifecycle & Recovery

控制系统真正难的是异常恢复。Linux-macctl 的状态模型覆盖：

- SSH ControlMaster stale socket；
- timeout / descendant cleanup；
- login / logout lifecycle；
- sleep / Wake-on-LAN；
- DarkWake 与 GUI readiness 区分；
- controlled reboot；
- boot epoch；
- pre-login vs post-login readiness；
- route / VPN disruption classification；
- browser crash orphan recovery；
- transaction replay / indeterminate mutation recovery；
- committed-source backup / restore drill。

系统不会把 `HEADLESS_READY`、`LOGIN_REQUIRED` 或“网络刚恢复”冒充成 `FULL_READY`。

---

<a id="architecture"></a>

## 🏗️ Architecture

Linux-macctl 把**传输、权限、动作、证据**拆成不同层，避免所有能力都坍缩成一个 root shell。

```text
               AI Agent / ChatGPT / Human Operator
                            │
                    SentinelX / SSH / API
                            │
                  ┌─────────▼─────────┐
                  │   Linux Gateway    │
                  │   linux-macctl     │
                  ├────────────────────┤
                  │ Policy             │
                  │ Transaction        │
                  │ Audit              │
                  │ Doctor / Recovery  │
                  │ Browser Engine     │
                  │ Artifact Engine    │
                  │ Fleet Control      │
                  └───────┬─────┬──────┘
                          │     │
                pinned SSH│     │OpenSSH
                          │     │
             ┌────────────▼─┐ ┌─▼────────────────┐
             │ macOS Target │ │ Remote Linux     │
             ├──────────────┤ │ Fleet            │
             │ OpenSSH      │ ├──────────────────┤
             │ MacCtl Helper│ │ files / process  │
             │ AX / TCC     │ │ systemd / logs   │
             │ SCK / Vision │ │ scoped root ops  │
             │ Browser/App  │ │ fleet transport  │
             └──────────────┘ └──────────────────┘
```

### Control model

```text
Request
  ↓
Target Resolution
  ↓
Policy Classification
  ↓
Precondition
  ↓
Write-Ahead / Transaction Intent
  ↓
Bounded Execution
  ↓
Postcondition / Evidence
  ↓
Audit / Receipt
  ↓
Completed | Failed | Reconcile Required
```

这使 Linux-macctl 更接近一个“小型控制平面”，而不是一组散落的 shell 脚本。

---

<a id="security"></a>

## 🛡️ Security by Design

安全设计不是附加项，而是项目的一等能力。

| 安全边界 | 默认行为 |
|---|---|
| SSH Host Key | `StrictHostKeyChecking=yes`，必须独立核验 |
| Client Key | 本机生成，默认位于 `/etc/macctl`，不进入 Git/Release |
| Password | 只交给 OpenSSH 终端提示，Linux-macctl 不读取、不保存 |
| Unknown target | Fail closed |
| Unknown action | Fail closed |
| macOS TCC | 必须人工授权，不修改 TCC.db |
| System Update | 默认禁止 |
| Major Upgrade | 默认禁止 |
| High-impact mutation | 需要独立确认/授权 gate |
| Browser secrets | password/hidden/token value 默认不回传 |
| Messaging content | 正文不进入 durable receipt/audit |
| Artifact | exact SHA-256 / ACL / TTL / secret detection |
| Transaction | request-id / precondition / postcondition / replay control |
| Audit | digest chain / integrity verification / bounded metadata |

> [!WARNING]
> Linux-macctl 是高能力自动化工具。请只控制你拥有或明确获准管理的设备、账号和服务。不要通过修改源码或配置绕过平台权限、组织策略或法律授权边界。

更多信息：

- **[SECURITY.md](SECURITY.md)**
- **[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)**
- **[PUBLIC_PROVENANCE.json](PUBLIC_PROVENANCE.json)**

---

## 🚦 Capability Status

| Domain | Status | Notes |
|---|---:|---|
| Linux → macOS secure SSH control | ✅ Available | 固定 host-key + public-key trust |
| macOS file/process/launchd/log/network/storage | ✅ Available | 高影响 mutation 仍独立 gate |
| macOS GUI / AX / ScreenCapture / Vision | ✅ Available | 需要用户手工批准 TCC |
| Browser Engine / Chrome CDP | ✅ Available | exact-host / bounded action model |
| Safari native fallback | ✅ Available | AX + Vision 路径 |
| Production workstation qualification | ✅ Available | inventory 与 live qualification 分离 |
| Multi-Mac control plane | ✅ Control plane | 新设备必须单独建立 trust |
| Remote Linux fleet/root operations | ✅ Available | scoped root + bounded fleet concurrency |
| WeChat delegated messaging | ✅ Bounded | 仅绑定会话范围 |
| Artifact / attachment integrity pipeline | ✅ Available | exact-byte / SHA-256 / receipt |
| Logout / sleep / WOL / reboot recovery model | ✅ Available | 环境相关能力需现场满足条件 |
| Feishu delegated messaging | 🧪 Planned / Deferred | 当前不宣称支持 |
| Windows native reverse control | 🧪 Planned / Deferred | 当前不宣称支持 |
| Physical Ethernet ↔ Wi-Fi failover | ⚠️ Environment-specific | 不做泛化 PASS |
| Cold-power / OOB power control | ➖ Not in scope | 需要独立硬件/OOB 方案 |

---

## 🎯 Use Cases

### AI Operator for a Mac workstation

让上层 Agent 安全地完成：

```text
检查 Mac readiness
→ 拉取代码
→ 构建/测试
→ 操作 GUI 工具
→ 浏览器验证
→ 收集 artifact
→ SHA-256 校验
→ 返回结果
```

### Browser workflow automation

```text
打开 isolated browser session
→ exact-host policy
→ 页面结构提取
→ DOM / AX / Vision 路由
→ 动作
→ postcondition
→ 下载产物
→ cleanup
```

### Fleet operations

```text
按 provider / region / role / tag 选择目标
→ bounded concurrency
→ transport classification
→ scoped operation
→ per-target evidence
→ fleet summary
```

### Human-approved real-world workflows

```text
AI 提议动作
→ Policy 分类
→ 需要时请求显式确认
→ 执行动作
→ 视觉/系统 postcondition
→ Audit receipt
```

---

## 🔧 Operating Principles

Linux-macctl 的几条核心原则：

1. **Capability ≠ Authorization** — 能做到，不代表默认允许做。
2. **Evidence over assumptions** — 没有证据就不把状态写成 PASS。
3. **Exactly one or fail** — UI / selector / target 有歧义时拒绝猜测。
4. **Bound everything** — timeout、输出、并发、TTL、重试都应该有界。
5. **Secrets stay out of durable state** — 密钥、密码、消息正文、token 不应该出现在源码或长期审计里。
6. **Recovery is part of execution** — crash、reboot、network loss 不是“异常分支”，而是控制系统本身的一部分。
7. **Immutable releases** — 正式 Release 不移动、不覆盖、不回写历史资产。

---

<a id="roadmap"></a>

## 🗺️ Roadmap

Roadmap 是方向，不是对版本日期的承诺。所有新增高影响能力都会先经过独立安全合同和真实资格验证，再进入公开支持范围。

### v0.6.x — Public Distribution & Hardening

- [x] 一键公网安装；
- [x] clean-history public distribution；
- [x] Apache-2.0；
- [x] deterministic release package；
- [x] immutable GitHub Release；
- [x] public privacy scanner；
- [ ] Debian / Ubuntu `.deb`；
- [ ] Fedora / RHEL `.rpm`；
- [ ] Arch / openSUSE 原生包；
- [ ] SBOM；
- [ ] Sigstore / signed provenance；
- [ ] 多发行版 fresh-VM installer CI；
- [ ] 更完善的安装诊断和 rollback UX。

### v0.7 — Workflow Orchestration

目标：从“能控制”升级为“能可靠执行完整工作流”。

- declarative workflow / runbook；
- step dependency；
- conditional execution；
- approval gate；
- retry / timeout / compensation；
- step-level transaction；
- long-running task state；
- scheduled / event-driven workflows；
- browser → Mac → Linux → Messaging 的跨域编排；
- workflow-level audit / evidence bundle。

### v0.8 — Fleet Control Center

- 大规模 target onboarding；
- device group / role / environment；
- fleet policy；
- fleet health dashboard；
- drift detection；
- distributed job execution；
- rollout / canary；
- target capability discovery；
- operator / agent role separation；
- 更强的 backup / restore / disaster recovery。

### v0.9 — Cross-platform & More Adapters

- Windows Native Control：PowerShell、Services、Process、Filesystem、Registry、Event Log、Scheduled Tasks、Windows UI Automation；
- WSL2 作为 Windows target 下的 Linux execution domain；
- Feishu delegated messaging adapter；
- 更多浏览器和应用级 adapter；
- 更多远程 transport / bridge；
- 可插拔 notification / messaging / artifact backend。

### Toward v1.0 — Open Automation Platform

- extension / adapter SDK；
- signed extension packages；
- policy pack；
- reusable workflow marketplace；
- RBAC / multi-operator；
- secret-provider integration；
- richer observability；
- stable public API / compatibility contract。

---

## 📦 Release Engineering

公开版本坚持可复现和不可变发布：

- GitHub Actions CI；
- public privacy scan；
- deterministic tarball；
- SHA-256 sidecar；
- release manifest；
- GitHub Immutable Releases；
- Apache-2.0 LICENSE 内置在发行包；
- release assets 远端 digest 验证；
- 安装器下载后先校验再解包；
- 正式 tag 不随着 `main` 后续提交移动。

当前稳定版：**v0.6.2**<br>
Releases：**https://github.com/udianlaio/linux-macctl/releases**

---

## 🔒 Privacy & Public Provenance

公开仓库来自经过审计的公开发行树，而不是把内部开发仓库历史直接暴露出来。

公开源码与 Release **不包含**：

- 开发者真实主机配置；
- SSH private key；
- Token / Cookie；
- 测试联系人；
- 私有 LAN / 云主机拓扑；
- Keychain / TCC database；
- runtime `/etc/macctl`；
- audit log / transaction runtime；
- 私有资格验证证据。

这部分信息放在这里，是为了说明供应链和隐私边界，而不是把它当作项目的第一句自我介绍。

公开来源关系见 **[PUBLIC_PROVENANCE.json](PUBLIC_PROVENANCE.json)**。

---

## ❓ FAQ

<details>
<summary><b>Linux-macctl 是远程桌面软件吗？</b></summary>
<br>
不是。它更接近一个自动化控制平面。远程桌面解决的是“人看到屏幕并操作”，Linux-macctl 解决的是“系统如何在明确策略、状态、证据和恢复边界内执行动作”。GUI 只是其中一个执行域。
</details>

<details>
<summary><b>一定要配合 ChatGPT 或 SentinelX 吗？</b></summary>
<br>
不一定。`macctl` 本身是 Linux 上的控制 CLI。ChatGPT、SentinelX、其他 Agent、CI、脚本或人工终端都可以作为上层调用者。具体上层 transport 与账号体系不属于 Linux-macctl 的强绑定依赖。
</details>

<details>
<summary><b>它会保存我的 Mac 密码吗？</b></summary>
<br>
不会。首次公钥投递需要密码时，密码交给 OpenSSH 的终端提示。Linux-macctl 不读取、不持久化密码。
</details>

<details>
<summary><b>为什么不能自动接受 SSH host key？</b></summary>
<br>
因为第一次连接正是最需要验证目标身份的时候。自动 `accept-new` 会把“第一次看到的机器”当成可信机器，这与本项目的目标身份模型冲突。
</details>

<details>
<summary><b>能不能自动授予 macOS Accessibility / Screen Recording？</b></summary>
<br>
不能，也不会尝试绕过。TCC 权限必须由用户在 macOS 系统界面中批准。
</details>

<details>
<summary><b>能控制多台 Mac 吗？</b></summary>
<br>
控制平面支持多 target / fleet 模型；但每一台新 Mac 都必须单独建立 identity、known_hosts 和资格状态。不会把第一台机器的授权自动继承给第二台。
</details>

<details>
<summary><b>Windows 呢？</b></summary>
<br>
Windows Native Control 已列入未来路线，但当前公开版本不宣称支持。未来设计方向是直接控制 Windows Native 能力，WSL2 作为 Windows target 下的辅助 Linux execution domain，而不是通过 Linux VM 反向绕回 Windows。
</details>

---

## 🤝 Contributing

欢迎 Issue、PR、文档改进、发行版适配和新 adapter 提案。

- **Bug / Feature Request:** https://github.com/udianlaio/linux-macctl/issues
- **Pull Requests:** https://github.com/udianlaio/linux-macctl/pulls
- 大型能力建议建议先开 Issue 讨论安全边界、兼容面和测试策略；
- 涉及新 target / browser / messaging / privileged action 的 PR，应同时说明 fail-closed 行为和测试合同。

如果这个项目对你有帮助，欢迎给一个 ⭐。它会帮助更多需要 **AI + macOS + Linux automation** 的人看到这个项目。

---

## 📄 License

Linux-macctl is open source under the **Apache License 2.0**.

你可以自由使用、修改、分发和用于商业场景，同时需遵守 Apache-2.0 的许可证与通知要求。Apache-2.0 同时提供明确的专利授权与专利争议终止条款。

完整条款见 **[LICENSE](LICENSE)**。

---

<div align="center">

### Linux-macctl

**Build powerful automation. Keep control explicit.**

`Linux → macOS · Browser · Workstation · Fleet · Messaging · Policy · Audit · Recovery`

</div>
