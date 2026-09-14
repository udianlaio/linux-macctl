# Linux-macctl

Linux 网关到 macOS 的受控远程控制平面。公开仓库使用**干净 Git 历史**，不包含开发者的真实主机配置、私钥、测试联系人、内网拓扑或内部资格证据。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh | sudo bash
```

安装器会：下载固定版本 Release、校验 SHA-256、安装到 `/opt/macctl`、生成独立 SSH 密钥，并可在同一条命令内进入 Mac 配对向导。密码只由 OpenSSH 在终端中读取，Linux-macctl 不读取、不记录密码。

只安装、不立即配对：

```bash
curl -fsSL https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh | sudo bash -s -- --no-pair
sudo macctl-setup
```

## macOS 前置条件

1. 在 Mac 上打开 **系统设置 → 通用 → 共享 → 远程登录**。
2. 配对时必须在 Mac 本机独立核对 SSH host key 指纹；安装器不会自动跳过 `StrictHostKeyChecking`。
3. 终端/文件/进程等 SSH 能力完成后即可使用。Accessibility、Screen Recording、Automation 等 GUI 权限必须由用户在 macOS 中人工批准；本项目不会绕过 TCC。

## 常用命令

```bash
sudo macctl version
sudo macctl ping
sudo macctl auth --fresh
sudo macctl status
sudo macctl doctor
sudo macctl-upgrade
sudo macctl-uninstall
```

## 安全边界

- 默认 `StrictHostKeyChecking=yes`，不接受“首次连接自动信任”。
- 私钥只生成在本机 `/etc/macctl`，权限 0600，不进入 Git/Release。
- macOS system update / major upgrade 默认禁止。
- 高影响操作继续要求显式确认；安装成功不等于自动授权 reboot、shutdown、真实网络切换或安全策略变更。
- 微信委托消息能力属于绑定会话的受限能力；不会自动扩展到所有联系人。
- Feishu 与 Windows Reverse Control 不在当前公开资格范围。

## 版本

公开发行版：**0.6.1**。核心控制面来源于已验收 `Linux-macctl v0.6.0`，公开版增加 clean-history distribution、隐私清洗和一键安装层。详见 `PUBLIC_PROVENANCE.json`。

## 许可

本仓库当前未附加开放源代码许可证；公开可见不等同于授予再分发/衍生授权。若需要社区开源协作，可由仓库所有者后续明确选择许可证。
