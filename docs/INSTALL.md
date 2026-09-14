# 安装与首次配对

## Linux 网关

支持常见 Linux 发行版。需要 root/sudo、Python 3、OpenSSH client、curl、tar、sha256sum。安装器可在 apt/dnf/yum/zypper/pacman 系统自动补齐缺失依赖。

一键安装命令见 README。默认安装位置：程序 `/opt/macctl`，配置 `/etc/macctl`，状态 `/var/lib/macctl`，审计 `/var/log/macctl`。

## Mac 配对

`sudo macctl-setup` 会生成/复用独立 ed25519 client key，读取 Mac ed25519 SSH host key，并要求操作者在 Mac 本机核对指纹后输入 `YES`。之后通过 OpenSSH 的密码提示完成一次公钥投递；脚本不会读取或保存密码。

## macOS GUI 权限

完整 GUI 控制需要 MacCtl Helper 和 macOS TCC 权限。公开版保留 Helper 源码，但不会自动修改 TCC 数据库。Accessibility、Screen Recording、Finder/System Events Automation 必须由用户在 macOS UI 中人工批准。

`macctl doctor` 会区分 SSH、GUI session、Helper、TCC、AX、ScreenCapture、Vision 等 readiness，不会把“SSH 可用”冒充“FULL_READY”。

## 升级/卸载

`sudo macctl-upgrade` 保留 `/etc/macctl` 配置和生成的 SSH key。`sudo macctl-uninstall` 默认也保留配置/状态；`--purge` 才删除本机运行数据。卸载不会静默删除远端 Mac 的 authorized_keys 条目。
