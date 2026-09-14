# Security

## 不进入公开仓库/Release 的内容

- SSH 私钥、known_hosts 的真实内容、密码、Token、Cookie、Keychain、TCC 数据库；
- 真实用户名、测试联系人、内网 IP/MAC、设备序列号/UUID；
- `/etc/macctl`、`/var/lib/macctl`、`/var/log/macctl` 运行时数据；
- 私有工程仓库的历史提交和内部资格证据。

## 安装链

`install.sh` 从 GitHub Release 下载版本化源码包并验证 `.sha256` 后才安装。Release 使用 immutable releases 时，tag 与 assets 在发布后不可替换。

## 报告安全问题

请通过 GitHub Security Advisories 的私密报告功能；不要在公开 issue 中粘贴密钥、日志或真实基础设施信息。
