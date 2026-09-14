#!/usr/bin/env bash
set -euo pipefail
PURGE=0
[[ ${1:-} == --purge ]] && PURGE=1
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '请使用 sudo/root 运行。' >&2; exit 77; }
rm -f /usr/local/bin/macctl /usr/local/bin/macctl-setup /usr/local/bin/macctl-upgrade /usr/local/bin/macctl-uninstall
if [[ -d /opt/macctl ]]; then mv /opt/macctl "/opt/macctl.uninstalled.$(date +%Y%m%d%H%M%S)"; fi
if ((PURGE)); then
  echo 'PURGE 会删除本机配置、生成的 SSH 私钥、审计与状态；不会自动修改远端 Mac authorized_keys。'
  rm -rf /etc/macctl /var/lib/macctl /var/log/macctl /run/macctl
else
  echo '程序已卸载；/etc/macctl、/var/lib/macctl、/var/log/macctl 已保留以便恢复。'
fi
