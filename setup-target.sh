#!/usr/bin/env bash
set -euo pipefail
PREFIX="${MACCTL_PREFIX:-/opt/macctl}"
CONFIG_DIR="${MACCTL_CONFIG_DIR:-/etc/macctl}"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "请使用 sudo/root 运行。" >&2; exit 77; }
[[ -r /dev/tty && -w /dev/tty ]] || { echo "目标配对需要交互式终端。" >&2; exit 69; }
ask(){ local p="$1" d="$2" v; printf '%s [%s]: ' "$p" "$d" >/dev/tty; read -r v </dev/tty; printf '%s' "${v:-$d}"; }
TARGET=$(ask '目标名称' 'macmini')
HOST=$(ask 'Mac 主机名或 IP' 'macmini.local')
PORT=$(ask 'SSH 端口' '22')
USER=$(ask 'Mac 登录用户名' "$(logname 2>/dev/null || echo macuser)")
[[ "$TARGET" =~ ^[A-Za-z0-9._-]+$ ]] || { echo '非法目标名称' >&2; exit 64; }
[[ "$HOST" =~ ^[A-Za-z0-9.:_-]+$ ]] || { echo '非法主机名/IP' >&2; exit 64; }
[[ "$USER" =~ ^[A-Za-z0-9._-]+$ ]] || { echo '非法用户名' >&2; exit 64; }
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || { echo '非法端口' >&2; exit 64; }
IDENTITY="$CONFIG_DIR/id_ed25519"; KNOWN="$CONFIG_DIR/known_hosts"; SSHCFG="$CONFIG_DIR/ssh_config"
[[ -f "$IDENTITY" ]] || ssh-keygen -q -t ed25519 -a 64 -N '' -C 'linux-macctl' -f "$IDENTITY"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
if ! ssh-keyscan -T 5 -p "$PORT" -t ed25519 "$HOST" > "$TMP" 2>/dev/null || [[ ! -s "$TMP" ]]; then
  echo "无法读取 Mac SSH host key。请先在 macOS 系统设置中启用 Remote Login（远程登录）。" >&2; exit 68
fi
echo '即将信任的 Mac SSH host key 指纹：'
ssh-keygen -lf "$TMP"
echo '请在 Mac 本机核对 /etc/ssh/ssh_host_ed25519_key.pub 的 SHA256 指纹。'
printf '已从 Mac 本机独立核对并完全一致？输入大写 YES 继续: ' >/dev/tty
read -r confirmed </dev/tty
[[ "$confirmed" == YES ]] || { echo '未确认 host key，已停止；没有写入信任关系。' >&2; exit 77; }
cat "$TMP" > "$KNOWN"; chmod 0600 "$KNOWN"
cat > "$SSHCFG" <<EOF
Host $TARGET
    HostName $HOST
    Port $PORT
    User $USER
    IdentityFile $IDENTITY
    IdentitiesOnly yes
    BatchMode yes
    PreferredAuthentications publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    StrictHostKeyChecking yes
    UserKnownHostsFile $KNOWN
    CheckHostIP yes
    VerifyHostKeyDNS no
    ControlMaster auto
    ControlPath /run/macctl/%C
    ControlPersist 600
    ConnectTimeout 5
    ConnectionAttempts 1
    ServerAliveInterval 15
    ServerAliveCountMax 2
    ForwardAgent no
    ForwardX11 no
    RequestTTY no
    LogLevel ERROR
EOF
chmod 0600 "$SSHCFG"
echo '正在把 Linux-macctl 公钥加入 Mac。若 Mac 要求密码，请直接在终端输入；密码不会被脚本读取或保存。'
PUB="$IDENTITY.pub"
if command -v ssh-copy-id >/dev/null 2>&1; then
  ssh-copy-id -i "$PUB" -p "$PORT" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes "$USER@$HOST"
else
  cat "$PUB" | ssh -p "$PORT" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes -o PreferredAuthentications=password,keyboard-interactive "$USER@$HOST" 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; IFS= read -r k; grep -qxF "$k" ~/.ssh/authorized_keys || printf "%s\n" "$k" >> ~/.ssh/authorized_keys'
fi
python3 - "$CONFIG_DIR/config.json" "$TARGET" "$HOST" "$PORT" "$USER" <<'PY'
import json,sys
p,target,host,port,user=sys.argv[1:]
d=json.load(open(p)); d.update(target=target,host=host,port=int(port),user=user,ssh_config_file='/etc/macctl/ssh_config',identity_file='/etc/macctl/id_ed25519',known_hosts_file='/etc/macctl/known_hosts')
open(p,'w').write(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
PY
chmod 0600 "$CONFIG_DIR/config.json"
echo '基础 SSH 配对完成，开始只读验证：'
/usr/local/bin/macctl ping
/usr/local/bin/macctl auth --fresh
/usr/local/bin/macctl status
set +e
/usr/local/bin/macctl doctor
rc=$?
set -e
if ((rc!=0)); then
  echo '基础 SSH 已完成；Doctor 尚未 FULL_READY 通常表示 MacCtl Helper/TCC GUI 权限尚未配置。'
  echo '请阅读 /opt/macctl/docs/INSTALL.md 的“macOS GUI 权限”部分。'
fi
