#!/usr/bin/env bash
set -euo pipefail
VERSION="${MACCTL_VERSION:-0.6.2}"
REPO="${MACCTL_PUBLIC_REPO:-udianlaio/linux-macctl}"
TAG="linux-v${VERSION}"
ASSET="linux-macctl-${VERSION}.tar.gz"
PREFIX="${MACCTL_PREFIX:-/opt/macctl}"
CONFIG_DIR="${MACCTL_CONFIG_DIR:-/etc/macctl}"
BIN_DIR="${MACCTL_BIN_DIR:-/usr/local/bin}"
STATE_DIR="${MACCTL_STATE_DIR:-/var/lib/macctl}"
LOG_DIR="${MACCTL_LOG_DIR:-/var/log/macctl}"
RUN_DIR="${MACCTL_RUN_DIR:-/run/macctl}"
NO_PAIR=0
ARCHIVE=""
CHECKSUM=""
for a in "$@"; do
  case "$a" in
    --no-pair|--upgrade) NO_PAIR=1 ;;
    --help|-h) echo "usage: install.sh [--no-pair] [--upgrade]"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 64 ;;
  esac
done
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "请使用 sudo/root 运行安装器。" >&2; exit 77; }
need=(python3 curl tar sha256sum ssh ssh-keygen ssh-keyscan)
missing=()
for c in "${need[@]}"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
if ((${#missing[@]})); then
  echo "缺少依赖: ${missing[*]}" >&2
  if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y python3 curl ca-certificates openssh-client coreutils tar
  elif command -v dnf >/dev/null 2>&1; then dnf install -y python3 curl ca-certificates openssh-clients coreutils tar
  elif command -v yum >/dev/null 2>&1; then yum install -y python3 curl ca-certificates openssh-clients coreutils tar
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install python3 curl ca-certificates openssh coreutils tar
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm python curl ca-certificates openssh coreutils tar
  else echo "无法自动安装依赖，请先安装: ${missing[*]}" >&2; exit 69; fi
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [[ -n "${MACCTL_LOCAL_ARCHIVE_DIR:-}" ]]; then
  cp "$MACCTL_LOCAL_ARCHIVE_DIR/$ASSET" "$TMP/$ASSET"
  cp "$MACCTL_LOCAL_ARCHIVE_DIR/$ASSET.sha256" "$TMP/$ASSET.sha256"
else
  BASE="${MACCTL_RELEASE_BASE_URL:-https://github.com/${REPO}/releases/download/${TAG}}"
  curl -fL --retry 3 --proto '=https' --tlsv1.2 -o "$TMP/$ASSET" "$BASE/$ASSET"
  curl -fL --retry 3 --proto '=https' --tlsv1.2 -o "$TMP/$ASSET.sha256" "$BASE/$ASSET.sha256"
fi
( cd "$TMP" && sha256sum -c "$ASSET.sha256" )
python3 - "$TMP/$ASSET" <<'PY'
import tarfile,sys
with tarfile.open(sys.argv[1],'r:gz') as t:
    for m in t.getmembers():
        p=m.name
        parts=p.split('/')
        if p.startswith('/') or '..' in parts:
            raise SystemExit('unsafe archive member: '+p)
        if m.issym() or m.islnk():
            target=m.linkname
            if target.startswith('/') or '..' in target.split('/'):
                raise SystemExit('unsafe archive link: '+p)
PY
mkdir -p "$TMP/src"
tar -xzf "$TMP/$ASSET" -C "$TMP/src" --strip-components=1 --no-same-owner
[[ -f "$TMP/src/src/linux_macctl/cli.py" && -f "$TMP/src/PUBLIC_PROVENANCE.json" ]] || { echo "invalid release payload" >&2; exit 65; }
if [[ -d "$PREFIX" ]]; then
  BACKUP="${PREFIX}.pre-${VERSION}-$(date +%Y%m%d%H%M%S)"
  cp -a "$PREFIX" "$BACKUP"
  echo "已备份旧程序到 $BACKUP"
fi
mkdir -p "$PREFIX" "$CONFIG_DIR" "$STATE_DIR" "$STATE_DIR/transactions" "$STATE_DIR/artifacts" "$STATE_DIR/attachment-deliveries" "$STATE_DIR/attachment-relays" "$LOG_DIR" "$RUN_DIR"
rm -rf "$PREFIX"/*
cp -a "$TMP/src/." "$PREFIX/"
chmod 0755 "$PREFIX/install.sh" "$PREFIX/setup-target.sh" "$PREFIX/upgrade.sh" "$PREFIX/uninstall.sh"
chmod 0755 "$PREFIX/macos-helper/build.sh" "$PREFIX/macos-helper/setup-signing.sh"
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then cp "$PREFIX/config.example.json" "$CONFIG_DIR/config.json"; fi
if [[ ! -f "$CONFIG_DIR/id_ed25519" ]]; then ssh-keygen -q -t ed25519 -a 64 -N '' -C 'linux-macctl' -f "$CONFIG_DIR/id_ed25519"; fi
: > "$CONFIG_DIR/known_hosts.tmp"; rm -f "$CONFIG_DIR/known_hosts.tmp"
touch "$CONFIG_DIR/known_hosts"
chmod 0750 "$CONFIG_DIR" "$LOG_DIR"
chmod 0600 "$CONFIG_DIR/config.json" "$CONFIG_DIR/id_ed25519" "$CONFIG_DIR/known_hosts"
chmod 0644 "$CONFIG_DIR/id_ed25519.pub"
cat > "$BIN_DIR/macctl" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$PREFIX/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m linux_macctl.cli "\$@"
EOF
cat > "$BIN_DIR/macctl-setup" <<EOF
#!/usr/bin/env bash
exec "$PREFIX/setup-target.sh" "\$@"
EOF
cat > "$BIN_DIR/macctl-upgrade" <<EOF
#!/usr/bin/env bash
exec "$PREFIX/upgrade.sh" "\$@"
EOF
cat > "$BIN_DIR/macctl-uninstall" <<EOF
#!/usr/bin/env bash
exec "$PREFIX/uninstall.sh" "\$@"
EOF
chmod 0755 "$BIN_DIR/macctl" "$BIN_DIR/macctl-setup" "$BIN_DIR/macctl-upgrade" "$BIN_DIR/macctl-uninstall"
python3 - "$CONFIG_DIR/config.json" "$VERSION" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['version']=sys.argv[2]
open(p,'w').write(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
PY
python3 -m compileall -q "$PREFIX"
echo "Linux-macctl ${VERSION} 安装完成。"
if [[ "$NO_PAIR" -eq 0 && -r /dev/tty && -w /dev/tty ]]; then
  printf '现在配置一台 Mac 目标？[Y/n] ' >/dev/tty
  read -r ans </dev/tty || ans=n
  case "${ans:-Y}" in n|N|no|NO) ;; *) "$PREFIX/setup-target.sh" ;; esac
else
  echo "稍后可运行: sudo macctl-setup"
fi
