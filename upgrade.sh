#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || exec sudo "$0" "$@"
URL="https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh"
curl -fsSL --proto '=https' --tlsv1.2 "$URL" | bash -s -- --upgrade --no-pair
