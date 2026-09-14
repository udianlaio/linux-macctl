#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=$(tr -d '\r\n' < VERSION)
TAG="linux-v${VERSION}"
OUT=${1:-dist}
[[ -z "$(git status --porcelain)" ]] || { echo 'working tree must be clean' >&2; exit 65; }
HEAD=$(git rev-parse HEAD); TREE=$(git rev-parse 'HEAD^{tree}')
mkdir -p "$OUT"
T=$(mktemp); trap 'rm -f "$T"' EXIT
git archive --format=tar --prefix="linux-macctl-${VERSION}/" HEAD > "$T"
gzip -n -9 < "$T" > "$OUT/linux-macctl-${VERSION}.tar.gz"
SHA=$(sha256sum "$OUT/linux-macctl-${VERSION}.tar.gz" | awk '{print $1}')
printf '%s  %s\n' "$SHA" "linux-macctl-${VERSION}.tar.gz" > "$OUT/linux-macctl-${VERSION}.tar.gz.sha256"
python3 - "$OUT/linux-macctl-release-${VERSION}.json" "$VERSION" "$TAG" "$HEAD" "$TREE" "$SHA" <<'PY'
import json,sys
p,v,tag,head,tree,sha=sys.argv[1:]
json.dump({'schema':'linux-macctl-public-release/v1','version':v,'tag':tag,'git_commit':head,'git_tree':tree,'artifact':{'name':f'linux-macctl-{v}.tar.gz','sha256':sha},'history_exported':False,'runtime_secrets_exported':False},open(p,'w'),indent=2,sort_keys=True); open(p,'a').write('\n')
PY
sha256sum "$OUT"/*
