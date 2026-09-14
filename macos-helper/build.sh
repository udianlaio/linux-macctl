#!/bin/sh
set -eu
APP="${1:-$HOME/Applications/MacCtl Helper.app}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIGN_DIR="${MACCTL_SIGN_DIR:-$HOME/.macctl/signing}"
SIGN_KEYCHAIN="${MACCTL_SIGN_KEYCHAIN:-$SIGN_DIR/macctl-signing.keychain-db}"
SIGN_PASSFILE="${MACCTL_SIGN_PASSFILE:-$SIGN_DIR/keychain.pass}"
SIGN_IDENTITY="${MACCTL_SIGN_IDENTITY:-MacCtl Local Code Signing}"

mkdir -p "$APP/Contents/MacOS"
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
/usr/bin/clang -fobjc-arc -O2 -framework Cocoa -framework ApplicationServices -framework CoreGraphics -framework ScreenCaptureKit -framework Vision -framework ServiceManagement \
  -o "$APP/Contents/MacOS/MacCtlHelper" "$HERE/MacCtlHelper.m"

SIGN_MODE=adhoc
if [ -f "$SIGN_KEYCHAIN" ] && [ -s "$SIGN_PASSFILE" ]; then
  PASS=$(cat "$SIGN_PASSFILE")
  /usr/bin/security unlock-keychain -p "$PASS" "$SIGN_KEYCHAIN" >/dev/null 2>&1 || true
  if /usr/bin/security find-identity -v -p codesigning "$SIGN_KEYCHAIN" 2>/dev/null | /usr/bin/grep -Fq "$SIGN_IDENTITY"; then
    /usr/bin/codesign --force --keychain "$SIGN_KEYCHAIN" --sign "$SIGN_IDENTITY" --identifier app.openai.macctl.helper \
      --options runtime --entitlements "$HERE/MacCtlHelper.entitlements" "$APP"
    SIGN_MODE=local-identity
  else
    /usr/bin/codesign --force --sign - --identifier app.openai.macctl.helper \
      --options runtime --entitlements "$HERE/MacCtlHelper.entitlements" "$APP"
  fi
else
  /usr/bin/codesign --force --sign - --identifier app.openai.macctl.helper \
    --options runtime --entitlements "$HERE/MacCtlHelper.entitlements" "$APP"
fi

/usr/bin/codesign --verify --deep --strict "$APP"
echo "Built: $APP"
echo "SignMode=$SIGN_MODE"
/usr/bin/codesign -dv --verbose=2 "$APP" 2>&1 | egrep "Identifier=|Signature=|Authority=|TeamIdentifier=" || true
/usr/bin/codesign -dr - "$APP" 2>&1 || true
