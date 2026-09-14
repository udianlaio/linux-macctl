#!/bin/sh
set -eu
DIR="$HOME/.macctl/signing"
KC="$DIR/macctl-signing.keychain-db"
PASSFILE="$DIR/keychain.pass"
KEY="$DIR/codesign.key.pem"
CERT="$DIR/codesign.crt.pem"
P12="$DIR/signer.p12"
IDENTITY="MacCtl Local Code Signing"
mkdir -p "$DIR"
chmod 700 "$DIR"
if [ ! -s "$PASSFILE" ]; then
  /usr/bin/openssl rand -hex 32 > "$PASSFILE"
  chmod 600 "$PASSFILE"
fi
PASS=$(cat "$PASSFILE")
if [ ! -f "$KC" ]; then
  /usr/bin/security create-keychain -p "$PASS" "$KC"
fi
/usr/bin/security set-keychain-settings -lut 21600 "$KC"
/usr/bin/security unlock-keychain -p "$PASS" "$KC"
if ! /usr/bin/security list-keychains -d user | /usr/bin/grep -Fq "$KC"; then
  /usr/bin/security list-keychains -d user -s "$HOME/Library/Keychains/login.keychain-db" "$KC"
fi
if ! /usr/bin/security find-certificate -c "$IDENTITY" "$KC" >/dev/null 2>&1; then
  /usr/bin/openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
    -keyout "$KEY" -out "$CERT" -days 3650 \
    -subj "/CN=$IDENTITY/O=macctl/" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"
  chmod 600 "$KEY"
  P12PASS=$(/usr/bin/openssl rand -hex 24)
  /usr/bin/openssl pkcs12 -export -inkey "$KEY" -in "$CERT" -out "$P12" -passout "pass:$P12PASS" -name "$IDENTITY"
  /usr/bin/security import "$P12" -k "$KC" -P "$P12PASS" -T /usr/bin/codesign -T /usr/bin/security
  /usr/bin/security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PASS" "$KC" >/dev/null
  /bin/rm -f "$P12" "$KEY"
fi
/usr/bin/security find-identity -v -p codesigning "$KC"
printf 'KEYCHAIN=%s\nIDENTITY=%s\n' "$KC" "$IDENTITY"
