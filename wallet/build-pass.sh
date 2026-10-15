#!/bin/bash
set -euo pipefail
PASS_DIR="${1:-.}"
P12="${2:-Sayed-Wallet.p12}"
OUTPUT="${3:-Sayed-AlMosawi.pkpass}"
if [ ! -f "$P12" ]; then echo "Missing $P12"; exit 1; fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
openssl pkcs12 -in "$P12" -clcerts -nokeys -out "$TMP/signerCert.pem"
openssl pkcs12 -in "$P12" -nocerts -nodes -out "$TMP/signerKey.pem"
security find-certificate -c "Apple Worldwide Developer Relations Certification Authority" -a -p | awk 'BEGIN{n=0}/BEGIN CERTIFICATE/{n++; f=sprintf("'"$TMP"'/wwdr-%d.pem",n)} {if(f) print > f}'
WWDR=""
for f in "$TMP"/wwdr-*.pem; do
  if openssl x509 -in "$f" -noout -subject 2>/dev/null | grep -q "OU *= *G4"; then WWDR="$f"; break; fi
done
[ -n "$WWDR" ] || { echo "Apple WWDR G4 not found"; exit 1; }
python3 - "$PASS_DIR" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); m={}
for f in sorted(p.iterdir()):
    if f.is_file() and f.name not in ("manifest.json","signature","build-pass.sh","README.md",".gitignore") and not f.name.endswith((".p12",".pfx",".key",".pem",".pkpass")):
        m[f.name]=hashlib.sha1(f.read_bytes()).hexdigest()
(p/"manifest.json").write_text(json.dumps(m,separators=(",",":")),encoding="utf-8")
PY
openssl smime -binary -sign -certfile "$WWDR" -signer "$TMP/signerCert.pem" -inkey "$TMP/signerKey.pem" -in "$PASS_DIR/manifest.json" -out "$PASS_DIR/signature" -outform DER
rm -f "$OUTPUT"
(cd "$PASS_DIR"; zip -q -X "$OUTPUT" pass.json manifest.json signature icon*.png logo*.png thumbnail*.png)
echo "Created $PASS_DIR/$OUTPUT"
