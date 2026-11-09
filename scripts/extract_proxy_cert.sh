#!/usr/bin/env bash
# Extracts the mTLS client cert from YOUR OWN installed copy of JioHomeJFE.apk
# and splits it into cert.pem / key.pem for use with curl.
#
# Usage: ./extract_proxy_cert.sh /path/to/JioHomeJFE.apk
#
# We do NOT redistribute proxy.p12 itself - it's pulled fresh from your own
# APK each time, since it's bundled inside the app you installed.

set -e

APK="$1"
if [ -z "$APK" ]; then
    echo "Usage: $0 /path/to/JioHomeJFE.apk"
    exit 1
fi

PKCS12_PASSWORD='Shyam2.Maheshwari080525#$'

echo "[*] Extracting proxy.p12 from $APK ..."
unzip -p "$APK" assets/proxy.p12 > proxy.p12

echo "[*] Splitting into client-cert.pem / client-key.pem ..."
openssl pkcs12 -in proxy.p12 -clcerts -nokeys -out client-cert.pem \
    -passin "pass:${PKCS12_PASSWORD}"
openssl pkcs12 -in proxy.p12 -nocerts -nodes -out client-key.pem \
    -passin "pass:${PKCS12_PASSWORD}"

echo "[+] Done: proxy.p12, client-cert.pem, client-key.pem"
echo "    Use with curl: --cert client-cert.pem --key client-key.pem"
