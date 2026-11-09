# JODU52041 (Jio AirFiber ODU) — WebUI Unlock & Config Toolkit

Reverse-engineered from the official `JioHomeJFE` Android app, the device's own
`libxframeworks.so` (pulled from its rootfs), and the ODU's Angular WebUI
bundle (`main.js`). Tested against a **JODU52041** (Askey-built Jio AirFiber
Outdoor Unit). Other Jio AirFiber/ODU models *may* share the same backend
(same ODM, same app), but field offsets, hardcoded strings, and the
mTLS-required-firmware allowlist may differ — verify everything against your
own device before trusting it blindly.

**This only works on hardware you own.** Everything below assumes physical/
BLE/network access to your own ODU, using credentials and keys that ship
inside apps and firmware you already legitimately possess. It does not grant
access to anyone else's device.

**No warranty.** Writing to `/userdb/data/cfg/*.cfg` touches live device
config. Back up every file before you overwrite it (every script and every
step below does this automatically where possible — don't skip it).

---

## What's actually going on here

The ODU runs a local HTTPS management API (`JioODU`, an Angular SPA) on the
device. Normally it's reachable two ways:

1. **Wi-Fi/LAN**, at `https://192.168.225.1/` (if you're on the ODU's own
   network) — the app's `OpenWebGui` flow auto-logs into this with
   JS-injected default creds.
2. **Bluetooth PAN tethering** — the app pairs over BLE, brings up a
   Bluetooth PAN (tethering) link, reads the ODU's PAN-assigned IP off a
   GATT characteristic, and talks to the ODU's REST API over that link
   instead. This is the path this toolkit focuses on.

Either way, the API requires **mutual TLS** (client certificate) on newer
firmware builds (port `4443` instead of `443`), plus session auth on top of
that. Below is everything needed to reproduce that full chain yourself.

---

## 1. Default WebUI / API credentials

Hardcoded in the `JioHomeJFE` APK (`OpenWebGui.java`,
`BLEConnectActivity.onStart()`):

| Username | Password     | Where it's used                              |
|----------|--------------|-----------------------------------------------|
| `Admin`  | `Jiocentrum` | eSIM app's own handshake login (`/cgi-bin/app/account/auth`) |
| `admin`  | `P@ssw0rd`   | Fallback retry if the above fails (ONT/IDU WebView flow) |

These are also the seed values the app writes into its own preferences the
first time it pairs with a device — i.e. they're genuinely the device's
factory-default admin credentials, not something only the app knows.

## 2. mTLS client certificate (needed for port `4443`)

Some firmware builds require a client certificate for the REST API (see
`scripts/patch_engtool.py`'s header comment for which firmware this applies
to — found via the `JODU52540_REL_*` allowlist in the app's
`RetrofitClient` class). If a plain login gets `308 redirect to :4443` and
then the TLS handshake fails without a client cert, you need this.

The cert/key live inside the `JioHomeJFE.apk` itself at `assets/proxy.p12`.
**We don't redistribute the cert file** — it's pulled fresh from your own
installed copy of the app:

```bash
./scripts/extract_proxy_cert.sh /path/to/JioHomeJFE.apk
```

This produces `proxy.p12`, `client-cert.pem`, `client-key.pem` in the current
directory. The PKCS12 password (also hardcoded/obfuscated in the APK, already
decoded for you) is `Shyam2.Maheshwari080525#$`.

## 3. Logging in over the REST API

```bash
IP=10.169.218.220   # your ODU's current IP (LAN or BT-PAN)

curl -k -i -X POST "https://${IP}:4443/auth.fcgi" \
  -H "Cookie: Secure; LANGUAGE=1; expert=true" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
  --cert client-cert.pem --key client-key.pem \
  --data-binary '{"AuthCmd":"Login","UserPW":"Jiocentrum","UserName":"Admin"}'
```

**Important quirk, found empirically, not by design:** sending the
`Cookie: Secure; LANGUAGE=1; expert=true` header on the *initial* login
request causes `/auth.fcgi` to return `Status: OK` with a real session token
in `Result[0].Login` — this was observed to succeed even with an incorrect
password. We don't have a root-cause explanation beyond "the presence of
those baseline cookies appears to change how the endpoint validates the
request" — treat it as an unexplained firmware auth-logic quirk, not a
documented feature, and test on your own device before relying on it.
Whatever is returned in `Result[0].Login` is the real session token — use it
as the `UID=` cookie on every subsequent request:

```bash
UID="<value from Result[0].Login above>"

curl -k "https://${IP}:4443/restful/sysadm/serial_number" \
  -H "Cookie: Secure; LANGUAGE=1; expert=true; UID=${UID}; FIRST_LOGIN_FLAG=0; privilege=0; login_block=false" \
  --cert client-cert.pem --key client-key.pem
```

## 4. Enabling the WebUI itself

There's a real toggle for this in the app (`EsimDetailsActivity`'s "Web Gui
Status" switch), but it's conditionally shown — easiest to just call the API
directly:

```bash
curl -k -X POST "https://${IP}:4443/cgi-bin/app/esim/enable_gui" \
  -H "Content-Type: application/json" \
  -H "Cookie: QSESSIONID=<session from /cgi-bin/app/account/auth login>" \
  --cert client-cert.pem --key client-key.pem \
  -d '{"enable_gui":true}'
```

(Note this uses the *other* session type, from `/cgi-bin/app/account/auth`,
not the `/auth.fcgi` one above — they're separate auth scopes in this
firmware, confirmed by the returned session cookie being `Path`-scoped
differently.) Then just visit `https://<ip>:4443/` with the client cert
loaded (import the `.p12` as a client cert on whatever device/browser you're
using) — it serves the real Angular WebUI (`JioODU`).

## 5. Reading/writing the device's config files

The ODU's persistent config (`/userdb/data/cfg/*.cfg` and the mirrored
`/userdb/data/cfg2/*.cfg`) uses a custom encrypted format:

```
offset 0:  20 bytes   magic "*IMQ0.0.0.A" + padding
offset 20: uint32 LE  checksum = sum of all plaintext bytes, mod 2^32
offset 24: uint32 LE  record count
offset 28: uint32 LE  ciphertext length
offset 32: ...        AES-128-CBC ciphertext
```

- **AES key:** `+Askey Computer+` (16 bytes, literal ASCII)
- **AES IV:** `TS87` + bytes `0x04..0x0F` (16 bytes)

Both extracted from `ServiceConfig::EncryptedAesData` /
`ServiceConfig::DecryptedAesData` in the device's own
`usr/lib/libxframeworks.so.0.0.0` (found via ARM disassembly of the
PC-relative literal pool — see the key-extraction commit history in this
repo's issue/commit log if you want the exact disassembly).

Once decrypted, the plaintext is a table of records:

```
offset 0:  u16 LE   record index
offset 2:  u16 LE   type tag 0x9856 (marks a valid record; anything else = end of table)
offset 4:  40 bytes  NUL-padded ASCII name (RECID_...)
offset 44..71:       reserved/padding
offset 72: u32 LE   "type" field
offset 76: 4 bytes  value (ASCII string if type==2, else little-endian integer)
```

**Record size isn't fixed at 80 bytes** — confirmed universal rule:

```
record_total_bytes = 80 + max(0, type_value - 4)
```

A `type` of `1`/`4`/`8` is a plain scalar (record is just 80 bytes). Larger
`type` values mean the record has an extra `type - 4` bytes of payload
appended right after (a longer string, an array, etc.) — this is how e.g.
`RECID_FOTA_REMOTE_URL` (`type=516`) reserves a 512-byte string buffer.

### Scripts

- **`decrypt_and_parse.py`** — decrypt + dump a raw `.cfg` file pulled
  straight off the device (handles the fixed-record-table prefix of a file;
  use `parse_cfg.py` on an already-decrypted file instead if you've split
  the steps up).
- **`patch_engtool.py`** — flips `RECID_TOOL_CFG_TELNET`,
  `RECID_TOOL_CFG_SSH`, and `RECID_CONSOLE` to `1` in `engtool.cfg`.
- **`patch_tr069.py`** — retargets the TR-069 ACS URL (e.g. to point at your
  own GenieACS instead of Jio's `acs.oss.jio.com`) in `tr069.cfg`.
- **`extract_proxy_cert.sh`** — pulls the mTLS client cert out of your own
  APK (see §2).

All patch scripts: decrypt → modify specific bytes → recompute the checksum
→ re-encrypt, preserving the exact original file length (same plaintext
length in means same AES-CBC ciphertext length out, so there's no
padding/size risk).

```bash
pip3 install pycryptodome

# pull via adb (safer than editing live on-device)
adb pull /userdb/data/cfg/engtool.cfg ./engtool.orig
adb pull /userdb/data/cfg2/engtool.cfg ./engtool2.orig

python3 scripts/patch_engtool.py engtool.orig  engtool.new
python3 scripts/patch_engtool.py engtool2.orig engtool2.new

# ALWAYS back up the on-device originals before overwriting
adb shell cp /userdb/data/cfg/engtool.cfg  /userdb/data/cfg/engtool.cfg.bak
adb shell cp /userdb/data/cfg2/engtool.cfg /userdb/data/cfg2/engtool.cfg.bak

adb push engtool.new  /userdb/data/cfg/engtool.cfg
adb push engtool2.new /userdb/data/cfg2/engtool.cfg

adb shell reboot   # no live-reload path found for engtool/tr069 - reboot required
```

After reboot:
```bash
adb shell "netstat -tlnp 2>/dev/null | grep -E ':22|:23'"
adb shell "ps | grep -iE 'telnet|ssh|dropbear'"
```
If nothing's listening, the config flag flipped fine but this firmware build
may simply not ship a telnet/sshd binary — check
`find / -iname "*telnetd*" -o -iname "*dropbear*" -o -iname "*sshd*"` on
device.

## 6. REST API map (partial)

Everything under `/restful/` follows the same pattern: JSON body like
`{"Page": "...", "RequestMethod": "GET"|"PUT"|"POST", ...}`, same session
cookie + client cert as above. Categories found in the WebUI's JS bundle:

```
CoreM        - opmode (router/bridge switch!), factory reset
DEVS         - cpu/mem usage
bluetooth    - pan_enable, pan_status
clientlist
diagnostic   - ping, traceroute, nslookup
engtool      - soc_log, tcpdump, xap_log, webui_mask (read-only)
eogre        - GRE tunnel list (on/off per tunnel, NOT a router/bridge switch)
euicc        - eSIM profile management
firewall / firewallv6
fotaClient
fwup         - firmware upgrade/version
lan / lan6
lte          - cellular info, band preference, cell lock
natfw        - port forwarding / DMZ
qcmap
sntp
speedtest
sysadm       - reboot, backup/restore, serial number, hostname
tr069
traffic
upnp
```

Router/bridge mode specifically: `PUT /restful/CoreM/opmode` with body
`{"Page":"SetOpMode","RequestMethod":"PUT","mode":"ROUTER"|"BRIDGE","bridge_type":"AUTO"|...,"mac":"..."}`.
Always `GET /restful/CoreM/opmode` first to see your firmware's exact current
field values before setting anything.

## 7. Known findings worth knowing about (not necessarily something to *do*)

- Firmware update check-in: `RECID_FOTA_REMOTE_URL` in `fotaClient.cfg`
  points at `https://avus46.askeycloudapi.com/v1/verchk/.../Model?v=<firmware
  version>&u=<your device's IMEI>` — sent in plaintext on every check.
- `DEVS.cfg` confirms this is a `user_build` (locked retail build, not
  eng/userdebug) — explains why `webui_mask` and similar flags default
  restricted.
- `engtool.cfg` also has `RECID_TOOL_CFG_MOUNT` (default SMB mount config,
  placeholder `192.168.1.100`), `RECID_LOG_CFG_MODEM`, `RECID_LOG_CFG_XAP`
  (remote diagnostic log destinations, also default to `192.168.1.100`).

---

## Credits / method

- APK decompiled with [jadx](https://github.com/skylot/jadx).
- Device rootfs cross-referenced from a community-sourced dump
  (`AMIT-ALT-MC/Rootfs` on GitHub).
- AES key/IV extracted via ARM disassembly of `libxframeworks.so` using
  `arm-linux-gnueabihf-objdump`.
- General Jio AirFiber/Fiber customization community:
  [JFC-Group](https://github.com/JFC-Group) — worth checking for broader
  tips beyond this specific toolkit.

This repo documents one person's own hardware. If you use any of this, back
up before you write anything, and don't expect official support if something
goes wrong.
