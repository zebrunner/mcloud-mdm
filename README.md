# Zebrunner MCloud MDM

The MDM service of [MCloud](https://github.com/zebrunner/mcloud) next to [NanoHUB](https://github.com/micromdm/nanohub) (the Apple MDM server, its API and the webhook): the device identities by SCEP with a one-time challenge per enrollment profile, the enrollment profiles of the agents of the device hosts, and the admin UI of the MDM commands, the ready profiles and the DDM declarations. One Go program, the image is `linux/amd64` and `linux/arm64` on Alpine.

```text
 iPhone ---- https /mdm, /checkin -----------> proxy of MCloud --> NanoHUB (MySQL) --> APNs
   |   \---- https /scep (one-time challenge) -> proxy of MCloud --> mcloud-mdm :8080
   | USB                                                                 |  ^ webhook
 agent of the device host -- GET /mdm/enroll (token) --> proxy ------->  |  |
                                                     admin UI :8081 <----+--+ (MCloud authentication)
```

- The device listener (`:8080`) is published by the proxy of MCloud: `/scep`, `/mdm/enroll` and `/healthz`.
- The admin listener (`:8081`) takes only the requests with `MDM_ADMIN_TOKEN` (`Authorization: Bearer <token>`, or the token as the password of Basic: a browser asks for it) and is never published without the authentication of MCloud: it sends any MDM command to any device. NanoHUB posts its webhook there, with the token in the userinfo of its webhook URL.
- An enrollment needs the device on USB once (supervision, then the profile installed with no prompt by the agent: go-ios and the supervision identity); every command afterwards goes over the network and APNs. Apple Business (ADE) is the other way in: the enrollment profile URL is the same.
- Android: [Headwind MDM](https://github.com/h-mdm/hmdm-server) is the server and the agent of `android/agent` the device owner, set over adb with no factory reset; mcloud-mdm drives Headwind MDM by its API ([Android](#android)).

## Image contents

| Component | Version |
| --- | --- |
| Go | 1.27.3 (build stage), the module needs 1.26 |
| [smallstep/scep](https://github.com/smallstep/scep) | the SCEP protocol (RFC 8894) |
| [howett.net/plist](https://github.com/DHowett/go-plist) | 1.0.1, the profiles and the commands |
| Alpine | 3.24.3 |

## Build

```bash
make build VERSION=0.1
```

The images are `public.ecr.aws/zebrunner/mcloud-mdm`: CI publishes every merge into `develop` as `<VERSION>-develop-<sha>` and `<VERSION>-develop-latest` (the newest one), a release is tagged `<VERSION>` by hand (`make push VERSION=<VERSION>`).

## Run

NanoHUB trusts the SCEP CA of mcloud-mdm (`-ca` of the shared data volume) and posts its webhook to the admin listener:

```yaml
services:
  mdm:
    image: public.ecr.aws/zebrunner/mcloud-mdm:0.1-develop-latest
    environment:
      MDM_PUBLIC_URL: https://mcloud.example.com
      NANOHUB_URL: http://mdm-nanohub:9004
      NANOHUB_API_KEY: ${NANOHUB_API_KEY}
      MDM_ENROLL_TOKEN: ${MDM_ENROLL_TOKEN}
      MDM_ADMIN_TOKEN: ${MDM_ADMIN_TOKEN}
    volumes:
      - mdm-data:/data
  mdm-nanohub:
    image: ghcr.io/micromdm/nanohub:0.2.0
    environment:
      NANOHUB_API_KEY: ${NANOHUB_API_KEY}
      NANOHUB_CA: /mdm-data/scep/ca.pem
      NANOHUB_STORAGE: mysql
      NANOHUB_STORAGE_DSN: nanohub:${MYSQL_PASSWORD}@tcp(mdm-mysql:3306)/nanohub?parseTime=true
      NANOHUB_WEBHOOK_URL: http://admin:${MDM_ADMIN_TOKEN}@mdm:8081/webhook
    volumes:
      - mdm-data:/mdm-data:ro
volumes:
  mdm-data:
```

The proxy publishes `/mdm` and `/checkin` of NanoHUB and `/scep`, `/mdm/enroll` of mcloud-mdm on the address of `MDM_PUBLIC_URL`; the admin UI behind the authentication of MCloud. The SCEP CA is created at the first start (`/data/scep/ca.pem`, `ca.key`); start NanoHUB after it.

Then, in the admin UI: upload the APNs push certificate and its key (the tab Push certificate), and the agents can enroll the devices.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `MDM_PUBLIC_URL` | | the https URL the devices and the agents reach: the MDM server is `<MDM_PUBLIC_URL>/mdm`, the enrollment profile `<MDM_PUBLIC_URL>/mdm/enroll`; required |
| `MDM_SCEP_URL` | `<MDM_PUBLIC_URL>/scep` | the SCEP URL of the enrollment profile, e.g. plain http of a lab with a self-signed certificate |
| `MDM_DEVICE_LISTEN` | `:8080` | the device listener: `/scep`, `/mdm/enroll`, `/healthz` |
| `MDM_ADMIN_LISTEN` | `:8081` | the admin UI, its API (`/api/...`) and the webhook of NanoHUB (`/webhook`) |
| `MDM_DATA_DIR` | `/data` | the SCEP CA (`scep/`) and the state of the UI (`state.json`, mode 600: it has the unlock tokens of the devices) |
| `NANOHUB_URL` | `http://mdm-nanohub:9004` | the API of NanoHUB |
| `NANOHUB_API_KEY` | | the API key of NanoHUB; required |
| `MDM_ENROLL_TOKEN` | | the secret of 16+ characters of `GET /mdm/enroll` (`Authorization: Bearer`); required |
| `MDM_ADMIN_TOKEN` | | the secret of 32+ characters of every request of the admin listener (`Authorization: Bearer <token>`, or the password of Basic with any user); `401` with a Basic challenge without it; required |
| `MDM_PROFILE_ID` | `com.zebrunner.mcloud.mdm` | the PayloadIdentifier of the enrollment profile |
| `MDM_ORG_NAME` | `Zebrunner MCloud` | the organization of the profiles and of the SCEP CA |
| `MDM_TLS_CA_FILE` | | the PEM CA of a self-signed MDM server: the enrollment profile installs it and pins the MDM connection to it |
| `MDM_CHALLENGE_TTL` | `10m` | the life of the one-time SCEP challenge of an enrollment profile |
| `MDM_CERT_DAYS` | `365` | the validity of the device identities; the devices renew them with the same identity (RenewalReq) |
| `LOGGER_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR` |
| `HMDM_URL` | | the API of Headwind MDM, e.g. `http://mdm-hmdm:8080`; empty: no Android |
| `HMDM_LOGIN` | `admin` | the user of Headwind MDM |
| `HMDM_PASSWORD` | | its password (`android/hmdm-init.sh` sets it); required with `HMDM_URL` |
| `HMDM_PUBLIC_URL` | `<MDM_PUBLIC_URL>/hmdm` | the URL of Headwind MDM the agents reach (one path segment at most: the agent sends it as its server project), https (plain http: a lab only, logged) |
| `HMDM_SHARED_SECRET` | | the `SHARED_SECRET` of Headwind MDM (the MQTT password of the agents), 16+ characters without colons or spaces; required with `HMDM_URL` |
| `HMDM_MQTT_PORT` | `31443` for an https `HMDM_PUBLIC_URL`, `31000` otherwise | the MQTT port of the agents on the host of `HMDM_PUBLIC_URL` (TLS when it is https) |
| `HMDM_TLS_CA_FILE` | | the PEM CA of a private certificate of `HMDM_PUBLIC_URL`: the setup installs it on the devices (a lab) |
| `MDM_ANDROID_AGENT_APK` | `/android/mcloud-mdm-agent.apk` | the agent (`make agent`) served at `/android/agent.apk` |
| `MDM_STF_URL` | | the API of STF (MCloud, `http://stf-api:3000`): the names, nodes and locations of the devices (the groups of the admin UI), whether a user has a device (the jobs on free devices only); empty: none of them |
| `MDM_STF_TOKEN` | | an access token of STF (Settings, Keys) for `MDM_STF_URL`, read only |
| `MDM_ENFORCE_NODE_BINDING` | `false` | `true`: a node acts on the MDM of its own devices only ([Node binding](#node-binding)); needs `MDM_STF_URL` and `MDM_STF_TOKEN` |

## Enrollment

`GET /mdm/enroll?udid=<udid>` with `Authorization: Bearer <MDM_ENROLL_TOKEN>` returns an enrollment profile (`application/x-apple-aspen-config`) with a new one-time SCEP challenge: it signs one device identity within `MDM_CHALLENGE_TTL`, a leaked profile is useless afterwards. The agent of the device host installs it over USB with no prompt on a supervised device:

```bash
curl -fsS -H "Authorization: Bearer $MDM_ENROLL_TOKEN" "https://mcloud.example.com/mdm/enroll?udid=$UDID" -o enroll.mobileconfig
P12_PASSWORD=... ios profile add enroll.mobileconfig --p12file=supervision.p12 --udid=$UDID
```

- The user can always remove the MDM profile: iOS refuses an MDM payload in a profile that cannot be removed unless it comes from ADE (checked on iOS 18.7.11). The removal is the `CheckOut` event; the agent enrolls the device again.
- The removal of the MDM profile removes every profile MDM installed; the DDM declarations come back with the next enrollment (mcloud-mdm notifies DDM after it).
- Developer Mode, the supervision and the recovery of a device that lost MDM need USB: no MDM command or key exists for them.

## Android

Headwind MDM (`headwindmdm/hmdm`, amd64 only, with PostgreSQL) is the server of the Android agents: their configurations, the MQTT push and the device info. It serves plain http and MQTT inside; the proxy terminates TLS (`proxy.conf`): https under `/hmdm` of the domain of the farm (`HMDM_PUBLIC_URL`, the proxy strips the prefix) and MQTT over TLS on the same host (`HMDM_MQTT_PORT`, 31443 -> 31000). No DNS name or certificate of its own.

- `android/hmdm-entrypoint.sh` (the entrypoint of `hmdm`) writes the context of the web application at every start: `base.url` is `HMDM_PUBLIC_URL`, `secure.enrollment=1` (the agents sign their requests with `SHARED_SECRET`: nobody else enrolls or reads a configuration, checked: an unsigned request is refused).
- `android/hmdm-init.sh` (a one-shot service on the `postgres` image) sets `HMDM_PASSWORD` (Headwind MDM asks for a new password at its first start) and points the URLs of the files of the applications to `HMDM_PUBLIC_URL`; with `HMDM_INTERNAL_URL` it waits for the web application first (the init.sql of the first start would bring the reset back) and applies it again for a minute.
- The web panel and the API of the admins are never published: mcloud-mdm reaches them inside, the panel is for `ssh -L` only. Tomcat logs "Error creating SSLContext" of its unused 8443 connector: harmless.

```yaml
  hmdm:
    image: headwindmdm/hmdm:0.1.9
    entrypoint: ["/bin/sh", "/hmdm-entrypoint.sh"]
    environment:
      SQL_HOST: hmdm-postgres
      SQL_USER: hmdm
      SQL_BASE: hmdm
      SQL_PASS: ${HMDM_SQL_PASS}
      PROTOCOL: http
      BASE_DOMAIN: demo.zebrunner.farm
      HMDM_PUBLIC_URL: https://demo.zebrunner.farm/hmdm
      SHARED_SECRET: ${HMDM_SHARED_SECRET}
      HMDM_URL: https://h-mdm.com/files/hmdm-5.41.1-os.war
      CLIENT_VERSION: "6.40"
    volumes:
      - ./android/hmdm-entrypoint.sh:/hmdm-entrypoint.sh:ro
  hmdm-init:
    image: postgres:16-alpine
    entrypoint: ["/bin/sh", "/hmdm-init.sh"]
    environment:
      PGHOST: hmdm-postgres
      PGUSER: hmdm
      PGPASSWORD: ${HMDM_SQL_PASS}
      PGDATABASE: hmdm
      HMDM_PASSWORD: ${HMDM_PASSWORD}
      HMDM_PUBLIC_URL: https://demo.zebrunner.farm/hmdm
      HMDM_INTERNAL_URL: http://hmdm:8080
    volumes:
      - ./android/hmdm-init.sh:/hmdm-init.sh:ro
    restart: "no"
```

The agent is the launcher of Headwind MDM ([hmdm-android](https://github.com/h-mdm/hmdm-android), Apache-2.0) with `android/agent/hmdm-android.patch`:

- the setup over adb, without the screen: `content call --uri content://com.hmdm.launcher.mcloud --method setup --arg <server> --extra deviceId:s:<serial> --extra secret:s:<secret> --extra token:s:<secret> [--extra pin:s:<pin>[,<pin>]]`; only the uid of adb shell (or root) may call it. Android 9+ also takes the same parameters as JSON on the stdin of `content write --uri content://com.hmdm.launcher.mcloud/setup` (then `content call ... --method setup` without arguments, within 60 seconds): the secret is in no command line of the device, see [TLS and setup of the agent](#tls-and-setup-of-the-agent).
- the shared secret of the server comes with the setup: one APK for every farm. It is the token of the agent too: once set, `setup` and `release` need it. Every user of adb is the shell uid, the remote debug of MCloud too: without the secret nobody moves the device to another server or releases it.
- the release: the push `mcloudRelease` (the admin UI) or `--method release --extra token:s:<secret>` over adb (`android/release.sh`); the agent removes its device owner (the reset password token first, Android 12 fails otherwise).
- no `android:testOnly`, no backup: adb cannot remove the device owner (`dpm remove-active-admin`: "non-test admin"), uninstall the agent (`DELETE_FAILED_DEVICE_POLICY_MANAGER`), clear its data or disable it (checked on Android 12). Android keeps the test-only flag of the moment the device owner was set: `android/enroll.sh` sets the device owner of a test-only admin again.
- no permission dialog of the agent; a crash on the first start without a configuration fixed.
- no component for the other apps of the device (an app under test): the plugin API of Headwind MDM (`PluginApiService`, its `sendPush` ran any push with the public key `LIBRARY_API_KEY`) and the stub `CheckForegroundApplicationService` are not exported, the end of an installation (`INSTALL_COMPLETE`) reaches the agent only (a signature permission, `RECEIVER_NOT_EXPORTED`), the SIM receiver ignores a broadcast without its extras (it crashed the agent). Exported still: the launcher activity (`HOME`), the setup provider (adb shell and root only), the receivers of the boot, the shutdown and the SIM (a log line), and the components of the system (`BIND_DEVICE_ADMIN`, `BIND_JOB_SERVICE`, `DUMP`).

`make agent AGENT_KEYSTORE=<keystore> AGENT_KEYSTORE_PASSWORD=<password>` builds and signs `bin/mcloud-mdm-agent.apk` in Docker (linux/amd64). Keep the key: Android updates a device owner app signed with the same key only.

### TLS and setup of the agent

The agent checks the server of every connection (the API, the files, MQTT over TLS) itself:

- with the pin of the setup (`pin`: base64 of the SHA-256 of the public key of the certificate of the server, like `MCLOUD_TLS_PIN` of the nodes; several comma separated, 4 at most, for a planned key change): a certificate with a pinned key is the server whatever its CA, name or dates (a self-signed certificate of the proxy is fine); the host of the server accepts no other key, even from a public CA. A new key of the proxy cuts the pinned agents off until their next setup (`./zebrunner.sh mdm enroll` of mcloud-agent): send the old and the new pin before the change.
- without a pin (an older server): the CAs of the system and the CA of the setup (`ca`, `HMDM_TLS_CA_FILE`), never a user CA of the device (Settings > Security: any user of the device may add one); the setup writes a warning into the device log.
- MQTT verifies the host name or the pin too (paho 1.2.0 ignored the answer of its host name verifier).
- every setup replaces these settings (a setup without `pin` removes the pin). The agent trusts the CA of the setup alone: it no longer installs it as a user CA of the device, and its next setup (or the release) removes the one an older agent installed; until then it trusts its saved copy.

`status` (`content call --uri content://com.hmdm.launcher.mcloud --method status`) shows `pinned`, `caTrusted` (a CA of the setup), `caInstalled` (a user CA of an older agent still on the device) and `features=pin,staged` (an older agent has no `features`). The staged parameters (`content write`, Android 9+): one JSON object of the names of the extras, `baseUrl` for `--arg`, `mqttPort` a number:

```bash
printf '%s' '{"baseUrl": "https://mcloud.example.com", "serverProject": "hmdm", "deviceId": "<serial>", "secret": "<secret>", "token": "<secret>", "mqttPort": 31443, "pin": "<pin>"}' \
  | adb -s <serial> shell content write --uri content://com.hmdm.launcher.mcloud/setup
adb -s <serial> shell content call --uri content://com.hmdm.launcher.mcloud --method setup
```

They are bound to their method (`/setup`, `/release` with `{"token": "<secret>"}`), taken by its next call within 60 seconds, and a call with arguments while they wait is refused. `content` exits 0 on an error too: a script looks for `Result: Bundle[` on its stdout. Checked on an Android 16 emulator (API 36): the API, the APK download and MQTT with the pin of a self-signed certificate; a wrong pin refused, also when a CA of the setup trusts the certificate; the staged setup and release; an agent of the previous patch with a CA of the setup updated in place keeps its server, its next setup removes the user CA.

The rollout of a new agent (version `6.40.1-mcloud`, code 15401; the same signing key, see [Signing key of the Android agent](#signing-key-of-the-android-agent)):

1. `make agent` with the key of the farms; `keytool -printcert -jarfile bin/mcloud-mdm-agent.apk` shows the certificate of the deployed agent.
2. Publish it: `configuration/mdm/android/mcloud-mdm-agent.apk` of MCloud (`MDM_ANDROID_AGENT_APK`), served at `/android/agent.apk`.
3. Update the devices: `./zebrunner.sh mdm enroll <devices>` of mcloud-agent (or `android/enroll.sh`) installs it over the old one (`adb install -r`, the device owner and the data stay) and sets it up again, with the pin when the server sends it. Headwind MDM could also install it (a new version of `com.hmdm.launcher` in its configurations: the agent compares the version code), but without a new setup the agent gets no pin.

Every device gets its own configuration `mcloud-<serial>` (a copy of `Common - Minimal`) safe for a farm: the system launcher stays (`runDefaultLauncher`), the agent never grants the permissions of the apps (`ASKALL`) and installs no app but itself, no kiosk. The enrollment on the device host (`android/enroll.sh`, the device on USB, no Google account on it: Android refuses a device owner then):

```bash
MDM_URL=https://mcloud.example.com MDM_ENROLL_TOKEN=... android/enroll.sh <serial> [name]
```

It downloads `/android/agent.apk`, takes the setup of `GET /android/enroll?serial=<serial>&format=shell` (the enrollment token; the JSON without `format` has the adb commands), installs the agent, sets the device owner, sets the agent up and starts it. Without the server of the agent, `android/release.sh <serial> [--uninstall]` releases the device with the command of `GET /android/release` (the enrollment token). Lost both the server and its secret: only a factory reset removes the device owner; keep `HMDM_SHARED_SECRET` with the signing key of the agent.

| Preset | Android | Checked on a Pixel 3 XL, Android 12 |
| --- | --- | --- |
| `swupdate-postpone` | `SystemUpdatePolicy` postpone (30 days) | |
| `bluetooth-off` | Bluetooth off, `no_bluetooth` | restriction active, Bluetooth off; removed: restriction gone |
| `erase-off` | `no_factory_reset` | restriction active |
| `wifi-locked` | `no_config_wifi` | a local restriction of the user, active; removed |
| `accounts-off` | `no_modify_accounts` | |
| `users-off` | `no_add_user` | |

The agent always sets `no_safe_boot`. `no_debugging_features`, `no_install_apps` and `no_uninstall_apps` are never offered: they break adb.

The commands are push messages (MQTT); the agent writes what it did into the device log of Headwind MDM, the admin UI shows it and marks a command delivered by its "Got Push Message". Checked on a Pixel 3 XL, Android 12:

| Command | Push | Result |
| --- | --- | --- |
| Sync the configuration | `configUpdated` | the configuration and the device info |
| Reboot | `reboot` | rebooted, the agent connects again by itself |
| Run a shell command | `runCommand` | `sh -c` as the app of the agent (not the adb shell), the output (3000 characters) in the log |
| Run an app | `runApp` | the launcher activity, optional action, data, extras |
| Clear the data of an app | `clearAppData` | `clearApplicationUserData`, "cleared" in the log |
| Uninstall an app | `uninstallApp` | silent; the agent itself is refused |
| Grant the runtime permissions | `grantPermissions` | `grant`: granted and fixed by the policy; `default`: back to the user (patched: the farm configuration would only reset them) |
| Open a screen | `intent` | an activity by its action, e.g. `android.settings.WIFI_SETTINGS` |
| Send a broadcast | `broadcast` | action, package, data, extras |
| Delete a file, a directory; empty a directory | `deleteFile`, `deleteDir`, `purgeDir` | the shared storage (`/sdcard/<path>`), no `..`, never the root |
| Clear the downloads of the agent | `clearDownloadHistory` | |
| Exit the kiosk, permissive mode | `exitKiosk`, `permissiveMode` | no effect: the farm configuration has no kiosk |
| Open the admin screen of the agent | `adminPanel` | opens WITHOUT the password: whoever sees the screen can change the server and clear the restrictions |
| Release the device | `mcloudRelease` | the device owner removed |
| Any push message | any type | a JSON payload; `mcloudRelease` only by Release |

The history of the commands is kept in memory (the last 300). The agent also starts its services at every start of its process (the patch: a watchdog): `BOOT_COMPLETED` did not reach it once after a reboot on Android 12, and the system launcher of a farm device never starts it.

## Infrastructure

A stack per farm next to its MCloud (not one for all the farms: the farms of different customers stay apart, and a farm already has its domain, its certificate, its proxy and its LDAP login). Shared by the farms: the APNs push certificate (the same one in every NanoHUB, renewed once a year) and the signing key of the agent (one APK). Per farm: `MDM_ENROLL_TOKEN`, `HMDM_SHARED_SECRET`, `HMDM_PASSWORD` and the supervision identity (a device moving to another farm is supervised again). About 1.5-2 GB of RAM per farm, mostly Headwind MDM.

| Part | iOS | Android |
| --- | --- | --- |
| containers | NanoHUB + MySQL 8.4 | Headwind MDM (amd64, Tomcat) + PostgreSQL + `hmdm-init` |
| shared | mcloud-mdm (SCEP, the enrollment, the admin UI) | mcloud-mdm (the enrollment, the agent APK, the admin UI) |
| the proxy of MCloud publishes | `/mdm`, `/checkin` (NanoHUB), `/scep`, `/mdm/enroll` (mcloud-mdm) | `/android/enroll`, `/android/release`, `/android/agent.apk` (mcloud-mdm), `/hmdm/` (the agent paths of Headwind MDM), MQTT over TLS 31443 |
| from the devices | https to the domain of the farm | https to the domain of the farm, TLS to its port 31443 |
| outbound | APNs: `api.push.apple.com` 443 | none (no Google services) |
| secrets | the APNs push certificate, the supervision identity, `MDM_ENROLL_TOKEN` | the signing key of the agent, `HMDM_SHARED_SECRET` (the token and the MQTT password of the agents), `HMDM_PASSWORD` |
| on the device host | go-ios: supervision, the profile, `ios pair`, Developer Mode | adb: `android/enroll.sh`, `android/release.sh` |
| the device | supervised (`ios prepare`, it erases) once | no account, a single user; no factory reset |

`proxy.conf` is the MDM part of stf-proxy ([MCloud and mcloud-agent](#mcloud-and-mcloud-agent)): every published path and MQTT only from the fixed public addresses of the site of the farm (its devices and its nodes leave it by them); the API of NanoHUB, the device listener of mcloud-mdm and the web panel of Headwind MDM stay inside; the admin UI is an ssh tunnel by default, optionally `/mcloud/mdm/` for the admins of STF (LDAP).

## MCloud and mcloud-agent

Everything goes through the domain and the proxy of the farm: no DNS name, certificate or secret of its own for the nodes.

MCloud (zebrunner/mcloud):

- the compose profile `mdm` (as `adb-relay`): `mdm`, `mdm-nanohub`, `mdm-mysql`, `hmdm`, `hmdm-postgres`, `hmdm-init`, switched on by `MDM_ENABLED=true` of `.env`; the image tags in `TAG_*`;
- `zebrunner.sh setup` generates `mdm.env` (mode 600, not the `variables.env` of STF): `MDM_ENROLL_TOKEN`, `MDM_ADMIN_TOKEN`, `NANOHUB_API_KEY`, `MYSQL_PASSWORD`, `HMDM_SQL_PASS`, `HMDM_PASSWORD`, `HMDM_SHARED_SECRET`; `MDM_PUBLIC_URL` is `STF_URL`;
- stf-proxy: the locations of `proxy.conf` (the addresses of the site and `MDM_ENROLL_TOKEN` rendered by the setup), its stream server on 31443 with the certificate of stf-proxy (`configuration/stf-proxy/ssl`), port 31443 published; a farm whose TLS ends before stf-proxy (a load balancer) terminates 31443 there too;
- the admin UI on `127.0.0.1:${MDM_ADMIN_PORT}` (9101) of the server only, by default: an ssh tunnel (`ssh -L 9101:127.0.0.1:9101 <server>`, then `http://127.0.0.1:9101`); optionally (`MDM_ADMIN_PUBLIC=true`) `/mcloud/mdm/` behind `/_hub_auth/admin` (the admins of STF) with `Host: $http_host` (the UI compares it with the Origin of its POSTs).

The API of the nodes (the device listener, `Authorization: Bearer <MDM_ENROLL_TOKEN>` injected by stf-proxy; `format=shell` answers `key=value` lines instead of JSON):

| Request | Answer |
| --- | --- |
| `GET /mdm/enroll?udid=<udid>` | the enrollment profile of an iOS device (a one-time SCEP challenge) |
| `GET /mdm/status?udid=<udid>` | `known`, `enrolled`, `checked_out`, `enrolled_at`, `last_seen_at`, `product`, `os_version`, `serial`, `unlock_token`: the webhook, the device is not touched |
| `POST /mdm/release?udid=<udid>` | 202 `command=<uuid>`: `RemoveProfile` of the enrollment profile, the device leaves MDM with every MDM profile (it stays supervised); 409 for a device that is not enrolled |
| `GET /android/agent.apk` | the agent |
| `GET /android/enroll?serial=<serial>[&name=<name>]` | the setup of the agent (`format=shell`: its `adb shell` command) |
| `GET /android/status?serial=<serial>` | `known`, `device_owner`, `last_sync_at`, `agent_version`, `model`, `os_version`, `managed`, `presets`: Headwind MDM, the device is not touched |
| `GET /android/release[?serial=<serial>]` | the `adb shell` command of the release without the server (the serial is required with `MDM_ENFORCE_NODE_BINDING`) |

mcloud-agent (zebrunner/mcloud-agent): `./zebrunner.sh mdm <status|enroll|release|supervise> <devices>` with the `MCLOUD_URL` and the `MCLOUD_NODE_TOKEN` of `./zebrunner.sh join` (no new setting): stf-proxy checks the node token (`GET /api/v1/nodes/self` of stf-api) and calls mcloud-mdm with `MDM_ENROLL_TOKEN`. `status` asks the server only. `enroll` and `release` take the lock of the device, stop its containers (if it has any: a new device has none yet), run a one-shot container of the image of its connector (`docker run --rm --entrypoint ...` with the USB device and the volumes of the connector: `mcloud-key-volume` of adb, `<device>-lockdown` of the pairing), then start its containers again:

- Android (adb): `GET /android/agent.apk` into the connector, `GET /android/enroll?serial=<udid>&name=<name>&format=shell` (the `adb shell` command of the setup), `adb install -r`, `dpm set-device-owner com.hmdm.launcher/.AdminReceiver`, the setup, `am start`; the release: `GET /android/release` (its `adb shell` command). `android/enroll.sh` and `android/release.sh` are the reference.
- iOS (go-ios, `/var/lib/lockdown` of the connector): `GET /mdm/enroll?udid=<udid>&name=<name>` (a profile with a one-time challenge), `ios profile add --p12file=<supervision identity>`; `ios pair --p12file` after a lost pairing. `supervise`: `ios erase`, `ios activate`, `ios prepare` with the certificate of the identity and every skip key, `ios devmode enable`, the Wi-Fi profile of the farm, then the enrollment; WebDriverAgent of the connector continues the Setup Assistant of iOS 26.
- later: the udev and systemd hook of a connected device enrolls a device that is not enrolled.

### Node binding

Every node has the same `MDM_ENROLL_TOKEN` behind stf-proxy: without more, a node could ask the MDM about any device of
the farm, release it, enroll another udid or take the release command of the Android agents (with `HMDM_SHARED_SECRET`).
With `MDM_ENFORCE_NODE_BINDING=true` (off by default: every node acts on every device, as before):

- stf-proxy passes the label of the node of the token in `X-MCloud-Node` (stf-api answers it to the `auth_request`,
  `proxy.conf`; the header of the client is overwritten);
- every node call names its device (`udid` or `serial`, also `GET /android/release` and `GET /mdm/enroll` then) and
  mcloud-mdm asks STF (`GET /api/v1/devices/<serial>`, `MDM_STF_TOKEN`: an admin who sees every device) for its
  `node`: another node, a device STF does not know or no node: `403 forbidden`, logged with the node and the device;
  STF does not answer: `503`, nothing done;
- no `X-MCloud-Node` (an stf or an mcloud without it): every node call is refused (`403`), logged as an error to update
  them; fail closed;
- the SCEP challenge of an enrollment profile is bound to its udid: it signs only a CSR whose subject is the one of that
  device (`mcloud-mdm-<udid>-...`).

Not covered (follow-ups): `HMDM_SHARED_SECRET` is one for the farm and stays in the setup and the release commands
of the agents (their protocol needs it), now only for the node of the device; NanoHUB does not give the identity of a
device to the webhook, so the udid of an `Authenticate` is not compared with the subject of its identity.

## Keys and certificates

| Key | Made | Valid | Where | Lost | Leaked |
| --- | --- | --- | --- | --- | --- |
| The APNs push certificate and its key | once for all the farms, by Apple | 1 year, renewed | NanoHUB (the admin UI uploads it) | every iOS device enrolls again | it wakes the devices up, no command: the commands come from NanoHUB only |
| The supervision identity | once per farm (or per customer) | 10 years | the device hosts (`MDM_SUPERVISION_P12` of mcloud-agent) | no silent pairing and no profile over USB: every iOS device is erased to be supervised again | with USB access to a device: a silent pairing, any profile |
| The signing key of the Android agent | once for all the farms | 27 years | the build machine only, at `make agent` | no update of the agent: every Android device is reset to factory settings | a modified agent installed over adb as an update of the device owner |
| The SCEP CA | by mcloud-mdm, at its first start | 10 years | `/data/scep` of mcloud-mdm (the volume `mcloud-mdm-data`) | every iOS device enrolls again | device identities of the MDM for anybody |
| `mdm.env` of MCloud | by `./zebrunner.sh setup` | - | the server of MCloud | Android: the device owner goes with a factory reset only (`HMDM_SHARED_SECRET`) | the API of NanoHUB, the release of the Android agents over adb |

Keep every one of them in the store of the secrets (two copies at least): none can be made again with the same effect.

### APNs push certificate

Apple issues it to an Apple ID for a push CSR signed by an MDM vendor. Use an Apple ID of the company, not a personal one: only the same Apple ID renews it.

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout push.key -out push.csr -subj "/CN=MCloud MDM push/O=<company>/C=<country>"
chmod 600 push.key
```

1. The vendor signature of `push.csr`, one of:
   - [mdmcert.download](https://mdmcert.download): a free signing service (a third party; its terms of use apply): upload `push.csr`, get the signed request;
   - an own MDM vendor certificate (`MDM CSR` of Apple Developer, an organization, granted by Apple on request) and `mdmutil mdmcsr-sign -apns-csr push.csr -mdmcsr-private-key <vendor key> -mdmcsr-certificate <mdm.cer> ...`.
2. [identity.apple.com/pushcert](https://identity.apple.com/pushcert) with the Apple ID: Create a Certificate, upload the signed request, download the certificate (`MDM_..._Certificate.pem`).
3. The admin UI, the tab Push certificate: the certificate and `push.key` (or `POST /api/pushcert` of the admin UI with `{"pem": "<certificate><key>"}`). Not straight into NanoHUB: mcloud-mdm keeps the topic of the certificate, without it `/mdm/enroll` answers 503.

The renewal, every year before `openssl x509 -in <certificate> -noout -enddate`: a new signed request (step 1), Renew of the same certificate at identity.apple.com (Renew keeps its topic; Create gives a new topic and every iOS device enrolls again), the admin UI. The key may stay.

### Supervision identity

```bash
ios prepare create-cert    # go-ios: supervision-cert.pem, supervision-cert.der, supervision-private-key.pem, ... here
openssl rand -base64 24    # the password of the PKCS#12 file
openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -inkey supervision-private-key.pem -in supervision-cert.pem -out supervision.p12 -name "<farm> supervision"
chmod 600 supervision.p12 supervision-private-key.*
```

3DES: go-ios reads it (checked with OpenSSL 3 and LibreSSL of macOS). The supervision of a device (it erases the device): `ios prepare --certfile=supervision-cert.der --orgname=<organization> --skip-all`. The device hosts get `supervision.p12` and its password (`MDM_SUPERVISION_P12`, `MDM_SUPERVISION_P12_PASSWORD` of mcloud-agent), readable for their user only; a device supervised with another identity needs an erase.

### Signing key of the Android agent

```bash
keytool -genkeypair -keystore agent.jks -storetype PKCS12 -alias mcloud -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=MCloud MDM agent, O=<company>"
chmod 600 agent.jks
AGENT_KEYSTORE_PASSWORD=... make agent AGENT_KEYSTORE=agent.jks
```

One key and one APK for all the farms. Android updates a device owner app signed with the same key only: `keytool -printcert -jarfile bin/mcloud-mdm-agent.apk` shows the certificate of an APK; compare it before a deployment.

### Generated by MCloud

`mdm.env` (`./zebrunner.sh backup` copies it) and the SCEP CA:

```bash
docker cp mcloud-mdm:/data ./mcloud-mdm-data    # scep/ca.key, scep/ca.pem, state.json
```

## Deployment of a farm

Once for all the farms: the image of mcloud-mdm, the signing key of the agent and the agent APK (`make agent`), the APNs push certificate (renewed once a year with the same Apple ID), see [Keys and certificates](#keys-and-certificates).

Per farm (a test farm first):

1. The public addresses of the site: `curl ifconfig.me` from a node and from a device on the Wi-Fi of the farm. A device in the network of the server of MCloud may reach it by its private address: add that network too, and check the NAT loopback to the public address.
2. Port 31443/tcp of the server of MCloud open for the addresses of the site (a firewall, a security group of AWS); 443 is open already.
3. `MDM_ENABLED=true`, the addresses of the site, `./zebrunner.sh setup` (it generates `mdm.env`); keep `mdm.env` in the store of the secrets too: without `HMDM_SHARED_SECRET` and the server the device owner goes with a factory reset only.
4. `./zebrunner.sh start`; the checks: from another address `/mdm`, `/hmdm/...` and 31443 refuse; from the site `/android/agent.apk` answers, `openssl s_client -connect <farm>:31443` verifies; `/hmdm/` (the web panel) answers 404; the admin UI answers through the ssh tunnel (`/mcloud/mdm/` asks for the sign-in of STF when it is published).
5. The admin UI, iOS: the push certificate.
6. The supervision identity of the farm on its nodes ([Supervision identity](#supervision-identity)).
7. Android: the accounts (Google) off the devices, `./zebrunner.sh mdm enroll <devices>` of mcloud-agent; the admin UI shows the device owner and a fresh sync.
8. iOS: `./zebrunner.sh mdm supervise <devices>` of mcloud-agent erases, supervises and enrolls the devices (a window agreed with the users; `MDM_WIFI_SSID` of the hosts).
9. The presets (the delay of the updates, no factory reset, ...).
10. The backups: the volumes of MySQL, PostgreSQL and `/data` of mcloud-mdm (its SCEP CA: without it every iOS device enrolls again).

## Admin UI

Three tabs: iOS, Android and Server (`#ios`, `#android`, `#server` in the URL).

- iOS and Android: the devices with their model, node and location (STF), state, user (STF: free, in use, disconnected), set and the settings on; a filter, the node and the location (S1 selects S1_A1, S1_B2, ...), All, None, Invert, Problems (not managed, left MDM, waiting for sync), Free, Differ from their set. The checked devices are the targets of every action, a click on a device shows its details (Android: its log).
  - Settings: every preset On, Off or "-" (left as it is), with the counts of the selected devices; Apply runs the chosen ones on the selected devices.
  - Commands: every MDM command of iOS of Apple (a hint: what it does, what it needs, its result on a supervised iPhone XR with iOS 18.7.11; `{"$data": "<base64>"}` is data, filled from a file) and every push command of the Android agent; Send runs it on the selected devices, Add to the set puts it into Settings; iOS: Push (wake up).
  - Saved sets: the settings and the commands of Settings saved under a name per platform (kept in `state.json`; a password is never stored: the UI asks for it, a job without it fails that action). Apply runs a set on the selected devices; Assign makes it the set of the selected devices: the table shows the devices whose settings differ from their set, Fix applies the settings of the set to them. The default set of a platform is assigned and applied to every new device (iOS: a new enrollment; Android: a device new to Headwind MDM); a device enrolled again gets its own set.
  - Jobs: every Apply and Send is a job (`POST /api/jobs`, `GET /api/jobs`, `POST /api/jobs/cancel`): the devices in parallel (8 at a time), the actions of a device one by one, a failed action does not stop the next ones; ok, queued (iOS: the device takes the command when it connects), error, skipped, cancelled; the report of every iOS command. Options: a start time, free devices only (each device waits until nobody uses it in STF, checked every 30 s) and the end of the window (the devices still busy then are skipped). In memory, the last 50: a restart of mcloud-mdm drops the jobs that did not finish.
  - The commands sent with their reports (iOS; `Cleared`: never delivered, NanoMDM clears the queue of a device that enrolls again) or their delivery (Android), the check-in events (iOS) or the device log (Android).
- Server: the upload of the APNs push certificate and its key, the console of the API of NanoHUB with the DDM declarations (configurations, activations, sets, status) and NanoCMD, the manual enrollment of an Android serial.
- The names of the devices come from their hosts (`/mdm/enroll?udid=<udid>&name=<name>`, Android: the enrollment), else from STF; the iPhones show their marketing names; the unlock token of `ClearPasscode` is kept and never shown.

## Ready profiles

| Preset | Payload | Checked on iOS 18.7.11 |
| --- | --- | --- |
| `swupdate-delay` | `forceDelayedSoftwareUpdates`, `enforcedSoftwareUpdateDelay: 90` | iOS 18.7.12 hidden (the DDM deferral did not hide it) |
| `bluetooth-off` | `Settings` Bluetooth off, then `allowBluetoothModification: false` | restriction active |
| `airdrop-off` | `allowAirDrop: false` | restriction active |
| `erase-off` | `allowEraseContentAndSettings: false`, `allowUIConfigurationProfileInstallation: false` | |
| `wifi-allowed-only` | `com.apple.wifi.managed` + `forceWiFiToAllowedNetworksOnly`, `forceWiFiPowerOn` | the SSID and the password are typed in the UI, not stored |

## Limitations

- The file storage of NanoHUB loses the head of a command queue when a command is enqueued while the device acknowledges the last one (no lock in the kv queue of NanoMDM): use MySQL.
- `UserList`, `LogOutUser`, `DeleteUser`, `UserConfigured` are Shared iPad only, the enhanced log collection iOS 27+.
- The deferral of `com.apple.configuration.softwareupdate.settings` did not hide an 8 day old update on iOS 18.7.11; the restriction profile does, until iOS 26.

## Exit codes and health

- `0`: an invalid configuration, every invalid variable is logged (a restart does not fix it).
- `1`: a listener failed or the data directory is not writable.
- The healthcheck is the program: `mcloud-mdm -healthcheck` asks `/healthz` of the device listener.

## Development

| Target | What it checks |
| --- | --- |
| `make lint` | `tests/lint.sh`: the shared linters, gofmt, go vet, go mod tidy |
| `make test` | `go test -race ./...`: SCEP (one-time challenges, renewal), the profiles, the state, the admin API, the webhook and Android (a fake Headwind MDM) |
| `make docker` | `tests/image_test.sh`: the image, its configuration, exit codes, startup, both listeners and the CA kept in the volume |
| `make agent` | builds the Android agent (not part of `make check`) |
| `make check` | all of them |

The conventions of the repository are in [CONVENTIONS.md](CONVENTIONS.md).

## Support

[Zebrunner](https://zebrunner.com/) - open an issue in this repository.

## License

[Apache License 2.0](LICENSE)
