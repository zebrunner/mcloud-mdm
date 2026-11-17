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
- The admin listener (`:8081`) is never published without the authentication of MCloud: it sends any MDM command to any device. NanoHUB posts its webhook there.
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

## Run

NanoHUB trusts the SCEP CA of mcloud-mdm (`-ca` of the shared data volume) and posts its webhook to the admin listener:

```yaml
services:
  mdm:
    image: public.ecr.aws/zebrunner/mcloud-mdm:0.1
    environment:
      MDM_PUBLIC_URL: https://mcloud.example.com
      NANOHUB_URL: http://mdm-nanohub:9004
      NANOHUB_API_KEY: ${NANOHUB_API_KEY}
      MDM_ENROLL_TOKEN: ${MDM_ENROLL_TOKEN}
    volumes:
      - mdm-data:/data
  mdm-nanohub:
    image: ghcr.io/micromdm/nanohub:0.2.0
    environment:
      NANOHUB_API_KEY: ${NANOHUB_API_KEY}
      NANOHUB_CA: /mdm-data/scep/ca.pem
      NANOHUB_STORAGE: mysql
      NANOHUB_STORAGE_DSN: nanohub:${MYSQL_PASSWORD}@tcp(mdm-mysql:3306)/nanohub?parseTime=true
      NANOHUB_WEBHOOK_URL: http://mdm:8081/webhook
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
| `MDM_PROFILE_ID` | `com.zebrunner.mcloud.mdm` | the PayloadIdentifier of the enrollment profile |
| `MDM_ORG_NAME` | `Zebrunner MCloud` | the organization of the profiles and of the SCEP CA |
| `MDM_TLS_CA_FILE` | | the PEM CA of a self-signed MDM server: the enrollment profile installs it and pins the MDM connection to it |
| `MDM_CHALLENGE_TTL` | `10m` | the life of the one-time SCEP challenge of an enrollment profile |
| `MDM_CERT_DAYS` | `365` | the validity of the device identities; the devices renew them with the same identity (RenewalReq) |
| `LOGGER_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR` |
| `HMDM_URL` | | the API of Headwind MDM, e.g. `http://mdm-hmdm:8080`; empty: no Android |
| `HMDM_LOGIN` | `admin` | the user of Headwind MDM |
| `HMDM_PASSWORD` | | its password (`android/hmdm-init.sh` sets it); required with `HMDM_URL` |
| `HMDM_PUBLIC_URL` | | the http(s) URL of Headwind MDM the agents reach; required with `HMDM_URL` |
| `HMDM_SHARED_SECRET` | | the `SHARED_SECRET` of Headwind MDM (the MQTT password of the agents), 16+ characters without colons or spaces; required with `HMDM_URL` |
| `MDM_ANDROID_AGENT_APK` | `/android/mcloud-mdm-agent.apk` | the agent (`make agent`) served at `/android/agent.apk` |

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

Headwind MDM (`headwindmdm/hmdm`, amd64 only, with PostgreSQL) is the server of the Android agents: their configurations, the MQTT push (port 31000) and the device info. Its admin asks for a new password at the first start: `android/hmdm-init.sh`, a one-shot service on the `postgres` image, sets `HMDM_PASSWORD` at every start.

```yaml
  hmdm:
    image: headwindmdm/hmdm:0.1.9
    environment:
      SQL_HOST: hmdm-postgres
      SQL_USER: hmdm
      SQL_BASE: hmdm
      SQL_PASS: ${HMDM_SQL_PASS}
      PROTOCOL: https
      BASE_DOMAIN: hmdm.mcloud.example.com
      SHARED_SECRET: ${HMDM_SHARED_SECRET}
      HMDM_URL: https://h-mdm.com/files/hmdm-5.41.1-os.war
      CLIENT_VERSION: "6.40"
    ports:
      - "31000:31000"
  hmdm-init:
    image: postgres:16-alpine
    entrypoint: ["/bin/sh", "/hmdm-init.sh"]
    environment:
      PGHOST: hmdm-postgres
      PGUSER: hmdm
      PGPASSWORD: ${HMDM_SQL_PASS}
      PGDATABASE: hmdm
      HMDM_PASSWORD: ${HMDM_PASSWORD}
    volumes:
      - ./android/hmdm-init.sh:/hmdm-init.sh:ro
    restart: "no"
```

The agent is the launcher of Headwind MDM ([hmdm-android](https://github.com/h-mdm/hmdm-android), Apache-2.0) with `android/agent/hmdm-android.patch`:

- the setup over adb, without the screen: `content call --uri content://com.hmdm.launcher.mcloud --method setup --arg <server> --extra deviceId:s:<serial> --extra secret:s:<secret> --extra token:s:<secret>`; only the uid of adb shell (or root) may call it.
- the shared secret of the server comes with the setup: one APK for every farm. It is the token of the agent too: once set, `setup` and `release` need it. Every user of adb is the shell uid, the remote debug of MCloud too: without the secret nobody moves the device to another server or releases it.
- the release: the push `mcloudRelease` (the admin UI) or `--method release --extra token:s:<secret>` over adb (`android/release.sh`); the agent removes its device owner (the reset password token first, Android 12 fails otherwise).
- no `android:testOnly`, no backup: adb cannot remove the device owner (`dpm remove-active-admin`: "non-test admin"), uninstall the agent (`DELETE_FAILED_DEVICE_POLICY_MANAGER`), clear its data or disable it (checked on Android 12). Android keeps the test-only flag of the moment the device owner was set: `android/enroll.sh` sets the device owner of a test-only admin again.
- no permission dialog of the agent; a crash on the first start without a configuration fixed.

`make agent AGENT_KEYSTORE=<keystore> AGENT_KEYSTORE_PASSWORD=<password>` builds and signs `bin/mcloud-mdm-agent.apk` in Docker (linux/amd64). Keep the key: Android updates a device owner app signed with the same key only.

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
| `wifi-locked` | `no_config_wifi` | |
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

Next to every MCloud (one MDM per farm, Apple Business is the other way in):

| Part | iOS | Android |
| --- | --- | --- |
| containers | NanoHUB + MySQL 8.4 | Headwind MDM (amd64, Tomcat, about 1 GB of RAM) + PostgreSQL + `hmdm-init` |
| shared | mcloud-mdm (SCEP, the enrollment, the admin UI) | mcloud-mdm (the enrollment, the agent APK, the admin UI) |
| the proxy of MCloud publishes | `/mdm`, `/checkin` (NanoHUB), `/scep`, `/mdm/enroll` (mcloud-mdm) | `/android/` (mcloud-mdm); Headwind MDM on a host of its own (`HMDM_PUBLIC_URL`, the WAR is the root) |
| from the devices | https to the public URL (a certificate the device trusts, or `MDM_TLS_CA_FILE`) | http(s) to `HMDM_PUBLIC_URL` and TCP 31000 (MQTT) |
| outbound | APNs: `api.push.apple.com` 443 | none (no Google services) |
| secrets | the APNs push certificate (renewed every year with the same Apple ID), the supervision identity, `MDM_ENROLL_TOKEN` | the signing key of the agent, `HMDM_SHARED_SECRET` (the token of the agents), `HMDM_PASSWORD` |
| on the device host | go-ios: supervision, the profile, `ios pair`, Developer Mode | adb: `android/enroll.sh`, `android/release.sh` |
| the device | supervised (`ios prepare`, it erases) once | no account, a single user; no factory reset |

The admin listener `:8081` is published only behind the authentication of MCloud.

## Admin UI

- The devices of the webhook (`Authenticate`, `TokenUpdate`, `CheckOut`), with the unlock token of `ClearPasscode` kept and never shown.
- Every MDM command of iOS of Apple with its arguments and a hint: what it does, what it needs and its result on a supervised iPhone XR with iOS 18.7.11; `{"$data": "<base64>"}` is data, filled from a file.
- The history of the commands with the reports of the devices; `Cleared` is a command never delivered: NanoMDM clears the queue of a device that enrolls again.
- The ready profiles, installed by `InstallProfile` and removed by `RemoveProfile`, their "installed" marks from `ProfileList`.
- The console of the API of NanoHUB with the DDM declarations (configurations, activations, sets, status) and NanoCMD.
- The upload of the APNs push certificate and its key.
- Two tabs, iOS and Android (`#ios`, `#android` in the URL). Android: the devices of Headwind MDM, every push command with its arguments and hints, the presets of the selected device, the commands sent with their delivery, the device log, the enrollment commands of a serial.

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
