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

## Enrollment

`GET /mdm/enroll?udid=<udid>` with `Authorization: Bearer <MDM_ENROLL_TOKEN>` returns an enrollment profile (`application/x-apple-aspen-config`) with a new one-time SCEP challenge: it signs one device identity within `MDM_CHALLENGE_TTL`, a leaked profile is useless afterwards. The agent of the device host installs it over USB with no prompt on a supervised device:

```bash
curl -fsS -H "Authorization: Bearer $MDM_ENROLL_TOKEN" "https://mcloud.example.com/mdm/enroll?udid=$UDID" -o enroll.mobileconfig
P12_PASSWORD=... ios profile add enroll.mobileconfig --p12file=supervision.p12 --udid=$UDID
```

- The user can always remove the MDM profile: iOS refuses an MDM payload in a profile that cannot be removed unless it comes from ADE (checked on iOS 18.7.11). The removal is the `CheckOut` event; the agent enrolls the device again.
- The removal of the MDM profile removes every profile MDM installed; the DDM declarations come back with the next enrollment (mcloud-mdm notifies DDM after it).
- Developer Mode, the supervision and the recovery of a device that lost MDM need USB: no MDM command or key exists for them.

## Admin UI

- The devices of the webhook (`Authenticate`, `TokenUpdate`, `CheckOut`), with the unlock token of `ClearPasscode` kept and never shown.
- Every MDM command of iOS of Apple with its arguments and a hint: what it does, what it needs and its result on a supervised iPhone XR with iOS 18.7.11; `{"$data": "<base64>"}` is data, filled from a file.
- The history of the commands with the reports of the devices; `Cleared` is a command never delivered: NanoMDM clears the queue of a device that enrolls again.
- The ready profiles, installed by `InstallProfile` and removed by `RemoveProfile`, their "installed" marks from `ProfileList`.
- The console of the API of NanoHUB with the DDM declarations (configurations, activations, sets, status) and NanoCMD.
- The upload of the APNs push certificate and its key.

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
| `make test` | `go test -race ./...`: SCEP (one-time challenges, renewal), the profiles, the state, the admin API and the webhook |
| `make docker` | `tests/image_test.sh`: the image, its configuration, exit codes, startup, both listeners and the CA kept in the volume |
| `make check` | all of them |

The conventions of the repository are in [CONVENTIONS.md](CONVENTIONS.md).

## Support

[Zebrunner](https://zebrunner.com/) - open an issue in this repository.

## License

[Apache License 2.0](LICENSE)
