#!/bin/bash
# Releases an Android device of this host from mcloud-mdm over adb, without the server of the agent (README.md#android):
# the agent removes its device owner, the restrictions go away, no factory reset. The token of the agent (the secret
# of the server) comes from mcloud-mdm with the enrollment token.
#   MDM_URL=https://mcloud.example.com MDM_ENROLL_TOKEN=... android/release.sh <serial> [--uninstall]
# CURL_OPTS adds options of curl (e.g. --cacert ca.crt), ADB the adb command (e.g. "adb -H host").
set -euo pipefail

serial="${1:?usage: android/release.sh <serial> [--uninstall]}"
uninstall="${2:-}"
: "${MDM_URL:?the public URL of mcloud-mdm}"
: "${MDM_ENROLL_TOKEN:?the enrollment token of mcloud-mdm}"
read -r -a curl_opts <<< "${CURL_OPTS:-}"
read -r -a adb_cmd <<< "${ADB:-adb}"
agent=com.hmdm.launcher

adb_s() { "${adb_cmd[@]}" -s "$serial" "$@"; }

[[ "$(adb_s get-state 2> /dev/null)" == device ]] || {
  echo "release: ${serial} is not an adb device of this host (adb devices)" >&2
  exit 1
}

release="$(curl -fsS "${curl_opts[@]}" -H "Authorization: Bearer ${MDM_ENROLL_TOKEN}" -G \
  --data-urlencode "serial=${serial}" "${MDM_URL%/}/android/release")"
adb_s shell "$release" > /dev/null
if adb_s shell dpm list-owners | grep -q "${agent}/"; then
  echo "release: ${serial} still has the device owner" >&2
  exit 1
fi
echo "release: ${serial} has no device owner"
if [[ "$uninstall" == --uninstall ]]; then
  adb_s uninstall "$agent" > /dev/null
  echo "release: the agent is uninstalled"
fi
