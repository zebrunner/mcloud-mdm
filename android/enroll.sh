#!/bin/bash
# Enrolls an Android device of this host into mcloud-mdm over adb (README.md#android): the agent becomes the device
# owner without a factory reset and connects to Headwind MDM.
#   MDM_URL=https://mcloud.example.com MDM_ENROLL_TOKEN=... android/enroll.sh <serial> [name]
# CURL_OPTS adds options of curl (e.g. --cacert ca.crt), ADB the adb command (e.g. "adb -H host").
set -euo pipefail

serial="${1:?usage: android/enroll.sh <serial> [name]}"
name="${2:-}"
: "${MDM_URL:?the public URL of mcloud-mdm}"
: "${MDM_ENROLL_TOKEN:?the enrollment token of mcloud-mdm}"
read -r -a curl_opts <<< "${CURL_OPTS:-}"
read -r -a adb_cmd <<< "${ADB:-adb}"
agent=com.hmdm.launcher
admin="${agent}/.AdminReceiver"

adb_s() { "${adb_cmd[@]}" -s "$serial" "$@"; }

[[ "$(adb_s get-state 2> /dev/null)" == device ]] || {
  echo "enroll: ${serial} is not an adb device of this host (adb devices)" >&2
  exit 1
}

# adb installs only a file named *.apk
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
apk="${work}/mcloud-mdm-agent.apk"
curl -fsS "${curl_opts[@]}" -o "$apk" "${MDM_URL%/}/android/agent.apk"
configure="$(curl -fsS "${curl_opts[@]}" -H "Authorization: Bearer ${MDM_ENROLL_TOKEN}" -G \
  --data-urlencode "serial=${serial}" --data-urlencode "name=${name}" --data-urlencode "format=shell" \
  "${MDM_URL%/}/android/enroll")"

echo "enroll: installing the agent on ${serial}"
adb_s install -t -r "$apk" > /dev/null
if adb_s shell dpm list-owners | grep -q "$admin"; then
  echo "enroll: the agent is the device owner already"
else
  # Android refuses a device owner on a device with accounts or a second user: the output tells which
  adb_s shell dpm set-device-owner "$admin"
fi
adb_s shell "$configure" > /dev/null
adb_s shell am start -n "${agent}/.ui.MainActivity" > /dev/null
# the agent loads its configuration, then the system launcher comes back
sleep 10
adb_s shell content call --uri "content://${agent}.mcloud" --method status
