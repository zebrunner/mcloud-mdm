#!/bin/bash
# Enrolls an Android device of this host into mcloud-mdm over adb (README.md#android): the agent becomes the device
# owner without a factory reset and connects to Headwind MDM. adb alone cannot remove it: android/release.sh does.
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
# staged=1: the JSON of the staged form (staged=) and the command of the argument form (command=, unless the server
# allows the staged form only); an older server answers the command only
answer="$(curl -fsS "${curl_opts[@]}" -H "Authorization: Bearer ${MDM_ENROLL_TOKEN}" -G \
  --data-urlencode "serial=${serial}" --data-urlencode "name=${name}" --data-urlencode "format=shell" \
  --data-urlencode "staged=1" "${MDM_URL%/}/android/enroll")"
staged="$(sed -n 's/^staged=//p' <<< "$answer")"
configure="$(sed -n 's/^command=//p' <<< "$answer")"
if [[ -z "$staged" && -z "$configure" ]]; then
  configure="$(head -n 1 <<< "$answer")"
fi

echo "enroll: installing the agent on ${serial}"
adb_s install -r "$apk" > /dev/null
# an agent made the device owner while it was a test-only app stays removable over adb (Android keeps the flag of
# the moment): its device owner is set again
if adb_s shell dumpsys device_policy | grep -q "testOnlyAdmin=true"; then
  echo "enroll: the device owner is a test-only admin, setting it again"
  adb_s shell dpm remove-active-admin "$admin" > /dev/null
fi
if adb_s shell dpm list-owners | grep -q "$admin"; then
  echo "enroll: the agent is the device owner already"
else
  # Android refuses a device owner on a device with accounts or a second user: the output tells which
  adb_s shell dpm set-device-owner "$admin"
fi
# the staged form (an agent with the feature staged, Android 9+): the setup goes on the stdin of content write (printf
# is a builtin), the call has no argument: the secret is in no command line on the device, where every process of
# the shell uid reads them; else the argument form
sdk="$(adb_s shell getprop ro.build.version.sdk | tr -dc '0-9')"
features="$(adb_s shell content call --uri "content://${agent}.mcloud" --method status | tr -d '\r')"
if [[ -n "$staged" && "${sdk:-0}" -ge 28 && "$features" =~ features=[a-z,]*staged ]]; then
  printf '%s' "$staged" | adb_s shell content write --uri "content://${agent}.mcloud/setup"
  result="$(adb_s shell content call --uri "content://${agent}.mcloud" --method setup)"
elif [[ -n "$configure" ]]; then
  echo "enroll: no staged setup (a new agent and server, Android 9+): the setup has the secret in its arguments"
  result="$(adb_s shell "$configure")"
else
  echo "enroll: the agent has no staged setup (a new agent, Android 9+) and the server allows no other" >&2
  exit 1
fi
if [[ "$result" != *"Result: Bundle["* ]]; then
  echo "enroll: the setup of the agent failed: $(head -n 2 <<< "$result" | tr -d '\r')" >&2
  exit 1
fi
adb_s shell am start -n "${agent}/.ui.MainActivity" > /dev/null
# the agent loads its configuration, then the system launcher comes back
sleep 10
adb_s shell content call --uri "content://${agent}.mcloud" --method status
