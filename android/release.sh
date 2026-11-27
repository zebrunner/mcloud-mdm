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

answer="$(curl -fsS "${curl_opts[@]}" -H "Authorization: Bearer ${MDM_ENROLL_TOKEN}" -G \
  --data-urlencode "serial=${serial}" --data-urlencode "staged=1" "${MDM_URL%/}/android/release")"
staged="$(sed -n 's/^staged=//p' <<< "$answer")"
release="$(sed -n 's/^command=//p' <<< "$answer")"
if [[ -z "$staged" && -z "$release" ]]; then
  release="$(head -n 1 <<< "$answer")"
fi
# the staged form (an agent with the feature staged, Android 9+): the token on the stdin of content write, never in
# a command line on the device; else the argument form
sdk="$(adb_s shell getprop ro.build.version.sdk | tr -dc '0-9')"
features="$(adb_s shell content call --uri "content://${agent}.mcloud" --method status | tr -d '\r')"
if [[ -n "$staged" && "${sdk:-0}" -ge 28 && "$features" =~ features=[a-z,]*staged ]]; then
  printf '%s' "$staged" | adb_s shell content write --uri "content://${agent}.mcloud/release"
  adb_s shell content call --uri "content://${agent}.mcloud" --method release > /dev/null
elif [[ -n "$release" ]]; then
  adb_s shell "$release" > /dev/null
else
  echo "release: the agent has no staged release (a new agent, Android 9+) and the server allows no other" >&2
  exit 1
fi
if adb_s shell dpm list-owners | grep -q "${agent}/"; then
  echo "release: ${serial} still has the device owner" >&2
  exit 1
fi
echo "release: ${serial} has no device owner"
if [[ "$uninstall" == --uninstall ]]; then
  adb_s uninstall "$agent" > /dev/null
  echo "release: the agent is uninstalled"
fi
