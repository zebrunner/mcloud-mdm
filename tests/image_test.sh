#!/bin/bash
# Checks of the docker image: build, contents, configuration, the exit codes, the startup, the endpoints of both
# listeners and the SCEP CA kept in the data volume.
# IMAGE overrides the tag of the tested image (it is built when missing, REBUILD=true builds it anyway).
source "$(dirname "$0")/lib.sh"
cd "$REPO" || exit 1

IMAGE="${IMAGE:-mcloud-mdm:test}"
PREFIX="mcloud-mdm-test-$$"
TOKEN="0123456789abcdef0123"
ADMIN_TOKEN="0123456789abcdef0123456789abcdef"

require_cmd docker
docker info > /dev/null 2>&1 || skip "requires a running docker daemon"

# cleanup: removes the container and the volume of the startup checks
# called by the EXIT trap of lib.sh
# shellcheck disable=SC2329
cleanup() {
  docker rm --force "${PREFIX}-run" > /dev/null 2>&1
  docker volume rm "${PREFIX}-data" > /dev/null 2>&1
}

# in_container <command...>: runs the command in the started container
in_container() {
  docker exec "${PREFIX}-run" "$@" 2>&1
}

# start: starts the container of the startup checks with the data volume
start() {
  docker run -d --name "${PREFIX}-run" -v "${PREFIX}-data:/data" -e MDM_PUBLIC_URL=https://mcloud.example.com \
    -e NANOHUB_API_KEY=key -e MDM_ENROLL_TOKEN="$TOKEN" -e MDM_ADMIN_TOKEN="$ADMIN_TOKEN" "$IMAGE" > /dev/null 2>&1
}

# wait_healthy <seconds>: waits for the healthcheck of the started container
wait_healthy() {
  local i
  for ((i = 0; i < $1; i++)); do
    [[ "$(docker inspect "${PREFIX}-run" --format '{{.State.Health.Status}}' 2> /dev/null)" == "healthy" ]] && return 0
    sleep 1
  done
  return 1
}

# status <url> [header]: the HTTP status of a GET in the container
status() {
  if [[ -n "${2:-}" ]]; then
    in_container wget -S -q -O /dev/null --header "$2" "$1" | awk '/^  HTTP\// { code = $2 } END { print code }'
  else
    in_container wget -S -q -O /dev/null "$1" | awk '/^  HTTP\// { code = $2 } END { print code }'
  fi
}

section "build"
if [[ "${REBUILD:-false}" != "true" ]] && docker image inspect "$IMAGE" > /dev/null 2>&1; then
  skip_check "image builds" "$IMAGE exists, REBUILD=true builds it again"
elif docker build --progress=plain --provenance=false --tag "$IMAGE" . > "${WORK}/build.log" 2>&1; then
  pass "image builds"
else
  fail "image builds" "docker build failed" "$(tail -100 "${WORK}/build.log")"
  finish
fi

section "configuration"
config="$(docker image inspect "$IMAGE" --format '{{json .Config}}')"
check_contains "entrypoint" '"Entrypoint":["/opt/zebrunner/mcloud-mdm"]' "$config"
check_contains "the healthcheck is the program" '"/opt/zebrunner/mcloud-mdm","-healthcheck"' "$config"
check_contains "the data volume" '"/data":{}' "$config"
check_contains "the device listener" '"MDM_DEVICE_LISTEN=:8080"' "$config"
check_contains "the admin listener" '"MDM_ADMIN_LISTEN=:8081"' "$config"
check_contains "the image is labeled Apache-2.0" '"org.opencontainers.image.licenses":"Apache-2.0"' "$config"
check "the version of a build without VERSION" "dev" "$(docker run --rm "$IMAGE" -version 2>&1)"

section "exit codes"
out="$(docker run --rm "$IMAGE" 2>&1)"
check "no configuration exits with 0" "0" "$?"
check_contains "MDM_PUBLIC_URL is required" "MDM_PUBLIC_URL" "$out"
check_contains "NANOHUB_API_KEY is required" "NANOHUB_API_KEY is empty" "$out"
check_contains "MDM_ENROLL_TOKEN is required" "MDM_ENROLL_TOKEN" "$out"
check_contains "MDM_ADMIN_TOKEN is required" "MDM_ADMIN_TOKEN" "$out"
out="$(docker run --rm -e MDM_PUBLIC_URL=https://x -e NANOHUB_API_KEY=k -e MDM_ENROLL_TOKEN="$TOKEN" -e MDM_ADMIN_TOKEN="$ADMIN_TOKEN" \
  -e LOGGER_LEVEL=LOUD "$IMAGE" 2>&1)"
check "an invalid LOGGER_LEVEL exits with 0" "0" "$?"
check_contains "the invalid LOGGER_LEVEL is logged" "LOGGER_LEVEL" "$out"

section "startup"
if start && wait_healthy 60; then
  pass "the container is healthy"
else
  fail "the container is healthy" "not healthy" "$(docker logs "${PREFIX}-run" 2>&1 | tail -20)"
  finish
fi
logs="$(docker logs "${PREFIX}-run" 2>&1)"
check_contains "the first log line is the banner with the version of the build" \
  $'msg="\xe2\x94\x81\xe2\x94\x81 mcloud-mdm dev \xc2\xb7 device listener ' "$(head -1 <<< "$logs")"
check_contains "the SCEP CA is created" "SCEP CA created" "$logs"
check_not_contains "no error is logged" "level=ERROR" "$logs"
check "the key of the SCEP CA is private" "600" "$(in_container stat -c %a /data/scep/ca.key)"
check "the certificate of the SCEP CA is readable for NanoHUB" "644" "$(in_container stat -c %a /data/scep/ca.pem)"
ca="$(in_container sha256sum /data/scep/ca.pem)"

section "device listener"
check "the health endpoint" "ok" "$(in_container wget -qO- http://127.0.0.1:8080/healthz)"
check_contains "SCEP GetCACaps" "POSTPKIOperation" "$(in_container wget -qO- 'http://127.0.0.1:8080/scep?operation=GetCACaps')"
check "the enrollment profile needs the token" "401" "$(status http://127.0.0.1:8080/mdm/enroll)"
check "the enrollment profile needs the push certificate" "503" "$(status http://127.0.0.1:8080/mdm/enroll "Authorization: Bearer $TOKEN")"
check "the admin API is not on the device listener" "404" "$(status http://127.0.0.1:8080/api/state)"

section "admin listener"
admin="Authorization: Bearer ${ADMIN_TOKEN}"
check "the admin listener needs the admin token" "401" "$(status http://127.0.0.1:8081/api/state)"
check "a wrong admin token is refused" "401" "$(status http://127.0.0.1:8081/api/state "Authorization: Bearer wrong")"
check_contains "the UI" "<title>MCloud MDM</title>" "$(in_container wget -qO- --header "$admin" http://127.0.0.1:8081/)"
check_contains "the catalog of the commands" '"DeviceInformation"' \
  "$(in_container wget -qO- --header "$admin" http://127.0.0.1:8081/api/catalog)"
check_contains "the state" '"enroll_url":"https://mcloud.example.com/mdm/enroll"' \
  "$(in_container wget -qO- --header "$admin" http://127.0.0.1:8081/api/state)"

section "restart"
docker rm --force "${PREFIX}-run" > /dev/null 2>&1
if start && wait_healthy 60; then
  pass "the container is healthy again"
else
  fail "the container is healthy again" "not healthy" "$(docker logs "${PREFIX}-run" 2>&1 | tail -20)"
  finish
fi
check "the SCEP CA of the volume is kept" "$ca" "$(in_container sha256sum /data/scep/ca.pem)"
check_not_contains "no new SCEP CA" "SCEP CA created" "$(docker logs "${PREFIX}-run" 2>&1)"

finish
