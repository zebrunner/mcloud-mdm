#!/bin/sh
# Sets the password of the admin of Headwind MDM to HMDM_PASSWORD and clears the reset Headwind MDM asks for at its
# first start, so mcloud-mdm logs in (README.md#android). A one-shot service on the postgres image (psql, md5sum,
# sha1sum), next to the postgres of Headwind MDM: PGHOST, PGUSER, PGPASSWORD, PGDATABASE, HMDM_LOGIN, HMDM_PASSWORD.
set -eu

: "${HMDM_PASSWORD:?the password of the admin of Headwind MDM}"
login="${HMDM_LOGIN:-admin}"
# the salt of PasswordUtil of Headwind MDM: the stored hash is SHA1(MD5 in upper case hex + salt)
salt=5YdSYHyg2U

md5="$(printf '%s' "$HMDM_PASSWORD" | md5sum | cut -d' ' -f1 | tr 'a-f' 'A-F')"
hash="$(printf '%s%s' "$md5" "$salt" | sha1sum | cut -d' ' -f1)"

# Headwind MDM creates its tables and its admin at its first start
tries=0
until psql -qtAc "select 1 from users where login = '${login}'" 2> /dev/null | grep -q 1; do
  tries=$((tries + 1))
  if test "$tries" -gt 120; then
    echo "hmdm-init: no user ${login} in Headwind MDM after 10 minutes" >&2
    exit 1
  fi
  sleep 5
done

# the login refuses the user with a pending reset; a new authtoken invalidates the old sessions
psql -qtA -v ON_ERROR_STOP=1 -v hash="$hash" -v login="$login" << 'SQL'
update users set password = :'hash', passwordreset = false, passwordresettoken = null, authtoken = null
  where login = :'login' and (password <> :'hash' or passwordreset);
SQL
echo "hmdm-init: the password of ${login} is HMDM_PASSWORD"
