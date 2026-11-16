#!/bin/bash
# run.sh runs the whole demo on this machine: the mock OAuth provider, the
# issuer (which also serves the wallet) and the demo origin. Ctrl-C stops them
# all, as does any one of them exiting.
#
# usage: demo/run.sh
#
# They listen on localhost only, on ports 8080 to 8082. Open them in the
# browser as localhost too: the wallet needs a secure context for WebCrypto,
# and http://localhost counts as one.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(mktemp -d)
# Jobs started in the background ignore Ctrl-C, so stop them on the way out.
trap 'kill $(jobs -p) 2>/dev/null || true; wait; rm -rf "$bin"' EXIT
trap 'exit 130' INT TERM

go build -o "$bin/" . ./demo/origin ./demo/mockoauth

ADDR=127.0.0.1:8082 "$bin/mockoauth" &
ADDR=127.0.0.1:8080 \
    OAUTH_CLIENT_ID=demo OAUTH_CLIENT_SECRET=demo \
    OAUTH_AUTH_URL=http://localhost:8082/oauth/authorize \
    OAUTH_TOKEN_URL=http://localhost:8082/oauth/token \
    OAUTH_USERINFO_URL=http://localhost:8082/api/v1/profiles/me \
    "$bin/privacypass" &
# The origin reads the issuer's directory when it starts, so give the issuer a
# moment first.
sleep 1
ADDR=127.0.0.1:8081 "$bin/origin" &

cat <<EOF

The demo is running; Ctrl-C stops it.
  Mock OAuth provider  http://localhost:8082 (any username, password 1234)
  Issuer               http://localhost:8080 (wallet at http://localhost:8080/wallet)
  Demo origin          http://localhost:8081

EOF
wait -n
