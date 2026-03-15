#!/bin/sh
set -eu

: "${API_BASE_URL:=http://localhost:8002}"
: "${GITHUB_REPO_URL:=https://github.com/Betta_Cyber/CQL-HUB}"
: "${COMPANY_URL:=https://betta.gp}"

envsubst '${API_BASE_URL} ${GITHUB_REPO_URL} ${COMPANY_URL}' \
  < /usr/share/nginx/html/config.template.js \
  > /usr/share/nginx/html/config.js
