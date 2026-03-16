#!/bin/sh
set -eu

: "${API_BASE_URL:=/api}"
: "${API_PROXY_TARGET:=http://backend:8002}"
: "${GITHUB_REPO_URL:=https://github.com/BettaCyber/CQL-HUB}"
: "${COMPANY_URL:=https://betta.gp}"

envsubst '${API_BASE_URL} ${GITHUB_REPO_URL} ${COMPANY_URL}' \
  < /usr/share/nginx/html/config.template.js \
  > /usr/share/nginx/html/config.js

envsubst '${API_PROXY_TARGET}' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf
