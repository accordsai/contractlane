#!/usr/bin/env bash
set -euo pipefail

if [ ! -f ".env" ]; then
  echo "WARNING: .env not found. Docker Compose will run with shell environment only."
  exit 0
fi

default_password="CHANGE_ME_STRONG_PASSWORD"
default_hmac="CHANGE_ME_DELEGATION_HMAC_SECRET"
default_webhook="CHANGE_ME_EXEC_WEBHOOK_SECRET"

postgres_password="$(awk -F= '$1=="POSTGRES_PASSWORD"{print $2}' .env | tail -n1)"
delegation_secret="$(awk -F= '$1=="IAL_DELEGATION_HMAC_SECRET"{print $2}' .env | tail -n1)"
webhook_secret="$(awk -F= '$1=="EXEC_WEBHOOK_SECRET"{print $2}' .env | tail -n1)"

if [ "${postgres_password}" = "${default_password}" ]; then
  echo "WARNING: POSTGRES_PASSWORD is still default in .env. Change it before exposing the demo publicly."
fi

if [ "${delegation_secret}" = "${default_hmac}" ]; then
  echo "WARNING: IAL_DELEGATION_HMAC_SECRET is still default in .env."
fi

if [ "${webhook_secret}" = "${default_webhook}" ]; then
  echo "WARNING: EXEC_WEBHOOK_SECRET is still default in .env."
fi
