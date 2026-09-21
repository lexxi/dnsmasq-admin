#!/bin/bash
set -euo pipefail

# Adjust these values for your environment before installation.
DNSMASQ_RES_FILE="${DNSMASQ_RES_FILE:-/etc/dnsmasq.d/dhcp-reservations.conf}"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
DOMAIN="${DOMAIN:-home.local}"
LOCAL_HOSTNAME="${LOCAL_HOSTNAME:-dnsmasq}"

TMP_FILE="${HOSTS_FILE}.tmp"

{
    echo "127.0.0.1 localhost"
    echo "127.0.1.1 ${LOCAL_HOSTNAME} ${LOCAL_HOSTNAME}.${DOMAIN}"

    grep -E '^dhcp-host=' "${DNSMASQ_RES_FILE}" | \
    while IFS=',' read -r first ip host; do
        [ -z "${ip:-}" ] && continue

        if [ -z "${host:-}" ]; then
            host="host-${ip//./-}"
        fi

        echo "${ip} ${host} ${host}.${DOMAIN}"
    done
} > "${TMP_FILE}"

mv "${TMP_FILE}" "${HOSTS_FILE}"
