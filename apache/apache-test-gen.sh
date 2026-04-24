#!/usr/bin/env bash
# apache-test-gen.sh — substitute placeholders in apache/apache.conf
# to produce apache-test.conf with absolute paths and unprivileged
# ports suitable for the local test rig.
#
# Mirrors nginx/nginx-test-gen.sh. The generated file is .gitignored;
# regenerate it any time the checkout moves or after editing
# apache.conf.
#
# Usage:
#     apache/apache-test-gen.sh
#     apachectl -t -f $(pwd)/apache/apache-test.conf -d $(pwd)/apache

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SRC="${PROJECT_ROOT}/apache/apache.conf"
DST="${PROJECT_ROOT}/apache/apache-test.conf"
LOGS="${PROJECT_ROOT}/apache/logs"

# Unprivileged ports for local tests. 8443 is taken by FastAPI, 8444
# by nginx tests; 8445 / 8082 are the next safe pair.
LISTEN_PORT_HTTPS="${LISTEN_PORT_HTTPS:-8445}"
LISTEN_PORT_HTTP="${LISTEN_PORT_HTTP:-8082}"

[[ -f "${SRC}" ]] || {
    printf 'error: source template missing: %s\n' "${SRC}" >&2
    exit 1
}

mkdir -p "${LOGS}"

# Apache modules path — Ubuntu/Debian default. Override via env if
# you're on a distro that puts modules elsewhere.
APACHE_MODS_DIR="${APACHE_MODS_DIR:-/usr/lib/apache2/modules}"
if [[ ! -d "${APACHE_MODS_DIR}" ]]; then
    printf 'error: apache modules dir not found: %s\n' "${APACHE_MODS_DIR}" >&2
    printf '       set APACHE_MODS_DIR or install apache2 (apt install apache2)\n' >&2
    exit 1
fi

# Build the test config. The unprivileged rig differs from a
# system-installed Apache in three ways:
#   * Modules: we LoadModule explicitly because /etc/apache2/mods-enabled
#     symlinks aren't picked up when running with -f <our config>.
#   * ServerRoot/PidFile/Mutex: must point at a user-writable dir
#     (apache/logs/) so apachectl -k start works without root.
#   * Listen ports: 8445/8082 instead of 443/80 to avoid CAP_NET_BIND.
{
    printf '# GENERATED FILE — do not edit manually.\n'
    printf '# Source: apache/apache.conf\n'
    printf '# Generated at: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat <<EOF
# --- Bootstrap for unprivileged operation -----------------------------------
ServerRoot "${PROJECT_ROOT}/apache"
PidFile    "${LOGS}/apache.pid"
Mutex      "file:${LOGS}" default

ErrorLog     "${LOGS}/error.log"
LogLevel     warn
CustomLog    "${LOGS}/access.log" "%h \\"%r\\" %>s SSL_CLIENT_S_DN_CN=%{SSL_CLIENT_S_DN_CN}x verify=%{SSL_CLIENT_VERIFY}x"

User  ${USER}
Group $(id -gn)

# --- Required modules -------------------------------------------------------
# Built-in (static) modules that MUST NOT be LoadModule'd on Ubuntu's
# apache2.4.58: core, so, watchdog, http, log_config, logio, version,
# unixd. Anything else gets loaded explicitly here so the unprivileged
# rig works even when /etc/apache2/mods-enabled isn't consulted.
LoadModule mpm_event_module       ${APACHE_MODS_DIR}/mod_mpm_event.so
LoadModule authz_core_module      ${APACHE_MODS_DIR}/mod_authz_core.so
LoadModule headers_module         ${APACHE_MODS_DIR}/mod_headers.so
LoadModule rewrite_module         ${APACHE_MODS_DIR}/mod_rewrite.so
LoadModule ssl_module             ${APACHE_MODS_DIR}/mod_ssl.so
LoadModule socache_shmcb_module   ${APACHE_MODS_DIR}/mod_socache_shmcb.so
LoadModule proxy_module           ${APACHE_MODS_DIR}/mod_proxy.so
LoadModule proxy_http_module      ${APACHE_MODS_DIR}/mod_proxy_http.so
LoadModule mime_module            ${APACHE_MODS_DIR}/mod_mime.so

TypesConfig /etc/mime.types

EOF

    # Substitute the placeholders. Use '#' as sed separator so paths
    # don't need escaping.
    sed \
        -e "s#PKI_DIR#${PROJECT_ROOT}/pki#g" \
        -e "s#APACHE_DIR#${PROJECT_ROOT}/apache#g" \
        -e "s#LISTEN_PORT_HTTPS#${LISTEN_PORT_HTTPS}#g" \
        -e "s#LISTEN_PORT_HTTP#${LISTEN_PORT_HTTP}#g" \
        "${SRC}"
} > "${DST}"

printf 'wrote %s\n' "${DST}"
printf '  listen https = :%s\n' "${LISTEN_PORT_HTTPS}"
printf '  listen http  = :%s\n' "${LISTEN_PORT_HTTP}"
