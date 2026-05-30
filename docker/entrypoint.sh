#!/bin/bash
#
# Entrypoint for the octodns-powerdns dev PowerDNS container.
#
# Waits for the mariadb service, creates and initializes the pdns schema if
# it's empty, generates /etc/powerdns/pdns.conf from the PDNS_* environment
# variables, and then execs the pdns_server command passed as CMD.

set -euo pipefail

: "${DB_HOST:=db}"
: "${DB_PORT:=3306}"
: "${DB_USER:=root}"
: "${DB_PASS:=l3tmein}"
: "${DB_NAME:=pdns}"
: "${API_KEY:=its@secret}"
: "${WEBSERVER_PASSWORD:=its@secret}"

export MYSQL_PWD="${DB_PASS}"
MYSQL=(mariadb --host="${DB_HOST}" --port="${DB_PORT}" --user="${DB_USER}")

echo "waiting for mariadb at ${DB_HOST}:${DB_PORT}..."
until "${MYSQL[@]}" --execute=';' >/dev/null 2>&1; do
    sleep 1
done
echo "mariadb is up"

"${MYSQL[@]}" --execute="CREATE DATABASE IF NOT EXISTS ${DB_NAME}"

TABLE_COUNT=$(
    "${MYSQL[@]}" --skip-column-names --batch --execute="
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema='${DB_NAME}'
    "
)
if [ "${TABLE_COUNT}" -eq 0 ]; then
    echo "initializing pdns schema in ${DB_NAME}"
    "${MYSQL[@]}" --database="${DB_NAME}" \
        < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
fi

cat > /etc/powerdns/pdns.conf <<EOF
launch=gmysql,geoip

gmysql-host=${DB_HOST}
gmysql-port=${DB_PORT}
gmysql-user=${DB_USER}
gmysql-password=${DB_PASS}
gmysql-dbname=${DB_NAME}

api=yes
api-key=${API_KEY}
webserver=yes
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password=${WEBSERVER_PASSWORD}
webserver-port=8081

loglevel=5

enable-lua-records=shared
edns-subnet-processing=yes

geoip-database-files=mmdb:/etc/powerdns/GeoIP2-City-Test.mmdb
geoip-zones-file=/etc/powerdns/geoip.yaml
EOF

exec "$@"
