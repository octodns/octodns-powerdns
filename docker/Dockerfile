FROM debian:bookworm-slim

# Use the official PowerDNS apt repo (auth-49 = 4.9.x) rather than Debian's
# 4.7.3, which has a known crash in geoipbackend on startup. [trusted=yes] is
# acceptable here because this image is dev-only (local docker-compose) and
# never shipped or deployed.
RUN printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' \
        > /etc/apt/preferences.d/pdns \
    && printf 'deb [trusted=yes] http://repo.powerdns.com/debian bookworm-auth-49 main\n' \
        > /etc/apt/sources.list.d/pdns.list \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        mariadb-client \
        pdns-server \
        pdns-backend-geoip \
        pdns-backend-mysql \
    && rm --recursive --force /var/lib/apt/lists/* \
    && rm --force /etc/powerdns/pdns.d/*.conf

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/tcp 53/udp 8081/tcp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/pdns_server", "--guardian=no", "--daemon=no"]
