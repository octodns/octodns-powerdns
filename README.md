## PowerDNS API provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [PowerDNS's API](https://doc.powerdns.com/authoritative/http-api/index.html).

### Installation

#### Command line

```
pip install octodns-powerdns
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.21
octodns-powerdns==0.0.3
requests==2.31.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@67ea0b0ea7961e37b028cfe21c463fa3e5090c8f#egg=octodns
-e git+https://git@github.com/octodns/octodns-powerdns.git@e33349e5edfe4e12a1d179a32a5f70a8ec4c2aad#egg=octodns_powerdns
requests==2.31.0
```

### Configuration

```yaml
providers:
  powerdns:
      class: octodns_powerdns.PowerDnsProvider
      # The host on which PowerDNS api is listening (required)
      host: fqdn
      # The port on which PowerDNS api is listening (optional, default 8081)
      port: 8081
      # The api key that grants access (required, example is using an env var)
      api_key: env/POWERDNS_API_KEY
      # The URL scheme (optional, default http)
      # scheme: https
      # Check SSL certificate (optional, default True)
      # ssl_verify: true
      # Send DNS NOTIFY to secondary servers after change (optional, default false)
      # notify: false
      # The PowerDNS server id used in API URLs (optional, default localhost)
      # server_id: localhost
      # Force dynamic record support on/off, bypassing the runtime probe
      # (optional, default None — probe /config to decide)
      # enable_dynamic: true
```

### Support Information

#### Records

All octoDNS record types are supported.

#### Root NS Records

PowerDnsProvider supports full root NS record management.

#### Dynamic

PowerDnsProvider supports dynamic A, AAAA, and CNAME records by generating
[PowerDNS LUA records](https://doc.powerdns.com/authoritative/lua-records/index.html)
that route answers via the `continent()`, `country()`, and `region()` geo
helpers backed by the
[geoipbackend](https://doc.powerdns.com/authoritative/backends/geoip.html).
Pool values are emitted as `pickwhashed({{weight, value}, ...})`; pool
fallback chains are flattened into the selected pool's value list at encode
time.

The full octoDNS dynamic payload (pools, rules, weights, fallback) is
embedded in a leading Lua comment as a base64-encoded JSON blob so that
`populate` after an `apply` round-trips cleanly — octodns-powerdns parses
that marker rather than trying to read back the generated Lua.

##### Out of scope

- Subnet-based rules (`SUPPORTS_DYNAMIC_SUBNETS=False`) — octoDNS core strips
  them before they reach the provider.
- Per-value pool status (`SUPPORTS_POOL_VALUE_STATUS=False`) — all values are
  treated as `obey`.
- Manually-authored LUA records (`PowerDnsProvider/LUA`) — still supported
  via the existing opaque path; they are never reinterpreted as dynamic.

##### Server requirements

For dynamic records to actually resolve correctly, the PowerDNS server must
have:

1. `enable-lua-records=yes` (or `shared`)
2. The `geoipbackend` loaded via `launch=...,geoip` **and** a MaxMind database
   configured via `geoip-database-files=...`

**Silent-failure warning:** if `enable-lua-records` is on but the geoip
backend is not loaded, PowerDNS will happily serve the generated Lua but
every `continent()`/`country()` call will return an empty string — every
request falls through to the catchall pool. octodns-powerdns probes
`GET /api/v1/servers/{server_id}/config` once per run to check both settings
and disables dynamic support (logging a warning) if either is missing.

If the probe can't run (for example, the API key lacks access to `config`),
set `enable_dynamic: true` on the provider to force dynamic support on. Set
`enable_dynamic: false` to force it off regardless of server configuration.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

There is a [docker-compose.yml](/docker-compose.yml) file included in the repo that will set up a PowerDNS server with the API enabled for use in development. The api-key for it is `its@secret`.
