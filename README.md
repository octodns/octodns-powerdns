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
      # The api key that grans access (required, example is using an env var)
      api_key: env/POWERDNS_API_KEY
      # The URL scheme (optional, default http)
      # scheme: https
      # Check SSL certificate (optional, default True)
      # ssl_verify: true
      # Send DNS NOTIFY to secondary servers after change (optional, default false)
      # notify: false
```

### Support Information

#### Records

All octoDNS record types are supported.

#### Root NS Records

PowerDnsProvider supports full root NS record management.

#### Dynamic

PowerDnsProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

There is a [docker-compose.yml](/docker-compose.yml) file included in the repo that will set up a PowerDNS server with the API enabled for use in development. The api-key for it is `its@secret`.
