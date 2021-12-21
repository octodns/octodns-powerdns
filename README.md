## PowerDNS API provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [PowerDNS's API](https://doc.powerdns.com/authoritative/http-api/index.html).

### Installation

#### Command line

```
pip install octodns_powerdns
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns_powerdns==0.0.1
requests==2.26.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-powerdns.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_powerdns
requests==2.26.0
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
      # The nameservers to use for this provider (optional, default unmanaged)
      nameserver_values:
          - 1.2.3.4.
          - 1.2.3.5.
      # The nameserver record TTL when managed, (optional, default 600)
      nameserver_ttl: 300
```

### Developement

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

There is a [docker-compose.yml](/docker-compose.yml) file included in the repo that will set up a PowerDNS server with the API enabled for use in development. The api-key for it is `its@secret`.
