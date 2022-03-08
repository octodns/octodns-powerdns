## v0.0.3 - 2022-??-?? - Support the root

* Enable SUPPORTS_ROOT_NS for management of root NS records. Requires
  octodns>=0.9.16.

## v0.0.2 - 20??-??-?? - Root NS Records

#### Nothworthy Changes

* Root NS record management support added, requires octodns>=0.9.16,
  `nameserver_values` and `nameserver_ttl` support removed. managing PowerDNS
  root NS records should migrate to sources (usually YamlProvider, but could
  utilize dynamic source/provider if necessary)
