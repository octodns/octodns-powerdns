## v0.0.2 - 2022-11-09 - Root NS Records and (beta) LUA record support

#### Nothworthy Changes

* Root NS record management support added, requires octodns>=0.9.16,
  `nameserver_values` and `nameserver_ttl` support removed. managing PowerDNS
  root NS records should migrate to sources (usually YamlProvider, but could
  utilize dynamic source/provider if necessary)
* Support for `_get_nameserver_record` removed. For static values it should be
  replaced with configuration in yaml files. For dynamic values where
  information is sourced from an API or otherwise calculated a custom Source is
  recommended.
* Beta-level support for PowerDnsProvider/LUA scripted records, see
  https://doc.powerdns.com/authoritative/lua-records/index.html for their doc
  and https://gist.github.com/ahupowerdns/1e8bfbba95a277a4fac09cb3654eb2ac for
  some of what's possible.
* Allow configuring mode_of_operation and soa_edit_api via provider parameters
