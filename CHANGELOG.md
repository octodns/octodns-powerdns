## v0.0.? - 2024-??-?? - ???

* Support for fully managing zones with special characters in their names, e.g.
  128/26.2.0.192.in-addr.arpa. added.

## v0.0.6 - 2024-03-08 - Get port type straight

* DS Record support added
* Fix for url formatting of port when it's of type float

## v0.0.5 - 2023-09-12 - Known your zones

* Adds Provider.list_zones to enable new dynamic zone config functionality
* Support disabling SSL verification

## v0.0.4 - 2023-08-03 - Stay off the network unless you really need it

* Rework mode_of_operation to be fetched on-demand rather than during __init__
  so that the provider can be created w/o access to or credentials for the
  server. This should allow things like octodns-validate w/o connectivity.

## v0.0.3 - 2022-12-22 - TLSA

* Add support for TLSA records

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
