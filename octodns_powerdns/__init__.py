#
#
#

import logging
from operator import itemgetter
from urllib.parse import quote_plus

from requests import HTTPError, Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record, Rrset

from .dynamic import decode as _dynamic_decode
from .dynamic import encode as _dynamic_encode
from .record import PowerDnsLuaRecord

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '1.2.0'


def _encode_zone_name(name):
    # Powerdns uses a special encoding for URLs. Instead of "%2F" for a slash,
    # the slash must be encoded with "=2F". (This must be done in version 4.7.3
    # from Debian, from version >= 4.8 Powerdns accepts “%2F” and “=2F” as path
    # argument. The output of "/api/v1/servers/localhost/zones" still shows the
    # zone URL with "=2F")
    return quote_plus(name).replace('%', '=')


class PowerDnsBaseProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC_SUBNETS = True
    SUPPORTS_POOL_VALUE_STATUS = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS_MULTIVALUE_PTR = True
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'DS',
            'HTTPS',
            'LOC',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'SSHFP',
            'SRV',
            'SVCB',
            'TLSA',
            'TXT',
            'URI',
            PowerDnsLuaRecord._type,
        )
    )

    TIMEOUT = 5

    POWERDNS_MODES_OF_OPERATION = {
        'native',
        'primary',
        'secondary',
        'master',
        'slave',
    }
    POWERDNS_LEGACY_MODES_OF_OPERATION = {'native', 'master', 'slave'}

    def __init__(
        self,
        id,
        host,
        api_key,
        port=8081,
        scheme="http",
        ssl_verify=True,
        timeout=TIMEOUT,
        soa_edit_api='default',
        mode_of_operation='master',
        notify=False,
        server_id='localhost',
        enable_dynamic=None,
        *args,
        **kwargs,
    ):
        super().__init__(id, *args, **kwargs)

        if getattr(self, '_get_nameserver_record', False):
            raise ProviderException(
                '_get_nameserver_record no longer '
                'supported; instead migrate to using a '
                'dynamic source for zones; see '
                'CHANGELOG.md'
            )

        self.host = host
        self.port = int(port)
        self.scheme = scheme
        self.timeout = timeout
        self.notify = notify
        self.server_id = server_id

        self._powerdns_version = None
        self._supports_dynamic = enable_dynamic

        sess = Session()
        sess.headers.update(
            {
                'X-API-Key': api_key,
                'User-Agent': f'octodns/{octodns_version} octodns-powerdns/{__VERSION__}',
            }
        )
        sess.verify = ssl_verify
        self._sess = sess

        self.soa_edit_api = soa_edit_api
        # to avoid making an API call to get the pdns version during the
        # constructor we'll check the value against the larger set of possible
        # values. the first time we do something that requires the mode of
        # operation we'll do the work of fully vetting it based on version
        if mode_of_operation not in self.POWERDNS_MODES_OF_OPERATION:
            raise ValueError(
                f'invalid mode_of_operation "{mode_of_operation}" - available values: {self.POWERDNS_MODES_OF_OPERATION}'
            )
        # start out with an unset valid
        self._mode_of_operation = None
        # store what we were passed so that we can check it when the time comes
        self._mode_of_operation_arg = mode_of_operation

    def _request(self, method, path, data=None):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = (
            f'{self.scheme}://{self.host}:{self.port:d}/api/v1/servers/'
            f'{self.server_id}/{path}'.rstrip('/')
        )
        # Strip trailing / from url.
        resp = self._sess.request(method, url, json=data, timeout=self.timeout)
        self.log.debug('_request:   status=%d', resp.status_code)
        resp.raise_for_status()
        return resp

    def _get(self, path, data=None):
        return self._request('GET', path, data=data)

    def _post(self, path, data=None):
        return self._request('POST', path, data=data)

    def _put(self, path, data=None):
        return self._request('PUT', path, data=data)

    def _patch(self, path, data=None):
        return self._request('PATCH', path, data=data)

    def _data_for_dynamic(self, rrset):
        # A dynamic record always serializes to exactly one content entry in
        # a PowerDNS "LUA" rrset; if that's what we have, and its qtype is
        # dynamic-capable, try to decode the octodns-dynamic marker. Returns
        # None when the rrset isn't a dynamic record in disguise, in which
        # case it's a "real" PowerDnsProvider/LUA record.
        records = rrset['records']
        if len(records) != 1:
            return None
        _type, script = records[0]['content'].split(' ', 1)
        if not (
            _type in ('A', 'AAAA', 'CNAME')
            and script.startswith('"')
            and script.endswith('"')
        ):
            return None
        try:
            data = _dynamic_decode(script[1:-1], _type)
        except ValueError:
            return None
        data['ttl'] = rrset['ttl']
        return data

    @property
    def powerdns_version(self):
        if self._powerdns_version is None:
            try:
                resp = self._get('')
            except HTTPError as e:
                if e.response.status_code == 401:
                    # Nicer error message for auth problems
                    raise Exception(f'PowerDNS unauthorized host={self.host}')
                raise

            version = resp.json()['version']
            self.log.debug(
                'powerdns_version: got version %s from server', version
            )
            # The extra `-` split is to handle pre-release and source built
            # versions like 4.5.0-alpha0.435.master.gcb114252b
            self._powerdns_version = [
                int(p.split('-')[0]) for p in version.split('.')[:3]
            ]

        return self._powerdns_version

    @property
    def SUPPORTS_DYNAMIC(self):
        if self._supports_dynamic is None:
            self._supports_dynamic = self._probe_dynamic_support()
        return self._supports_dynamic

    def _probe_dynamic_support(self):
        try:
            resp = self._get('config')
            config = {item['name']: item['value'] for item in resp.json()}
        except (HTTPError, TypeError, KeyError, ValueError) as e:
            self.log.warning(
                'SUPPORTS_DYNAMIC: probe failed (%s), dynamic records '
                'disabled; set enable_dynamic=true to force',
                e,
            )
            return False
        lua_mode = config.get('enable-lua-records', '')
        if lua_mode not in ('yes', 'shared'):
            self.log.warning(
                'SUPPORTS_DYNAMIC: enable-lua-records=%r, dynamic records '
                'disabled; set enable_dynamic=true to force',
                lua_mode,
            )
            return False
        launch = [p.strip() for p in config.get('launch', '').split(',')]
        has_geoip = 'geoip' in launch or bool(
            config.get('geoip-database-files', '')
        )
        if not has_geoip:
            self.log.warning(
                'SUPPORTS_DYNAMIC: geoip backend not configured, dynamic '
                'records disabled; set enable_dynamic=true to force'
            )
            return False
        return True

    @property
    def soa_edit_api(self):
        # >>> [4, 4, 3] >= [4, 3]
        # True
        # >>> [4, 3, 3] >= [4, 3]
        # True
        # >>> [4, 1, 3] >= [4, 3]
        # False
        return self._soa_edit_api

    @soa_edit_api.setter
    def soa_edit_api(self, value):
        settings = {
            'default',
            'increase',
            'epoch',
            'soa-edit',
            'soa-edit-increase',
        }

        if value in settings:
            self._soa_edit_api = value
        else:
            raise ValueError(
                f'invalid soa_edit_api, "{value}" - available values: {settings}'
            )

    @property
    def mode_of_operation(self):
        if self._mode_of_operation is None:
            # start with what we were passed as a provider arg
            value = self._mode_of_operation_arg
            # we previously validated things against
            # POWERDNS_MODES_OF_OPERATION, the newer/larger set. If we're
            # running an (much) older version we need to check against the
            # reduced set of options now that we can get the version
            if (
                self.powerdns_version < [4, 5]
                and value not in self.POWERDNS_LEGACY_MODES_OF_OPERATION
            ):
                raise ValueError(
                    f'invalid mode_of_operation "{value}" - available values: {self.POWERDNS_LEGACY_MODES_OF_OPERATION}'
                )
            # we have a value we can now confidentily use
            self._mode_of_operation = value

        return self._mode_of_operation

    @property
    def check_status_not_found(self):
        # >=4.2.x returns 404 when not found
        return self.powerdns_version >= [4, 2]

    def list_zones(self):
        self.log.debug('list_zones:')
        resp = self._get('zones')
        return sorted([z['name'] for z in resp.json()])

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )
        encoded_name = _encode_zone_name(zone.name)
        resp = None
        try:
            resp = self._get(f'zones/{encoded_name}')
            self.log.debug('populate:   loaded')
        except HTTPError as e:
            error = self._get_error(e)
            if e.response.status_code == 401:
                # Nicer error message for auth problems
                raise Exception(f'PowerDNS unauthorized host={self.host}')
            elif e.response.status_code == 404 and self.check_status_not_found:
                # 404 means powerdns doesn't know anything about the requested
                # domain. We'll just ignore it here and leave the zone
                # untouched.
                pass
            elif (
                e.response.status_code == 422
                and error.startswith('Could not find domain ')
                and not self.check_status_not_found
            ):
                # 422 means powerdns doesn't know anything about the requested
                # domain. We'll just ignore it here and leave the zone
                # untouched.
                pass
            else:
                # just re-throw
                raise

        before = len(zone.records)
        exists = False

        if resp:
            exists = True
            rrsets = []
            for pdns_rrset in resp.json()['rrsets']:
                _type = pdns_rrset['type']
                if _type == 'LUA':
                    if PowerDnsLuaRecord._type not in self.SUPPORTS:
                        continue
                    # a "LUA" rrset may be an octoDNS dynamic record in
                    # disguise; if so it's handled directly since it doesn't
                    # have a 1:1 rrset/record type mapping like everything
                    # else does
                    data = self._data_for_dynamic(pdns_rrset)
                    if data is not None:
                        record_name = zone.hostname_from_fqdn(
                            pdns_rrset['name']
                        )
                        record = Record.new(
                            zone,
                            record_name,
                            data,
                            source=self,
                            lenient=lenient,
                        )
                        zone.add_record(record, lenient=lenient)
                        continue
                    _type = PowerDnsLuaRecord._type
                elif _type not in self.SUPPORTS:
                    continue
                rrsets.append(
                    Rrset(
                        pdns_rrset['name'],
                        _type,
                        pdns_rrset['ttl'],
                        [r['content'] for r in pdns_rrset['records']],
                    )
                )

            for record in Record.from_rrsets(
                zone, rrsets, lenient=lenient, source=self
            ):
                zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _rrset_for(self, record):
        if getattr(record, 'dynamic', None):
            # dynamic A/AAAA/CNAME records are always stored as a single
            # "LUA" rrset carrying the octodns-dynamic marker; they don't
            # have a 1:1 rrset/record type mapping like everything else does
            script = _dynamic_encode(record)
            content = f'{record._type} "{script}"'
            return Rrset(record.fqdn, 'LUA', record.ttl, [content])
        rrset = record.to_rrset()
        if rrset._type == PowerDnsLuaRecord._type:
            # octoDNS type name -> PowerDNS rrset type
            return Rrset(rrset.name, 'LUA', rrset.ttl, rrset.rdatas)
        return rrset

    def _records_for(self, record):
        rrset = self._rrset_for(record)
        records = [
            {'content': rdata, 'disabled': False} for rdata in rrset.rdatas
        ]
        return records, rrset._type

    def _mod_Create(self, change):
        new = change.new
        records, _type = self._records_for(new)
        return {
            'name': new.fqdn,
            'type': _type,
            'ttl': new.ttl,
            'changetype': 'REPLACE',
            'records': records,
        }

    def _mod_Update(self, change):
        new_records, new_type = self._records_for(change.new)
        _, existing_type = self._records_for(change.existing)
        replace = {
            'name': change.new.fqdn,
            'type': new_type,
            'ttl': change.new.ttl,
            'changetype': 'REPLACE',
            'records': new_records,
        }
        # When the backing rrset type changes (e.g. a static A becoming a
        # dynamic A, which is stored as an LUA rrset), the old rrset has to
        # be explicitly deleted — a REPLACE on the new type leaves the old
        # rrset alone.
        if existing_type != new_type:
            return [
                {
                    'name': change.existing.fqdn,
                    'type': existing_type,
                    'changetype': 'DELETE',
                },
                replace,
            ]
        return replace

    def _mod_Delete(self, change):
        existing = change.existing
        records, _type = self._records_for(existing)
        return {
            'name': existing.fqdn,
            'type': _type,
            'ttl': existing.ttl,
            'changetype': 'DELETE',
            'records': records,
        }

    def _get_error(self, http_error):
        try:
            return http_error.response.json()['error']
        except Exception:
            return ''

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        encoded_name = _encode_zone_name(desired.name)
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        mods = []
        for change in changes:
            class_name = change.__class__.__name__
            result = getattr(self, f'_mod_{class_name}')(change)
            if isinstance(result, list):
                mods.extend(result)
            else:
                mods.append(result)

        # Ensure that any DELETE modifications always occur before any REPLACE
        # modifications. This ensures that an A record can be replaced by a
        # CNAME record and vice-versa.
        mods.sort(key=itemgetter('changetype'))

        self.log.debug('_apply:   sending change request')

        try:
            self._patch(f'zones/{encoded_name}', data={'rrsets': mods})
            self.log.debug('_apply:   patched')
        except HTTPError as e:
            error = self._get_error(e)
            if not (
                (e.response.status_code == 404 and self.check_status_not_found)
                or (
                    e.response.status_code == 422
                    and error.startswith('Could not find domain ')
                    and not self.check_status_not_found
                )
            ):
                self.log.error(
                    '_apply:   status=%d, text=%s',
                    e.response.status_code,
                    e.response.text,
                )
                raise

            self.log.info('_apply:   creating zone=%s', desired.name)
            # 404 or 422 means powerdns doesn't know anything about the
            # requested domain. We'll try to create it with the correct
            # records instead of update. Hopefully all the mods are
            # creates :-)
            data = {
                'name': desired.name,
                'kind': self.mode_of_operation,
                'masters': [],
                'nameservers': [],
                'rrsets': mods,
                'soa_edit_api': self.soa_edit_api,
                'serial': 0,
            }
            try:
                self._post('zones', data)
            except HTTPError as e:
                self.log.error(
                    '_apply:   status=%d, text=%s',
                    e.response.status_code,
                    e.response.text,
                )
                raise
            self.log.debug('_apply:   created')

        if self.notify:
            self._request_notify(encoded_name)

        self.log.debug('_apply:   complete')

    def _request_notify(self, zoneid):
        self.log.debug('_request_notify: requesting notification: %s', zoneid)
        self._put(f'zones/{zoneid}/notify')


class PowerDnsProvider(PowerDnsBaseProvider):
    def __init__(
        self,
        id,
        host,
        api_key,
        port=8081,
        nameserver_values=None,
        nameserver_ttl=None,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f'PowerDnsProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, host=%s, port=%d, '
            'nameserver_values=%s, nameserver_ttl=%s',
            id,
            host,
            port,
            nameserver_values,
            nameserver_ttl,
        )
        super().__init__(
            id, host=host, api_key=api_key, port=port, *args, **kwargs
        )

        if nameserver_values or nameserver_ttl:
            raise ProviderException(
                'nameserver_values parameter no longer '
                'supported; migrate root NS records to '
                'sources; see CHANGELOG.md'
            )
