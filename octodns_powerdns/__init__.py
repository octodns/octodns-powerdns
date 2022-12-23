#
#
#

from requests import HTTPError, Session
from operator import itemgetter
import logging

from octodns.record import Record
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider

from .record import PowerDnsLuaRecord

__VERSION__ = '0.0.3'


def _escape_unescaped_semicolons(value):
    pieces = value.split(';')
    if len(pieces) == 1:
        return value
    last = pieces.pop()
    joined = ';'.join([p if p and p[-1] == '\\' else f'{p}\\' for p in pieces])
    ret = f'{joined};{last}'
    return ret


class PowerDnsBaseProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'LOC',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'SPF',
            'SSHFP',
            'SRV',
            'TLSA',
            'TXT',
            PowerDnsLuaRecord._type,
        )
    )
    TIMEOUT = 5

    def __init__(
        self,
        id,
        host,
        api_key,
        port=8081,
        scheme="http",
        timeout=TIMEOUT,
        soa_edit_api='default',
        mode_of_operation='master',
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
        self.port = port
        self.scheme = scheme
        self.timeout = timeout

        self._powerdns_version = None

        sess = Session()
        sess.headers.update({'X-API-Key': api_key})
        self._sess = sess

        self.soa_edit_api = soa_edit_api
        self.mode_of_operation = mode_of_operation

    def _request(self, method, path, data=None):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = (
            f'{self.scheme}://{self.host}:{self.port}/api/v1/servers/'
            f'localhost/{path}'.rstrip('/')
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

    def _patch(self, path, data=None):
        return self._request('PATCH', path, data=data)

    def _data_for_multiple(self, rrset):
        # TODO: geo not supported
        return {
            'type': rrset['type'],
            'values': [r['content'] for r in rrset['records']],
            'ttl': rrset['ttl'],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_NS = _data_for_multiple

    def _data_for_TLSA(self, rrset):
        values = []
        for record in rrset['records']:
            (
                certificate_usage,
                selector,
                matching_type,
                certificate_association_data,
            ) = record['content'].split(' ', 3)
            values.append(
                {
                    'certificate_usage': certificate_usage,
                    'selector': selector,
                    'matching_type': matching_type,
                    'certificate_association_data': certificate_association_data,
                }
            )
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_CAA(self, rrset):
        values = []
        for record in rrset['records']:
            flags, tag, value = record['content'].split(' ', 2)
            values.append({'flags': flags, 'tag': tag, 'value': value[1:-1]})
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_single(self, rrset):
        return {
            'type': rrset['type'],
            'value': rrset['records'][0]['content'],
            'ttl': rrset['ttl'],
        }

    _data_for_ALIAS = _data_for_single
    _data_for_CNAME = _data_for_single
    _data_for_PTR = _data_for_single

    def _data_for_quoted(self, rrset):
        return {
            'type': rrset['type'],
            'values': [
                _escape_unescaped_semicolons(r['content'][1:-1])
                for r in rrset['records']
            ],
            'ttl': rrset['ttl'],
        }

    _data_for_SPF = _data_for_quoted
    _data_for_TXT = _data_for_quoted

    def _data_for_LOC(self, rrset):
        values = []
        for record in rrset['records']:
            (
                lat_degrees,
                lat_minutes,
                lat_seconds,
                lat_direction,
                long_degrees,
                long_minutes,
                long_seconds,
                long_direction,
                altitude,
                size,
                precision_horz,
                precision_vert,
            ) = (record['content'].replace('m', '').split(' ', 11))
            values.append(
                {
                    'lat_degrees': int(lat_degrees),
                    'lat_minutes': int(lat_minutes),
                    'lat_seconds': float(lat_seconds),
                    'lat_direction': lat_direction,
                    'long_degrees': int(long_degrees),
                    'long_minutes': int(long_minutes),
                    'long_seconds': float(long_seconds),
                    'long_direction': long_direction,
                    'altitude': float(altitude),
                    'size': float(size),
                    'precision_horz': float(precision_horz),
                    'precision_vert': float(precision_vert),
                }
            )
        return {'ttl': rrset['ttl'], 'type': rrset['type'], 'values': values}

    def _data_for_MX(self, rrset):
        values = []
        for record in rrset['records']:
            preference, exchange = record['content'].split(' ', 1)
            values.append({'preference': preference, 'exchange': exchange})
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_NAPTR(self, rrset):
        values = []
        for record in rrset['records']:
            order, preference, flags, service, regexp, replacement = record[
                'content'
            ].split(' ', 5)
            values.append(
                {
                    'order': order,
                    'preference': preference,
                    'flags': flags[1:-1],
                    'service': service[1:-1],
                    'regexp': regexp[1:-1],
                    'replacement': replacement,
                }
            )
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_SSHFP(self, rrset):
        values = []
        for record in rrset['records']:
            algorithm, fingerprint_type, fingerprint = record['content'].split(
                ' ', 2
            )
            values.append(
                {
                    'algorithm': algorithm,
                    'fingerprint_type': fingerprint_type,
                    'fingerprint': fingerprint,
                }
            )
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_SRV(self, rrset):
        values = []
        for record in rrset['records']:
            priority, weight, port, target = record['content'].split(' ', 3)
            values.append(
                {
                    'priority': priority,
                    'weight': weight,
                    'port': port,
                    'target': target,
                }
            )
        return {'type': rrset['type'], 'values': values, 'ttl': rrset['ttl']}

    def _data_for_LUA(self, rrset):
        values = []
        for record in rrset['records']:
            _type, script = record['content'].split(' ', 1)
            values.append({'type': _type, 'script': script[1:-1]})
        return {
            'ttl': rrset['ttl'],
            'type': PowerDnsLuaRecord._type,
            'values': values,
        }

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
        settings = [
            "default",
            "increase",
            "epoch",
            "soa-edit",
            "soa-edit-increase",
        ]

        if value in settings:
            self._soa_edit_api = value
        else:
            raise ValueError(f'"soa_edit_api" - possibile values: {settings}')

    @property
    def mode_of_operation(self):
        return self._mode_of_operation

    @mode_of_operation.setter
    def mode_of_operation(self, value):
        if self.powerdns_version >= [4, 5]:
            settings = ["native", "primary", "secondary", "master", "slave"]
        else:
            settings = ["native", "master", "slave"]
        if value in settings:
            self._mode_of_operation = value
        else:
            raise ValueError(
                f'"mode_of_operation" - possible values: {settings}'
            )

    @property
    def check_status_not_found(self):
        # >=4.2.x returns 404 when not found
        return self.powerdns_version >= [4, 2]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        resp = None
        try:
            resp = self._get(f'zones/{zone.name}')
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
            for rrset in resp.json()['rrsets']:
                _type = rrset['type']
                _provider_specific_type = f'PowerDnsProvider/{_type}'
                if (
                    _type not in self.SUPPORTS
                    and _provider_specific_type not in self.SUPPORTS
                ):
                    continue
                data_for = getattr(self, f'_data_for_{_type}')
                record_name = zone.hostname_from_fqdn(rrset['name'])
                record = Record.new(
                    zone,
                    record_name,
                    data_for(rrset),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _records_for_multiple(self, record):
        return [
            {'content': v, 'disabled': False} for v in record.values
        ], record._type

    _records_for_A = _records_for_multiple
    _records_for_AAAA = _records_for_multiple
    _records_for_NS = _records_for_multiple

    def _records_for_TLSA(self, record):
        return [
            {
                'content': f'{v.certificate_usage} {v.selector} {v.matching_type} {v.certificate_association_data}',
                'disabled': False,
            }
            for v in record.values
        ], record._type

    def _records_for_CAA(self, record):
        return [
            {'content': f'{v.flags} {v.tag} "{v.value}"', 'disabled': False}
            for v in record.values
        ], record._type

    def _records_for_single(self, record):
        return [{'content': record.value, 'disabled': False}], record._type

    _records_for_ALIAS = _records_for_single
    _records_for_CNAME = _records_for_single
    _records_for_PTR = _records_for_single

    def _records_for_quoted(self, record):
        return [
            {'content': f'"{v}"', 'disabled': False} for v in record.values
        ], record._type

    _records_for_SPF = _records_for_quoted
    _records_for_TXT = _records_for_quoted

    def _records_for_LOC(self, record):
        return [
            {
                'content': '%d %d %0.3f %s %d %d %.3f %s %0.2fm %0.2fm %0.2fm %0.2fm'
                % (
                    int(v.lat_degrees),
                    int(v.lat_minutes),
                    float(v.lat_seconds),
                    v.lat_direction,
                    int(v.long_degrees),
                    int(v.long_minutes),
                    float(v.long_seconds),
                    v.long_direction,
                    float(v.altitude),
                    float(v.size),
                    float(v.precision_horz),
                    float(v.precision_vert),
                ),
                'disabled': False,
            }
            for v in record.values
        ], record._type

    def _records_for_MX(self, record):
        return [
            {'content': f'{v.preference} {v.exchange}', 'disabled': False}
            for v in record.values
        ], record._type

    def _records_for_NAPTR(self, record):
        return [
            {
                'content': f'{v.order} {v.preference} "{v.flags}" "{v.service}" '
                f'"{v.regexp}" {v.replacement}',
                'disabled': False,
            }
            for v in record.values
        ], record._type

    def _records_for_SSHFP(self, record):
        return [
            {
                'content': f'{v.algorithm} {v.fingerprint_type} {v.fingerprint}',
                'disabled': False,
            }
            for v in record.values
        ], record._type

    def _records_for_SRV(self, record):
        return [
            {
                'content': f'{v.priority} {v.weight} {v.port} {v.target}',
                'disabled': False,
            }
            for v in record.values
        ], record._type

    def _records_for_PowerDnsProvider_LUA(self, record):
        return [
            {'content': f'{v._type} "{v.script}"', 'disabled': False}
            for v in record.values
        ], 'LUA'

    def _mod_Create(self, change):
        new = change.new
        records_for = f'_records_for_{new._type}'.replace('/', '_')
        records_for = getattr(self, records_for)
        records = records_for(new)

        records, _type = records_for(new)
        return {
            'name': new.fqdn,
            'type': _type,
            'ttl': new.ttl,
            'changetype': 'REPLACE',
            'records': records,
        }

    _mod_Update = _mod_Create

    def _mod_Delete(self, change):
        existing = change.existing
        records_for = f'_records_for_{existing._type}'.replace('/', '_')
        records_for = getattr(self, records_for)
        records = records_for(existing)

        records, _type = records_for(existing)
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
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        mods = []
        for change in changes:
            class_name = change.__class__.__name__
            mods.append(getattr(self, f'_mod_{class_name}')(change))

        # Ensure that any DELETE modifications always occur before any REPLACE
        # modifications. This ensures that an A record can be replaced by a
        # CNAME record and vice-versa.
        mods.sort(key=itemgetter('changetype'))

        self.log.debug('_apply:   sending change request')

        try:
            self._patch(f'zones/{desired.name}', data={'rrsets': mods})
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

        self.log.debug('_apply:   complete')


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
