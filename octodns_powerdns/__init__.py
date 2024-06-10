#
#
#

import logging
from operator import itemgetter

from requests import HTTPError, Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record
from octodns.record.ds import DsValue

try:  # pragma: no cover
    from octodns.record.svcb import SvcbValue

    SUPPORTS_SVCB = True

    # quell warnings
    SvcbValue
except ImportError:  # pragma: no cover
    SUPPORTS_SVCB = False

from .record import PowerDnsLuaRecord

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.6'


def _escape_unescaped_semicolons(value):
    value = value[1:-1]
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
            'DS',
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
    # These are only supported if we have a new enough octoDNS core
    if SUPPORTS_SVCB:  # pragma: no cover
        SUPPORTS.add('HTTPS')
        SUPPORTS.add('SVCB')

    TIMEOUT = 5

    POWERDNS_MODES_OF_OPERATION = {
        'native',
        'primary',
        'secondary',
        'master',
        'slave',
    }
    POWERDNS_LEGACY_MODES_OF_OPERATION = {'native', 'master', 'slave'}

    # TODO: once we require octoDNS 2.0 this backwards compatibility code can go
    # away
    OLD_DS_FIELDS = hasattr(DsValue, 'flags')

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

        self._powerdns_version = None

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

        # doing this once here to "cache" thing, can't do it at the top level
        # b/c it can't see SUPPORTS
        self._rdata_parsers = {
            t: c._value_type.parse_rdata_text
            for t, c in Record.registered_types().items()
            if t in self.SUPPORTS
        }

        # PowerDNS semicolon handling differs from SPEC
        self._rdata_parsers['SPF'] = _escape_unescaped_semicolons
        self._rdata_parsers['TXT'] = _escape_unescaped_semicolons

        # TODO: once we require octoDNS 2.0 this backwards compatibility code
        # can go away
        self._rdata_parsers['DS'] = self._DS_parse_rdata_text_compat

    def _request(self, method, path, data=None):
        self.log.debug('_request: method=%s, path=%s', method, path)

        url = (
            f'{self.scheme}://{self.host}:{self.port:d}/api/v1/servers/'
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

    def _put(self, path, data=None):
        return self._request('PUT', path, data=data)

    def _patch(self, path, data=None):
        return self._request('PATCH', path, data=data)

    def _DS_parse_rdata_text_compat(self, value):
        ret = DsValue.parse_rdata_text(value)
        if self.OLD_DS_FIELDS:
            return {
                'flags': ret['key_tag'],
                'protocol': ret['algorithm'],
                'algorithm': ret['digest_type'],
                'public_key': ret['digest'],
            }
        return ret

    def _data_for(self, _type, rrset):
        rdata_parser = self._rdata_parsers[_type]
        records = rrset['records']
        if len(records) > 1:
            return {
                'type': _type,
                'values': [rdata_parser(r['content']) for r in records],
                'ttl': rrset['ttl'],
            }
        return {
            'type': _type,
            'value': rdata_parser(records[0]['content']),
            'ttl': rrset['ttl'],
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
                if _type == 'LUA':
                    _type = f'PowerDnsProvider/{_type}'
                elif _type not in self.SUPPORTS:
                    continue
                record_name = zone.hostname_from_fqdn(rrset['name'])
                record = Record.new(
                    zone,
                    record_name,
                    self._data_for(_type, rrset),
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

    def _records_for(self, record):
        if hasattr(record, 'values'):
            return [
                {'content': v.rdata_text, 'disabled': False}
                for v in record.values
            ], record._type
        return [
            {'content': record.value.rdata_text, 'disabled': False}
        ], record._type

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

    _mod_Update = _mod_Create

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

        if self.notify:
            self._request_notify(desired.name)

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
