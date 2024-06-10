#
#
#

from json import dumps, loads
from logging import getLogger
from os.path import dirname, join
from unittest import TestCase

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider import ProviderException
from octodns.provider.yaml import YamlProvider
from octodns.record import Record, ValidationError
from octodns.record.rr import RrParseError
from octodns.zone import Zone

from octodns_powerdns import (
    PowerDnsBaseProvider,
    PowerDnsProvider,
    _escape_unescaped_semicolons,
)
from octodns_powerdns.record import PowerDnsLuaRecord, _PowerDnsLuaValue

EMPTY_TEXT = '''
{
    "account": "",
    "dnssec": false,
    "id": "xunit.tests.",
    "kind": "Master",
    "last_check": 0,
    "masters": [],
    "mode_of_operation": "master",
    "name": "xunit.tests.",
    "notified_serial": 0,
    "rrsets": [],
    "serial": 2017012801,
    "soa_edit": "",
    "soa_edit_api": "default",
    "url": "api/v1/servers/localhost/zones/xunit.tests."
}
'''

with open('./tests/fixtures/powerdns-full-data.json') as fh:
    FULL_TEXT = fh.read()


class TestPowerDnsProvider(TestCase):
    def test_provider_version_detection(self):
        # Bad auth
        with requests_mock() as mock:
            mock.get(ANY, status_code=401, text='Unauthorized')

            with self.assertRaises(Exception) as ctx:
                provider = PowerDnsProvider('test', 'non.existent', 'api-key')
                provider.powerdns_version
            self.assertTrue('unauthorized' in str(ctx.exception))

        # Api not found
        with requests_mock() as mock:
            mock.get(ANY, status_code=404, text='Not Found')

            with self.assertRaises(Exception) as ctx:
                provider = PowerDnsProvider('test', 'non.existent', 'api-key')
                provider.powerdns_version
            self.assertTrue('404' in str(ctx.exception))

        # Test version detection
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.1.10"},
            )
            provider = PowerDnsProvider('test', 'non.existent', 'api-key')
            self.assertEqual(provider.powerdns_version, [4, 1, 10])

        # Test version detection for second time (should stay at 4.1.10)
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.2.0"},
            )
            self.assertEqual(provider.powerdns_version, [4, 1, 10])

        # Test version detection
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.2.0"},
            )

            # Reset version, so detection will try again
            provider._powerdns_version = None
            self.assertNotEqual(provider.powerdns_version, [4, 1, 10])

        # Test version detection with pre-releases
        with requests_mock() as mock:
            # Reset version, so detection will try again
            provider._powerdns_version = None
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.4.0-alpha1"},
            )
            self.assertEqual(provider.powerdns_version, [4, 4, 0])

            provider._powerdns_version = None
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.5.0-alpha0.435.master.gcb114252b"},
            )
            self.assertEqual(provider.powerdns_version, [4, 5, 0])

    def test_provider_version_config(self):
        # Test version 4.1.0
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.1.10"},
            )
            provider = PowerDnsProvider('test', 'non.existent', 'api-key')
            self.assertEqual(provider.soa_edit_api, 'default')
            self.assertEqual(provider.mode_of_operation, 'master')
            self.assertFalse(
                provider.check_status_not_found,
                'check_status_not_found should be false '
                'for version 4.1.x and below',
            )

        # Test version 4.2.0
        provider._powerdns_version = None
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.2.0"},
            )
            self.assertEqual(provider.soa_edit_api, 'default')
            self.assertEqual(provider.mode_of_operation, 'master')
            self.assertTrue(
                provider.check_status_not_found,
                'check_status_not_found should be true for version 4.2.x',
            )

        # Test version 4.3.0
        provider._powerdns_version = None
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.3.0"},
            )
            provider = PowerDnsProvider(
                'test',
                'non.existent',
                'api-key',
                soa_edit_api="soa-edit",
                mode_of_operation="slave",
            )
            self.assertEqual(provider.soa_edit_api, 'soa-edit')
            self.assertEqual(provider.mode_of_operation, 'slave')
            self.assertTrue(
                provider.check_status_not_found,
                'check_status_not_found should be true for version 4.3.x',
            )

        # Test version 4.5.0
        # mode_of_operation primary preffered over master and secondary prefered over slave.
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.5.0"},
            )
            provider = PowerDnsProvider(
                'test',
                'non.existent',
                'api-key',
                soa_edit_api="epoch",
                mode_of_operation="primary",
            )
            self.assertEqual(provider.soa_edit_api, 'epoch')
            self.assertEqual(provider.mode_of_operation, 'primary')
            self.assertTrue(
                provider.check_status_not_found,
                'check_status_not_found should be true for version 4.5.x',
            )

    def test_managed_attribute_validation(self):
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.2.0"},
            )

            with self.assertRaises(ValueError) as ctx:
                PowerDnsProvider(
                    'test',
                    'non.existent',
                    'api-key',
                    soa_edit_api='inception-increment',
                )
            self.assertTrue('invalid soa_edit_api', str(ctx.exception))

            # "Primary" is available since pdns v4.5
            with self.assertRaises(ValueError) as ctx:
                provider = PowerDnsProvider(
                    'test',
                    'non.existent',
                    'api-key',
                    mode_of_operation='primary',
                )
                provider.mode_of_operation()
            self.assertTrue('invalid mode_of_operation' in str(ctx.exception))

            # "foo" is never a valid option
            with self.assertRaises(ValueError) as ctx:
                provider = PowerDnsProvider(
                    'test', 'non.existent', 'api-key', mode_of_operation='foo'
                )
            self.assertTrue('invalid mode_of_operation' in str(ctx.exception))

    def test_provider(self):
        # Test version detection
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8082/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.1.10"},
            )
            provider = PowerDnsProvider(
                'test',
                'non.existent',
                'api-key',
                strict_supports=False,
                # specifically testing a float here to make sure it doesn't
                # include the .1 when applied to the url
                port=8082.1,
            )
            self.assertEqual(provider.powerdns_version, [4, 1, 10])

        # Bad auth
        with requests_mock() as mock:
            mock.get(ANY, status_code=401, text='Unauthorized')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertTrue('unauthorized' in str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent zone in PowerDNS <4.3.0 doesn't populate anything
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=422,
                json={'error': "Could not find domain 'unit.tests.'"},
            )
            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(set(), zone.records)

        # Non-existent zone in PowerDNS >=4.2.0 doesn't populate anything

        provider._powerdns_version = [4, 2, 0]
        with requests_mock() as mock:
            mock.get(ANY, status_code=404, text='Not Found')
            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(set(), zone.records)

        provider._powerdns_version = [4, 1, 0]

        # The rest of this is messy/complicated b/c it's dealing with mocking

        expected = Zone('unit.tests.', [])
        source = YamlProvider(
            'test', join(dirname(__file__), 'config'), supports_root_ns=False
        )
        source.populate(expected)
        expected_n = len(expected.records) - 4
        self.assertEqual(25, expected_n)

        # No diffs == no changes
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text=FULL_TEXT)

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(25, len(zone.records))
            changes = expected.changes(zone, provider)
            self.assertEqual(0, len(changes))

        # Used in a minute
        def assert_rrsets_callback(request, context):
            data = loads(request.body)
            self.assertEqual(expected_n, len(data['rrsets']))
            return ''

        # No existing records -> creates for every record in expected
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text=EMPTY_TEXT)
            # post 201, is response to the create with data
            mock.patch(ANY, status_code=201, text=assert_rrsets_callback)

            plan = provider.plan(expected)
            self.assertEqual(expected_n, len(plan.changes))
            self.assertEqual(expected_n, provider.apply(plan))
            self.assertTrue(plan.exists)

        # Non-existent zone -> creates for every record in expected
        # OMG this is fucking ugly, probably better to ditch requests_mocks and
        # just mock things for real as it doesn't seem to provide a way to get
        # at the request params or verify that things were called from what I
        # can tell
        not_found = {'error': "Could not find domain 'unit.tests.'"}
        with requests_mock() as mock:
            # get 422's, unknown zone
            mock.get(ANY, status_code=422, text=dumps(not_found))
            # patch 422's, unknown zone
            mock.patch(ANY, status_code=422, text=dumps(not_found))
            # post 201, is response to the create with data
            mock.post(ANY, status_code=201, text=assert_rrsets_callback)

            plan = provider.plan(expected)
            self.assertEqual(expected_n, len(plan.changes))
            self.assertEqual(expected_n, provider.apply(plan))
            self.assertFalse(plan.exists)

        provider._powerdns_version = [4, 2, 0]
        with requests_mock() as mock:
            # get 404's, unknown zone
            mock.get(ANY, status_code=404, text='')
            # patch 404's, unknown zone
            mock.patch(ANY, status_code=404, text=dumps(not_found))
            # post 201, is response to the create with data
            mock.post(ANY, status_code=201, text=assert_rrsets_callback)

            plan = provider.plan(expected)
            self.assertEqual(expected_n, len(plan.changes))
            self.assertEqual(expected_n, provider.apply(plan))
            self.assertFalse(plan.exists)

        provider._powerdns_version = [4, 1, 0]
        with requests_mock() as mock:
            # get 422's, unknown zone
            mock.get(ANY, status_code=422, text=dumps(not_found))
            # patch 422's,
            data = {'error': "Key 'name' not present or not a String"}
            mock.patch(ANY, status_code=422, text=dumps(data))

            with self.assertRaises(HTTPError) as ctx:
                plan = provider.plan(expected)
                provider.apply(plan)
            response = ctx.exception.response
            self.assertEqual(422, response.status_code)
            self.assertTrue('error' in response.json())

        with requests_mock() as mock:
            # get 422's, unknown zone
            mock.get(ANY, status_code=422, text=dumps(not_found))
            # patch 500's, things just blew up
            mock.patch(ANY, status_code=500, text='')

            with self.assertRaises(HTTPError):
                plan = provider.plan(expected)
                provider.apply(plan)

        with requests_mock() as mock:
            # get 422's, unknown zone
            mock.get(ANY, status_code=422, text=dumps(not_found))
            # patch 500's, things just blew up
            mock.patch(ANY, status_code=422, text=dumps(not_found))
            # post 422's, something wrong with create
            mock.post(ANY, status_code=422, text='Hello Word!')

            with self.assertRaises(HTTPError):
                plan = provider.plan(expected)
                provider.apply(plan)

    def test_small_change(self):
        expected = Zone('unit.tests.', [])
        source = YamlProvider(
            'test', join(dirname(__file__), 'config'), supports_root_ns=False
        )
        source.populate(expected)
        self.assertEqual(29, len(expected.records))

        # A small change to a single record
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text=FULL_TEXT)
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': '4.1.0'},
            )
            provider = PowerDnsProvider(
                'test', 'non.existent', 'api-key', strict_supports=False
            )

            missing = Zone(expected.name, [])
            # Find and delete the SPF record
            for record in expected.records:
                if record._type != 'SPF':
                    missing.add_record(record)

            def assert_delete_callback(request, context):
                self.assertEqual(
                    {
                        'rrsets': [
                            {
                                'records': [
                                    {
                                        'content': '"v=spf1 ip4:192.168.0.1/16-all"',
                                        'disabled': False,
                                    }
                                ],
                                'changetype': 'DELETE',
                                'type': 'SPF',
                                'name': 'spf.unit.tests.',
                                'ttl': 600,
                            }
                        ]
                    },
                    loads(request.body),
                )
                return ''

            mock.patch(ANY, status_code=201, text=assert_delete_callback)

            plan = provider.plan(missing)
            self.assertEqual(1, len(plan.changes))
            self.assertEqual(1, provider.apply(plan))

    def test_notify(self):
        expected = Zone('unit.tests.', [])
        source = YamlProvider(
            'test', join(dirname(__file__), 'config'), supports_root_ns=False
        )
        source.populate(expected)

        # PUT /servers/{server_id}/zones/{zone_id}/notify should be invoked in apply()
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost/zones/unit.tests.',
                status_code=200,
                text=FULL_TEXT,
            )
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': '4.1.0'},
            )
            provider = PowerDnsProvider(
                'test',
                'non.existent',
                'api-key',
                strict_supports=False,
                notify=True,
            )

            missing = Zone(expected.name, [])
            # Find and delete the SPF record
            for record in expected.records:
                if record._type != 'SPF':
                    missing.add_record(record)

            plan = provider.plan(missing)
            self.assertEqual(1, len(plan.changes))

            def mock_notify(request, context):
                mock.put(
                    'http://non.existent:8081/api/v1/servers/localhost/zones/unit.tests./notify',
                    status_code=200,
                    text='',
                )
                return ''

            mock.patch(
                'http://non.existent:8081/api/v1/servers/localhost/zones/unit.tests.',
                status_code=204,
                text=mock_notify,  # PUT /notify is invoked after PATCHing the zone
            )

            self.assertEqual(1, provider.apply(plan))

    def test_nameservers_params(self):
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost',
                status_code=200,
                json={'version': "4.1.10"},
            )
            with self.assertRaises(ProviderException) as ctx:
                PowerDnsProvider(
                    'test',
                    'non.existent',
                    'api-key',
                    nameserver_values=['8.8.8.8.', '9.9.9.9.'],
                    nameserver_ttl=600,
                )
            self.assertTrue(
                str(ctx.exception).startswith(
                    'nameserver_values parameter no longer supported'
                )
            )

        class ChildProvider(PowerDnsBaseProvider):
            log = getLogger('ChildProvider')

            def _get_nameserver_record(self, *args, **kwargs):
                pass

        with self.assertRaises(ProviderException) as ctx:
            with requests_mock() as mock:
                mock.get(
                    'http://non.existent:8081/api/v1/servers/localhost',
                    status_code=200,
                    json={'version': "4.1.10"},
                )
                ChildProvider('text', 'non.existent', 'api-key')
            self.assertTrue(
                str(ctx.exception).startswith(
                    '_get_nameserver_record no longer supported;'
                )
            )

    def test_unescaped_semicolon(self):
        # no escapes
        self.assertEqual('', _escape_unescaped_semicolons(''))
        self.assertEqual('hello', _escape_unescaped_semicolons('"hello"'))
        self.assertEqual(
            'hello world!', _escape_unescaped_semicolons('"hello world!"')
        )

        # good
        self.assertEqual('\\;', _escape_unescaped_semicolons('"\\;"'))
        self.assertEqual('foo\\;', _escape_unescaped_semicolons('"foo\\;"'))
        self.assertEqual(
            'foo\\; bar\\;', _escape_unescaped_semicolons('"foo\\; bar\\;"')
        )
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('"foo\\; bar\\; baz\\;"'),
        )

        # missing
        self.assertEqual('\\;', _escape_unescaped_semicolons('";"'))
        self.assertEqual('foo\\;', _escape_unescaped_semicolons('"foo;"'))
        self.assertEqual(
            'foo\\; bar\\;', _escape_unescaped_semicolons('"foo; bar;"')
        )
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('"foo; bar; baz;"'),
        )

        # partial
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('"foo; bar\\; baz;"'),
        )

        # double escaped, left alone
        self.assertEqual('foo\\\\;', _escape_unescaped_semicolons('"foo\\\\;"'))

        # double ;;
        self.assertEqual(
            'foo\\;\\;', _escape_unescaped_semicolons('"foo\\;\\;"')
        )
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('"foo;\\;"'))
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('"foo\\;;"'))
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('"foo;;"'))

    def test_list_zones(self):
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=200,
                json=[
                    {'other': 'stuff', 'name': 'zeta.net.'},
                    {'some': 42, 'name': 'alpha.com.'},
                ],
            )
            provider = PowerDnsProvider(
                'test', 'non.existent', 'api-key', strict_supports=False
            )
            self.assertEqual(['alpha.com.', 'zeta.net.'], provider.list_zones())

    def test_data_for_DS_compat(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')

        rrset = {
            'records': [{'content': 'one two three four'}],
            'ttl': 42,
            'type': 'DS',
        }

        # old
        provider.OLD_DS_FIELDS = True
        value = provider._data_for('DS', rrset)['value']
        self.assertEqual(
            {
                'algorithm': 'three',
                'flags': 'one',
                'protocol': 'two',
                'public_key': 'four',
            },
            value,
        )

        # new
        provider.OLD_DS_FIELDS = False
        value = provider._data_for('DS', rrset)['value']
        self.assertEqual(
            {
                'algorithm': 'two',
                'digest': 'four',
                'digest_type': 'three',
                'key_tag': 'one',
            },
            value,
        )


class TestPowerDnsLuaRecord(TestCase):
    def test_basics(self):
        zone = Zone('unit.tests.', [])

        # no value(s)
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                'lua',
                {'type': PowerDnsLuaRecord._type, 'ttl': 42, 'values': []},
            )
        self.assertEqual(
            'at least one value required', ctx.exception.reasons[0]
        )

        # value missing type
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                'lua',
                {
                    'type': PowerDnsLuaRecord._type,
                    'ttl': 42,
                    'value': {'script': ''},
                },
            )
        self.assertEqual('missing type', ctx.exception.reasons[0])

        # value missing script
        with self.assertRaises(ValidationError) as ctx:
            Record.new(
                zone,
                'lua',
                {
                    'type': PowerDnsLuaRecord._type,
                    'ttl': 42,
                    'value': {'type': 'A'},
                },
            )
        self.assertEqual('missing script', ctx.exception.reasons[0])

        # valid record with a single value
        lua = Record.new(
            zone,
            'lua',
            {
                'type': PowerDnsLuaRecord._type,
                'ttl': 42,
                'value': {'script': '1.2.3.4', 'type': 'A'},
            },
        )
        self.assertEqual(
            {
                'ttl': 42,
                'value': _PowerDnsLuaValue({'script': '1.2.3.4', 'type': 'A'}),
            },
            lua.data,
        )

        # valid record with a multiple values
        luas = Record.new(
            zone,
            'lua',
            {
                'type': PowerDnsLuaRecord._type,
                'ttl': 42,
                'values': [
                    _PowerDnsLuaValue({'script': '1.2.3.4', 'type': 'A'}),
                    _PowerDnsLuaValue({'script': 'fc00::42', 'type': 'AAAA'}),
                ],
            },
        )
        self.assertEqual(
            {
                'ttl': 42,
                'values': [
                    _PowerDnsLuaValue({'script': '1.2.3.4', 'type': 'A'}),
                    _PowerDnsLuaValue({'script': 'fc00::42', 'type': 'AAAA'}),
                ],
            },
            luas.data,
        )

        # smoke tests
        lua.__repr__()
        hash(lua.values[0])

    def test_lua_parse_rdata_text(self):
        self.assertEqual(
            {'script': '1.2.3.4', 'type': 'A'},
            _PowerDnsLuaValue.parse_rdata_text('A "1.2.3.4"'),
        )

        with self.assertRaises(RrParseError):
            _PowerDnsLuaValue.parse_rdata_text('A'),

    def test_lua_validate(self):
        val = {'type': 'A', 'script': ''}
        # single value
        self.assertFalse(
            _PowerDnsLuaValue.validate(val, PowerDnsLuaRecord._type)
        )
        # tuple of values
        self.assertFalse(
            _PowerDnsLuaValue.validate((val), PowerDnsLuaRecord._type)
        )
        # list of values
        self.assertFalse(
            _PowerDnsLuaValue.validate([val, val], PowerDnsLuaRecord._type)
        )

        # list w/a bad value
        got = _PowerDnsLuaValue.validate([val, {}], PowerDnsLuaRecord._type)
        self.assertEqual(['missing type', 'missing script'], got)
