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
from octodns.zone import Zone

from octodns_powerdns import (
    PowerDnsBaseProvider,
    PowerDnsProvider,
    _encode_zone_name,
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

    def test_server_id(self):
        # Default server_id is "localhost"
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        self.assertEqual(provider.server_id, 'localhost')

        # Custom server_id is used in the API URL
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/custom-id',
                status_code=200,
                json={'version': "4.5.0"},
            )
            provider = PowerDnsProvider(
                'test', 'non.existent', 'api-key', server_id='custom-id'
            )
            self.assertEqual(provider.server_id, 'custom-id')
            self.assertEqual(provider.powerdns_version, [4, 5, 0])

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
        self.assertEqual(26, expected_n)

        # No diffs == no changes
        with requests_mock() as mock:
            mock.get(ANY, status_code=200, text=FULL_TEXT)

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(26, len(zone.records))
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
        self.assertEqual(30, len(expected.records))

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
                if record._type != 'SVCB':
                    missing.add_record(record)

            def assert_delete_callback(request, context):
                self.assertEqual(
                    {
                        'rrsets': [
                            {
                                'records': [
                                    {
                                        'content': '1 www.unit.tests.',
                                        'disabled': False,
                                    },
                                    {
                                        'content': '2 backups.unit.tests.',
                                        'disabled': False,
                                    },
                                ],
                                'changetype': 'DELETE',
                                'type': 'SVCB',
                                'name': 'svcb.unit.tests.',
                                'ttl': 3600,
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
                enable_dynamic=False,
            )

            missing = Zone(expected.name, [])
            # Find and delete the SPF record
            for record in expected.records:
                if record._type != 'SVCB':
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
        self.assertEqual('hello', _escape_unescaped_semicolons('hello'))
        self.assertEqual(
            'hello world!', _escape_unescaped_semicolons('hello world!')
        )

        # good
        self.assertEqual('\\;', _escape_unescaped_semicolons('\\;'))
        self.assertEqual('foo\\;', _escape_unescaped_semicolons('foo\\;'))
        self.assertEqual(
            'foo\\; bar\\;', _escape_unescaped_semicolons('foo\\; bar\\;')
        )
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('foo\\; bar\\; baz\\;'),
        )

        # missing
        self.assertEqual('\\;', _escape_unescaped_semicolons(';'))
        self.assertEqual('foo\\;', _escape_unescaped_semicolons('foo;'))
        self.assertEqual(
            'foo\\; bar\\;', _escape_unescaped_semicolons('foo; bar;')
        )
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('foo; bar; baz;'),
        )

        # partial
        self.assertEqual(
            'foo\\; bar\\; baz\\;',
            _escape_unescaped_semicolons('foo; bar\\; baz;'),
        )

        # double escaped, left alone
        self.assertEqual('foo\\\\;', _escape_unescaped_semicolons('foo\\\\;'))

        # double ;;
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('foo\\;\\;'))
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('foo;\\;'))
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('foo\\;;'))
        self.assertEqual('foo\\;\\;', _escape_unescaped_semicolons('foo;;'))

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

        # new
        value = provider._data_for_DS(rrset)['values'][0]
        self.assertEqual(
            {
                'algorithm': 'two',
                'digest': 'four',
                'digest_type': 'three',
                'key_tag': 'one',
            },
            value,
        )

    def test_records_for_DS_compat(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')

        class DummyRecord:
            _type = 'DS'

            def __init__(self, value):
                self.values = [value]

        class NewFields:
            key_tag = 'key_tag'
            algorithm = 'algorithm'
            digest_type = 'digest_type'
            digest = 'digest'

        new_fields = NewFields()

        # new
        data = provider._records_for_DS(DummyRecord(new_fields))[0]
        self.assertEqual(
            [
                {
                    'content': 'key_tag algorithm digest_type digest',
                    'disabled': False,
                }
            ],
            data,
        )

    def _dynamic_a(self, name='www', default='5.5.5.5'):
        zone = Zone('unit.tests.', [])
        return Record.new(
            zone,
            name,
            {
                'type': 'A',
                'ttl': 60,
                'values': [default],
                'dynamic': {
                    'pools': {
                        'eu': {'values': [{'value': '1.1.1.1'}]},
                        'default': {'values': [{'value': default}]},
                    },
                    'rules': [
                        {'geos': ['EU'], 'pool': 'eu'},
                        {'pool': 'default'},
                    ],
                },
            },
        )

    def test_records_for_dynamic_A(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        record = self._dynamic_a()
        records, _type = provider._records_for_A(record)
        self.assertEqual('LUA', _type)
        self.assertEqual(1, len(records))
        self.assertTrue(records[0]['content'].startswith('A "'))
        self.assertIn('octodns-dynamic:v1:', records[0]['content'])

    def test_records_for_dynamic_CNAME(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            'www',
            {
                'type': 'CNAME',
                'ttl': 60,
                'value': 'default.example.com.',
                'dynamic': {
                    'pools': {
                        'eu': {'values': [{'value': 'eu.example.com.'}]},
                        'default': {
                            'values': [{'value': 'default.example.com.'}]
                        },
                    },
                    'rules': [
                        {'geos': ['EU'], 'pool': 'eu'},
                        {'pool': 'default'},
                    ],
                },
            },
        )
        records, _type = provider._records_for_CNAME(record)
        self.assertEqual('LUA', _type)
        self.assertTrue(records[0]['content'].startswith('CNAME "'))

    def test_records_for_CNAME_static(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        zone = Zone('unit.tests.', [])
        record = Record.new(
            zone,
            'alias',
            {'type': 'CNAME', 'ttl': 60, 'value': 'target.example.com.'},
        )
        records, _type = provider._records_for_CNAME(record)
        self.assertEqual('CNAME', _type)
        self.assertEqual('target.example.com.', records[0]['content'])

    def test_data_for_LUA_dynamic_marker(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        record = self._dynamic_a()
        records, _ = provider._records_for_A(record)
        rrset = {
            'name': 'www.unit.tests.',
            'type': 'LUA',
            'ttl': 60,
            'records': records,
        }
        data = provider._data_for_LUA(rrset)
        self.assertEqual('A', data['type'])
        self.assertEqual(60, data['ttl'])
        self.assertIn('dynamic', data)
        self.assertEqual(['5.5.5.5'], data['values'])

    def test_data_for_LUA_single_no_marker_falls_back(self):
        # Single-record LUA with a qtype we support but no octodns marker —
        # should fall through to the PowerDnsLuaRecord path.
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        rrset = {
            'name': 'lua.unit.tests.',
            'type': 'LUA',
            'ttl': 60,
            'records': [
                {'content': 'A ";return \'1.2.3.4\'"', 'disabled': False}
            ],
        }
        data = provider._data_for_LUA(rrset)
        self.assertEqual(PowerDnsLuaRecord._type, data['type'])

    def test_data_for_LUA_single_unsupported_qtype_falls_back(self):
        # Single-record LUA for a qtype we don't translate dynamically —
        # should also fall through.
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        rrset = {
            'name': 'lua.unit.tests.',
            'type': 'LUA',
            'ttl': 60,
            'records': [
                {'content': 'TXT "return \'hello\'"', 'disabled': False}
            ],
        }
        data = provider._data_for_LUA(rrset)
        self.assertEqual(PowerDnsLuaRecord._type, data['type'])

    def test_mod_Update_same_rrset_type(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        zone = Zone('unit.tests.', [])
        existing = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 60, 'values': ['1.1.1.1']}
        )
        new = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 60, 'values': ['2.2.2.2']}
        )
        from octodns.record.change import Update

        mod = provider._mod_Update(Update(existing, new))
        self.assertIsInstance(mod, dict)
        self.assertEqual('A', mod['type'])
        self.assertEqual('REPLACE', mod['changetype'])

    def test_mod_Update_rrset_type_change_emits_delete(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        zone = Zone('unit.tests.', [])
        existing = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 60, 'values': ['1.1.1.1']}
        )
        new = self._dynamic_a()
        from octodns.record.change import Update

        mods = provider._mod_Update(Update(existing, new))
        self.assertIsInstance(mods, list)
        self.assertEqual(2, len(mods))
        delete, replace = mods
        self.assertEqual('DELETE', delete['changetype'])
        self.assertEqual('A', delete['type'])
        self.assertEqual('REPLACE', replace['changetype'])
        self.assertEqual('LUA', replace['type'])

    def test_apply_flattens_list_mods(self):
        # Exercise _apply's list-flatten branch via an Update whose backing
        # rrset type changes (static A → dynamic A → LUA rrset).
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        zone = Zone('unit.tests.', [])
        existing = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 60, 'values': ['1.1.1.1']}
        )
        new = self._dynamic_a()
        from octodns.provider.plan import Plan
        from octodns.record.change import Update

        plan = Plan(
            existing=zone,
            desired=zone,
            changes=[Update(existing, new)],
            exists=True,
        )

        captured = {}

        def patch_callback(request, context):
            captured['body'] = loads(request.body)
            return ''

        with requests_mock() as mock:
            mock.patch(ANY, status_code=204, text=patch_callback)
            provider._apply(plan)

        rrsets = captured['body']['rrsets']
        # Expect both a DELETE (for the old A rrset) and a REPLACE (for the
        # new LUA rrset) in the same PATCH.
        types = {(r['changetype'], r['type']) for r in rrsets}
        self.assertIn(('DELETE', 'A'), types)
        self.assertIn(('REPLACE', 'LUA'), types)

    def _config_payload(self, **overrides):
        config = {
            'enable-lua-records': 'shared',
            'launch': 'gmysql,geoip',
            'geoip-database-files': 'mmdb:/etc/powerdns/test.mmdb',
        }
        config.update(overrides)
        return [{'name': k, 'value': v} for k, v in config.items()]

    def test_supports_dynamic_probe_success(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(
                'http://non.existent:8081/api/v1/servers/localhost/config',
                status_code=200,
                json=self._config_payload(),
            )
            self.assertTrue(provider.SUPPORTS_DYNAMIC)
        # Second access is cached — no new request needed.
        self.assertTrue(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_probe_lua_yes(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=200,
                json=self._config_payload(**{'enable-lua-records': 'yes'}),
            )
            self.assertTrue(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_probe_lua_disabled(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=200,
                json=self._config_payload(**{'enable-lua-records': 'no'}),
            )
            self.assertFalse(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_probe_no_geoip(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=200,
                json=self._config_payload(
                    launch='gmysql', **{'geoip-database-files': ''}
                ),
            )
            self.assertFalse(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_probe_geoip_via_database_files(self):
        # launch= doesn't list geoip explicitly, but geoip-database-files is
        # set — still counts as geoip-capable.
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(
                ANY, status_code=200, json=self._config_payload(launch='gmysql')
            )
            self.assertTrue(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_probe_http_error(self):
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        with requests_mock() as mock:
            mock.get(ANY, status_code=401, text='Unauthorized')
            self.assertFalse(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_enable_dynamic_forced_true(self):
        # enable_dynamic=True skips the probe entirely.
        provider = PowerDnsProvider(
            'test', 'non.existent', 'api-key', enable_dynamic=True
        )
        self.assertTrue(provider.SUPPORTS_DYNAMIC)

    def test_supports_dynamic_enable_dynamic_forced_false(self):
        provider = PowerDnsProvider(
            'test', 'non.existent', 'api-key', enable_dynamic=False
        )
        self.assertFalse(provider.SUPPORTS_DYNAMIC)

    def test_dynamic_round_trip_via_rrset(self):
        # End-to-end codegen + parse: build a dynamic A, run it through
        # _records_for_A to produce the rrset content, then hand that rrset
        # back to _data_for_LUA and rebuild a record. The rebuilt record's
        # serialized form must match the original — that's the invariant
        # populate-after-apply relies on.
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        original = self._dynamic_a()
        records, _type = provider._records_for_A(original)
        rrset = {
            'name': original.fqdn,
            'type': _type,
            'ttl': original.ttl,
            'records': records,
        }
        data = provider._data_for_LUA(rrset)
        rebuilt = Record.new(Zone('unit.tests.', []), original.name, data)
        self.assertEqual(original._data(), rebuilt._data())

    def test_data_for_LUA_multi_record_legacy_path(self):
        # Multi-record LUA rrsets (the pre-dynamic PowerDnsLuaRecord use case)
        # are never decoded as dynamic, even if one of the entries happens to
        # look like a marker — the dynamic decoder only runs for single-entry
        # rrsets.
        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        rrset = {
            'name': 'lua.unit.tests.',
            'type': 'LUA',
            'ttl': 60,
            'records': [
                {'content': 'A ";return \'1.2.3.4\'"', 'disabled': False},
                {'content': 'AAAA ";return \'fc00::42\'"', 'disabled': False},
            ],
        }
        data = provider._data_for_LUA(rrset)
        self.assertEqual(PowerDnsLuaRecord._type, data['type'])
        self.assertEqual(2, len(data['values']))

    def test_data_for_LUA_malformed_marker_raises(self):
        # A content entry that starts with the dynamic marker but carries a
        # broken payload must raise ProviderException, not silently fall back
        # to PowerDnsLuaRecord — a corrupt marker is a bug, not a missing one.
        from octodns_powerdns.dynamic import DYNAMIC_MARKER

        provider = PowerDnsProvider('test', 'non.existent', 'api-key')
        broken = f'A ";{DYNAMIC_MARKER}AAAA"'
        rrset = {
            'name': 'www.unit.tests.',
            'type': 'LUA',
            'ttl': 60,
            'records': [{'content': broken, 'disabled': False}],
        }
        with self.assertRaises(ProviderException):
            provider._data_for_LUA(rrset)


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

    def test_encode_zone_name(self):
        for expected, value in (
            ('unit.tests.', 'unit.tests.'),
            ('another_one.unit.tests.', 'another_one.unit.tests.'),
            ('128=2F26.2.0.192.in-addr.arpa.', '128/26.2.0.192.in-addr.arpa.'),
        ):
            self.assertEqual(expected, _encode_zone_name(value))
