#
#
#

from unittest import TestCase

from octodns.provider import ProviderException
from octodns.record import Record
from octodns.zone import Zone

from octodns_powerdns.dynamic import DYNAMIC_MARKER, decode, encode

ZONE = Zone('unit.tests.', [])


def _record(name='www', _type='A', values=None, dynamic=None, ttl=60):
    data = {'type': _type, 'ttl': ttl}
    if values is not None:
        if _type == 'CNAME':
            data['value'] = values[0]
        else:
            data['values'] = values
    if dynamic is not None:
        data['dynamic'] = dynamic
    return Record.new(ZONE, name, data)


def _simple_dynamic(default='5.5.5.5'):
    return {
        'pools': {
            'eu': {'values': [{'value': '1.1.1.1'}]},
            'default': {'values': [{'value': default}]},
        },
        'rules': [{'geos': ['EU'], 'pool': 'eu'}, {'pool': 'default'}],
    }


class TestDynamicEncode(TestCase):
    def test_catchall_only(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {'default': {'values': [{'value': '5.5.5.5'}]}},
                'rules': [{'pool': 'default'}],
            },
        )
        script = encode(rec)
        self.assertIn(DYNAMIC_MARKER, script)
        self.assertIn("return pickwhashed({{1, '5.5.5.5'}})", script)
        # no if/elseif when there are no conditional rules
        self.assertNotIn('if ', script)
        self.assertNotIn('elseif', script)
        self.assertNotIn('\nend', script)

    def test_continent_only(self):
        rec = _record(values=['5.5.5.5'], dynamic=_simple_dynamic())
        script = encode(rec)
        self.assertIn("if (continent('EU')) then", script)
        self.assertIn("return pickwhashed({{1, '1.1.1.1'}})", script)
        self.assertIn("return pickwhashed({{1, '5.5.5.5'}})", script)

    def test_country_level(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'gb': {'values': [{'value': '1.1.1.1'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['EU-GB'], 'pool': 'gb'},
                    {'pool': 'default'},
                ],
            },
        )
        script = encode(rec)
        # continent dropped in favour of country
        self.assertIn("if (country('GB')) then", script)
        self.assertNotIn("continent('EU')", script)

    def test_subdivision_level(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'cal': {'values': [{'value': '4.4.4.4'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['NA-US-CA'], 'pool': 'cal'},
                    {'pool': 'default'},
                ],
            },
        )
        script = encode(rec)
        self.assertIn("if (country('US') and region('CA')) then", script)

    def test_multi_geo_single_rule(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'emea': {'values': [{'value': '1.1.1.1'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['AF', 'EU'], 'pool': 'emea'},
                    {'pool': 'default'},
                ],
            },
        )
        script = encode(rec)
        # rules are sorted by core; AF comes before EU
        self.assertIn("if (continent('AF')) or (continent('EU')) then", script)

    def test_if_elseif_chain(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'eu': {'values': [{'value': '1.1.1.1'}]},
                    'af': {'values': [{'value': '2.2.2.2'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['EU'], 'pool': 'eu'},
                    {'geos': ['AF'], 'pool': 'af'},
                    {'pool': 'default'},
                ],
            },
        )
        script = encode(rec)
        lines = script.splitlines()
        # marker, if, elseif, end, return
        self.assertTrue(lines[0].startswith(f';{DYNAMIC_MARKER}'))
        self.assertTrue(lines[1].startswith('if '))
        self.assertTrue(lines[2].startswith('elseif '))
        self.assertEqual(lines[3], 'end')
        self.assertTrue(lines[4].startswith('return '))

    def test_fallback_chain_flattens(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'eu': {'values': [{'value': '1.1.1.1'}]},
                    'gb': {'values': [{'value': '3.3.3.3'}], 'fallback': 'eu'},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['EU-GB'], 'pool': 'gb'},
                    {'pool': 'default'},
                ],
            },
        )
        script = encode(rec)
        self.assertIn(
            "return pickwhashed({{1, '3.3.3.3'}, {1, '1.1.1.1'}})", script
        )

    def test_weighted_values(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'eu': {
                        'values': [
                            {'value': '1.1.1.1', 'weight': 3},
                            {'value': '2.2.2.2', 'weight': 7},
                        ]
                    },
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [{'geos': ['EU'], 'pool': 'eu'}, {'pool': 'default'}],
            },
        )
        script = encode(rec)
        self.assertIn("{3, '1.1.1.1'}", script)
        self.assertIn("{7, '2.2.2.2'}", script)

    def test_deterministic(self):
        rec = _record(values=['5.5.5.5'], dynamic=_simple_dynamic())
        self.assertEqual(encode(rec), encode(rec))

    def test_encode_without_dynamic_raises(self):
        rec = _record(values=['5.5.5.5'])
        with self.assertRaises(ProviderException) as ctx:
            encode(rec)
        self.assertIn('non-dynamic', str(ctx.exception))

    def test_encode_subnet_rule_raises(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'ten': {'values': [{'value': '1.1.1.1'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'subnets': ['10.0.0.0/8'], 'pool': 'ten'},
                    {'pool': 'default'},
                ],
            },
        )
        with self.assertRaises(ProviderException) as ctx:
            encode(rec)
        self.assertIn('subnet', str(ctx.exception))

    def test_encode_multiple_catchalls_raises(self):
        # Hand-craft a record then poke an extra catchall rule in — octoDNS
        # core rejects multiple catchalls at validation time, so we bypass
        # Record.new and mutate .dynamic directly.
        rec = _record(values=['5.5.5.5'], dynamic=_simple_dynamic())
        extra = type(rec.dynamic.rules[-1])(
            len(rec.dynamic.rules), {'pool': 'default'}
        )
        rec.dynamic.rules.append(extra)
        with self.assertRaises(ProviderException) as ctx:
            encode(rec)
        self.assertIn('catchall', str(ctx.exception))

    def test_encode_no_catchall_raises(self):
        # Core enforces a catchall, so bypass it by deleting the catchall
        # rule from an already-built record.
        rec = _record(values=['5.5.5.5'], dynamic=_simple_dynamic())
        rec.dynamic.rules = [r for r in rec.dynamic.rules if r.data.get('geos')]
        with self.assertRaises(ProviderException) as ctx:
            encode(rec)
        self.assertIn('catchall', str(ctx.exception))


class TestDynamicDecode(TestCase):
    def test_missing_marker_raises_value_error(self):
        with self.assertRaises(ValueError):
            decode('', 'A')
        with self.assertRaises(ValueError):
            decode('if continent("EU") then return "1.1.1.1" end', 'A')

    def test_malformed_base64(self):
        bad = f';{DYNAMIC_MARKER}!!!not-base64!!!'
        with self.assertRaises(ValueError):
            # `!` isn't matched by the marker regex, so we get ValueError
            # (missing marker) rather than ProviderException.
            decode(bad, 'A')

    def test_malformed_json(self):
        # valid base64 of 'not json'
        from base64 import urlsafe_b64encode

        payload = urlsafe_b64encode(b'not json').decode('ascii')
        with self.assertRaises(ProviderException):
            decode(f';{DYNAMIC_MARKER}{payload}', 'A')

    def test_missing_pools_rules(self):
        from base64 import urlsafe_b64encode
        from json import dumps

        payload = urlsafe_b64encode(dumps({'foo': 'bar'}).encode()).decode()
        with self.assertRaises(ProviderException) as ctx:
            decode(f';{DYNAMIC_MARKER}{payload}', 'A')
        self.assertIn('pools/rules', str(ctx.exception))

    def test_no_catchall_in_payload(self):
        from base64 import urlsafe_b64encode
        from json import dumps

        payload_dict = {
            'pools': {'eu': {'values': [{'value': '1.1.1.1'}]}},
            'rules': [{'geos': ['EU'], 'pool': 'eu'}],
        }
        payload = urlsafe_b64encode(dumps(payload_dict).encode()).decode()
        with self.assertRaises(ProviderException) as ctx:
            decode(f';{DYNAMIC_MARKER}{payload}', 'A')
        self.assertIn('catchall', str(ctx.exception))

    def test_catchall_references_missing_pool(self):
        from base64 import urlsafe_b64encode
        from json import dumps

        payload_dict = {'pools': {}, 'rules': [{'pool': 'missing'}]}
        payload = urlsafe_b64encode(dumps(payload_dict).encode()).decode()
        with self.assertRaises(ProviderException) as ctx:
            decode(f';{DYNAMIC_MARKER}{payload}', 'A')
        self.assertIn('catchall', str(ctx.exception))

    def test_cname_empty_catchall_pool(self):
        from base64 import urlsafe_b64encode
        from json import dumps

        payload_dict = {
            'pools': {'default': {'values': []}},
            'rules': [{'pool': 'default'}],
        }
        payload = urlsafe_b64encode(dumps(payload_dict).encode()).decode()
        with self.assertRaises(ProviderException) as ctx:
            decode(f';{DYNAMIC_MARKER}{payload}', 'CNAME')
        self.assertIn('CNAME', str(ctx.exception))


class TestDynamicRoundTrip(TestCase):
    def _round_trip(self, rec):
        script = encode(rec)
        decoded = decode(script, rec._type)
        merged = {'ttl': rec.ttl, **decoded}
        rec2 = Record.new(ZONE, rec.name, merged)
        self.assertEqual(rec._data(), rec2._data())

    def test_simple(self):
        self._round_trip(_record(values=['5.5.5.5'], dynamic=_simple_dynamic()))

    def test_multi_pool_with_fallback(self):
        rec = _record(
            values=['5.5.5.5'],
            dynamic={
                'pools': {
                    'eu': {
                        'values': [{'value': '1.1.1.1'}, {'value': '2.2.2.2'}]
                    },
                    'gb': {'values': [{'value': '3.3.3.3'}], 'fallback': 'eu'},
                    'cal': {'values': [{'value': '4.4.4.4'}]},
                    'default': {'values': [{'value': '5.5.5.5'}]},
                },
                'rules': [
                    {'geos': ['NA-US-CA'], 'pool': 'cal'},
                    {'geos': ['EU-GB'], 'pool': 'gb'},
                    {'geos': ['EU'], 'pool': 'eu'},
                    {'pool': 'default'},
                ],
            },
        )
        self._round_trip(rec)

    def test_aaaa(self):
        rec = _record(
            _type='AAAA',
            values=['2001:db8::5'],
            dynamic={
                'pools': {
                    'eu': {'values': [{'value': '2001:db8::1'}]},
                    'default': {'values': [{'value': '2001:db8::5'}]},
                },
                'rules': [{'geos': ['EU'], 'pool': 'eu'}, {'pool': 'default'}],
            },
        )
        self._round_trip(rec)

    def test_cname(self):
        rec = _record(
            _type='CNAME',
            values=['default.example.com.'],
            dynamic={
                'pools': {
                    'eu': {'values': [{'value': 'eu.example.com.'}]},
                    'default': {'values': [{'value': 'default.example.com.'}]},
                },
                'rules': [{'geos': ['EU'], 'pool': 'eu'}, {'pool': 'default'}],
            },
        )
        self._round_trip(rec)
