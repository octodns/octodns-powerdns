#
#
#

import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from json import dumps, loads

from octodns.provider import ProviderException
from octodns.record.geo import GeoCodes

DYNAMIC_MARKER = '-- octodns-dynamic:v1:'

_MARKER_RE = re.compile(
    r';' + re.escape(DYNAMIC_MARKER) + r'([A-Za-z0-9_\-=]+)'
)


def _geo_condition(code):
    parsed = GeoCodes.parse(code)
    country = parsed['country_code']
    province = parsed['province_code']
    if province is not None:
        return f"country('{country}') and region('{province}')"
    if country is not None:
        return f"country('{country}')"
    return f"continent('{parsed['continent_code']}')"


def _rule_condition(geos):
    parts = [f'({_geo_condition(g)})' for g in geos]
    return ' or '.join(parts)


def _flatten_pool(pool_name, dynamic):
    values = []
    seen = set()
    current = pool_name
    while current is not None and current not in seen:
        seen.add(current)
        pool = dynamic.pools[current]
        for v in pool.data['values']:
            values.append((v['weight'], v['value']))
        current = pool.data.get('fallback')
    return values


def _pickwhashed(values):
    entries = ', '.join(f"{{{w}, '{v}'}}" for w, v in values)
    return f'pickwhashed({{{entries}}})'


def _pool_lua(pool_name, dynamic):
    return _pickwhashed(_flatten_pool(pool_name, dynamic))


def _marker_payload(record):
    payload = dumps(
        record.dynamic._data(), sort_keys=True, separators=(',', ':')
    )
    return urlsafe_b64encode(payload.encode('utf-8')).decode('ascii')


def encode(record):
    dynamic = getattr(record, 'dynamic', None)
    if not dynamic:
        raise ProviderException(
            f'{record.fqdn} {record._type}: encode called on non-dynamic record'
        )

    catchall = None
    conditional = []
    for rule in dynamic.rules:
        data = rule.data
        if data.get('subnets'):
            raise ProviderException(
                f'{record.fqdn} {record._type}: subnet rules are not supported'
            )
        geos = data.get('geos') or []
        if not geos:
            if catchall is not None:
                raise ProviderException(
                    f'{record.fqdn} {record._type}: multiple catchall rules'
                )
            catchall = data['pool']
            continue
        conditional.append((geos, data['pool']))

    if catchall is None:
        raise ProviderException(
            f'{record.fqdn} {record._type}: dynamic record has no catchall rule'
        )

    lines = [f';{DYNAMIC_MARKER}{_marker_payload(record)}']
    for i, (geos, pool) in enumerate(conditional):
        keyword = 'if' if i == 0 else 'elseif'
        cond = _rule_condition(geos)
        lines.append(f'{keyword} {cond} then return {_pool_lua(pool, dynamic)}')
    if conditional:
        lines.append('end')
    lines.append(f'return {_pool_lua(catchall, dynamic)}')
    return '\n'.join(lines)


def _catchall_values(parsed):
    rules = parsed.get('rules') or []
    pools = parsed.get('pools') or {}
    for rule in rules:
        if not rule.get('geos') and not rule.get('subnets'):
            pool = pools.get(rule.get('pool'))
            if pool is None:
                break
            return [v['value'] for v in pool.get('values', [])]
    raise ProviderException('dynamic payload has no catchall rule')


def decode(script, qtype):
    match = _MARKER_RE.search(script)
    if match is None:
        raise ValueError('no octodns-dynamic marker')

    try:
        raw = urlsafe_b64decode(match.group(1).encode('ascii'))
        parsed = loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as e:
        raise ProviderException(f'malformed octodns-dynamic marker: {e}') from e

    if (
        not isinstance(parsed, dict)
        or 'pools' not in parsed
        or 'rules' not in parsed
    ):
        raise ProviderException(
            'malformed octodns-dynamic marker: missing pools/rules'
        )

    values = _catchall_values(parsed)
    data = {'type': qtype, 'dynamic': parsed}
    if qtype == 'CNAME':
        if not values:
            raise ProviderException('dynamic CNAME catchall pool has no values')
        data['value'] = values[0]
    else:
        data['values'] = values
    return data
