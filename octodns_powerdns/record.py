from octodns.equality import EqualityTupleMixin
from octodns.record import RdataParseError, Record, ValuesMixin

try:  # pragma: no cover
    import octodns.record.validator

    _HAS_VALUE_VALIDATOR = hasattr(octodns.record.validator, 'ValueValidator')
    _HAS_VALIDATION_REASON = hasattr(
        octodns.record.validator, 'ValidationReason'
    )
except ImportError:  # pragma: no cover
    _HAS_VALUE_VALIDATOR = False
    _HAS_VALIDATION_REASON = False


def _unquote(value):
    # PowerDNS always wraps the LUA script in double quotes; strip them off,
    # mirroring octoDNS core's own `unquote()` helper
    # (octodns.record.base.unquote, not part of the public API surface).
    return value[1:-1]


def _validate_powerdns_lua_values(data):
    if not isinstance(data, (list, tuple)):
        data = (data,)
    reasons = []
    if len(data) == 0:
        reasons.append('at least one value required')
    for value in data:
        if 'type' not in value:
            reasons.append('missing type')
        if 'script' not in value:
            reasons.append('missing script')
    return reasons


if _HAS_VALUE_VALIDATOR:  # pragma: no cover

    class _PowerDnsLuaValueValidator(octodns.record.validator.ValueValidator):
        def validate(self, value_cls, data, _type):
            reasons = _validate_powerdns_lua_values(data)
            if _HAS_VALIDATION_REASON:
                return [
                    octodns.record.validator.ValidationReason(
                        r, validator_id=self.id
                    )
                    for r in reasons
                ]
            return reasons


class _PowerDnsLuaValue(EqualityTupleMixin, dict):
    # See https://doc.powerdns.com/authoritative/lua-records/index.html for the
    # LUA record docs and
    # https://gist.github.com/ahupowerdns/1e8bfbba95a277a4fac09cb3654eb2ac
    # has some good example scripts

    if not _HAS_VALUE_VALIDATOR:  # pragma: no cover

        @classmethod
        def validate(cls, data, _type):
            return _validate_powerdns_lua_values(data)

    @classmethod
    def process(cls, values):
        return [_PowerDnsLuaValue(v) for v in values]

    @classmethod
    def from_rdata_text(cls, rdata):
        try:
            _type, script = rdata.split(' ', 1)
        except ValueError:
            raise RdataParseError()
        return {'type': _type, 'script': _unquote(script)}

    def to_rdata_text(self):
        return f'{self._type} "{self.script}"'

    def __init__(self, value):
        self._type = value['type']
        self.script = value['script']

    @property
    def _type(self):
        return self['type']

    @_type.setter
    def _type(self, value):
        self['type'] = value

    @property
    def script(self):
        return self['script']

    @script.setter
    def script(self, value):
        self['script'] = value

    @property
    def data(self):
        return self

    def __hash__(self):
        return hash((self._type,))

    def _equality_tuple(self):
        return (self._type, self.script)

    def __repr__(self):
        return f'{self._type} (script)'


class PowerDnsLuaRecord(ValuesMixin, Record):
    _type = 'PowerDnsProvider/LUA'
    _value_type = _PowerDnsLuaValue

    if _HAS_VALUE_VALIDATOR:  # pragma: no cover
        VALIDATORS = [_PowerDnsLuaValueValidator('powerdns-lua-value')]


Record.register_type(PowerDnsLuaRecord)
