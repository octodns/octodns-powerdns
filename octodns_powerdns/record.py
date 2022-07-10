from octodns.record import Record, ValuesMixin
from octodns.equality import EqualityTupleMixin


class _PowerDnsLuaValue(EqualityTupleMixin):

    @classmethod
    def validate(cls, data, _type):
        if not isinstance(data, (list, tuple)):
            data = (data,)
        reasons = []
        return reasons

    @classmethod
    def process(cls, values):
        return [_PowerDnsLuaValue(v) for v in values]

    def __init__(self, value):
        self._type = value['type']
        self.script = value['script']

    @property
    def data(self):
        return {
            'script': self.script,
            'type': self._type,
        }

    def __hash__(self):
        return hash((self._type,))

    def _equality_tuple(self):
        return (self._type, self.script)

    def __repr__(self):
        return f'{self._type} (script)'


class PowerDnsLuaRecord(ValuesMixin, Record):
    _type = 'PowerDnsProvider/LUA'
    _value_type = _PowerDnsLuaValue


Record.register_type(PowerDnsLuaRecord)
