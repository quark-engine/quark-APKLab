class Bytecode(object):
    """
    Reference to Quark Engine - https://quark-engine.rtfd.io
    """

    def __init__(self, address, mnemonic, registers, parameter):
        self.address = address
        self._mnemonic = mnemonic
        if isinstance(registers[0], str):
            for reg_str in registers:
                self._registers = int(reg_str[1:])
        else:
            self._registers = registers
        self._parameter = parameter

    def __eq__(self, obj):
        return isinstance(obj, Bytecode) and self._mnemonic == obj._mnemonic and self._registers == obj._registers and self._parameter == obj._parameter

    def __hash__(self):
        return hash(self._mnemonic) ^ (hash(self._registers) < 2) ^ (hash(self._parameter) < 4)

    def __str__(self):
        return f'{self._mnemonic} {["v"+str(reg) for reg in self.registers]} {self._parameter}'

    def __repr__(self):
        return f"<Bytecode-mnemonic:{self._mnemonic}, registers:{self._registers}, parameter:{self._parameter}>"

    @property
    def address(self):
        return self._address

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def registers(self):
        return self._registers

    @property
    def parameter(self):
        return self._parameter
