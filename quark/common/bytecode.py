class Bytecode(object):
    """
    Reference to Quark Engine - https://quark-engine.rtfd.io
    """

    def __init__(self, address, mnemonic, registers, parameter):
        self._address = address
        self._mnemonic = mnemonic
        self._registers = []

        if registers:
            if isinstance(registers, list):
                if isinstance(registers[0], str):
                    if mnemonic.endswith('range'):
                        if ".." not in registers[0]:
                            raise TypeError(f'Unknown registers {registers}')

                        start_reg, end_reg = registers[0].split("..", 2)
                        start_reg = int(start_reg[1:])
                        end_reg = int(end_reg[1:])

                        self._registers = range(start_reg,end_reg)
                    else:
                        for reg_str in registers:
                            self._registers.append(int(reg_str[1:]))
                elif isinstance(registers[0], int):
                    self._registers = registers
            else:
                raise TypeError(f'Unknown registers {registers}')

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
