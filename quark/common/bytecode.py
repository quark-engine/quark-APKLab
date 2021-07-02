import re


class Bytecode(object):
    """
    Reference to Quark Engine - https://quark-engine.rtfd.io
    """

    def __init__(self, address, mnemonic, registers=None, parameter=None):
        self._address = address
        self._mnemonic = mnemonic
        self._registers = tuple(registers) if registers else tuple()

        if parameter:
            self._parameter = (
                parameter[:-1] if parameter[-1] == ";" else parameter
            )
        else:
            self._parameter = None

    def __eq__(self, bytecode):
        return self._address == bytecode.address

    def __gt__(self, bytecode):
        return self._address > bytecode.address

    def __ge__(self, bytecode):
        return self._address >= bytecode.address

    def __lt__(self, bytecode):
        return self._address < bytecode.address

    def __le__(self, bytecode):
        return self._address <= bytecode.address

    def __hash__(self):
        return (
            hash(self._mnemonic)
            ^ (hash(self._registers) < 2)
            ^ (hash(self._parameter) < 4)
        )

    def __str__(self):
        return f'{self._mnemonic} {["v"+str(reg) for reg in self.registers]} {self._parameter}'

    def __repr__(self):
        return f"<Bytecode-address:{self._address}, mnemonic:{self._mnemonic}, registers:{self._registers}, parameter:{self._parameter}>"

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

    @staticmethod
    def get_by_smali(address, smali):
        if smali == "":
            raise ValueError("Argument str cannot be empty.")

        if " " in smali:
            mnemonic, args = smali.split(maxsplit=1)  # Split into twe parts

            # invoke-kind instruction may left method index at the last
            if mnemonic.startswith("invoke"):
                args = args[: args.rfind(" ;")]

            args = [arg.strip() for arg in re.split("[{},]+", args) if arg]

            parameter = None
            # Remove the parameter at the last
            if len(args) > 0 and not args[-1].startswith("v"):
                parameter = args[-1]
                args = args[:-1]

            regs = None
            # Ranged registers
            if len(args) == 1 and (":" in args[0] or ".." in args[0]):
                register_str = args[0]
                regs = [
                    int(reg[1:])
                    for reg in re.split("[:.]+", register_str)
                    if reg
                ]

                if ".." in args[0]:
                    regs = range(regs[0], regs[1] + 1)

            # Simple registers
            elif len(args) != 0:
                try:
                    regs = [int(arg[1:]) for arg in args]
                except ValueError:
                    raise ValueError(
                        f"Cannot parse bytecode. Unknown smali {smali}."
                    )

            return Bytecode(address, mnemonic, regs, parameter)

        else:
            return Bytecode(address, smali, None, None)
