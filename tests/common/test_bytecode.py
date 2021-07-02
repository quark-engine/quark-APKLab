from quark.common.bytecode import Bytecode


class TestBytecode:
    def test_cmp(self):
        assert Bytecode(0x0, "move", [1, 2]) == Bytecode(0x0, "const", [1, 2])

        assert Bytecode(0x1, "move", [1, 2]) > Bytecode(0x0, "move", [1, 3])
        assert Bytecode(0x1, "move", [1, 2]) >= Bytecode(0x0, "move", [1, 3])
        assert Bytecode(0x0, "move", [1, 2]) < Bytecode(0x1, "move", [1, 3])
        assert Bytecode(0x1, "move", [1, 2]) <= Bytecode(0x1, "move", [1, 3])

    def test_hash(self):
        assert hash(Bytecode(0x1, "move", [1, 2])) == hash(
            Bytecode(0x1, "move", [1, 2])
        )
        assert hash(Bytecode(0x1, "move", [1, 2])) != hash(
            Bytecode(0x1, "const", [1, 2])
        )

    @staticmethod
    def test_get_by_smali():
        assert Bytecode.get_by_smali(0x0, "return-void") == Bytecode(
            0x0, "return-void"
        )
        assert Bytecode.get_by_smali(0x0, "const/16 v1") == Bytecode(
            0x0,
            "const/16",
            [
                1,
            ],
        )
        assert Bytecode.get_by_smali(0x0, "move v1, v2") == Bytecode(
            0x0, "move", [1, 2]
        )
        assert Bytecode.get_by_smali(
            0x0, "invoke-direct v1, v2, METHOD;"
        ) == Bytecode(0x0, "invoke-direct", [1, 2], "METHOD;")
        assert Bytecode.get_by_smali(0x0, "const-wide/32 v1:v2") == Bytecode(
            0x0, "const-wide/32", [1, 2]
        )
        assert Bytecode.get_by_smali(
            0x0, "invoke-direct/range {v1...v5}, METHOD;"
        ) == Bytecode(0x0, "invoke-direct/range", range(1, 6), "METHOD;")
