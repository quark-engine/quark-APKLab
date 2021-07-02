import pytest

from quark.core.rule import QuarkRule


@pytest.fixture
def rule_sample():
    return QuarkRule("tests/sample/00020.json")


class TestQuark(object):
    def analysis(self, quark_obj, rule_sample):
        pass
