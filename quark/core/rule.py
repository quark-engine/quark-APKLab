import json
import os


class QuarkRule:
    """RuleObject is used to store the rule from json file"""

    __slots__ = ["check_item", "_json_obj", "_crime", "_x1_permission", "_x2n3n4_comb", "_yscore", "rule_filename"]

    def __init__(self, json_filename):
        with open(json_filename) as json_file:
            json_obj = json.loads(json_file.read())
            self._crime = json_obj["crime"]
            self._x1_permission = json_obj["x1_permission"]
            self._x2n3n4_comb = json_obj["x2n3n4_comb"]
            self._yscore = json_obj["yscore"]
            self.rule_filename = os.path.basename(json_filename)

    def __repr__(self):
        return f"<RuleObject-{self.rule_filename}>"

    def __eq__(self, obj):
        return isinstance(obj, QuarkRule) and self.rule_filename == obj.rule_filename

    def __hash__(self):
        return hash(self.rule_filename)

    @property
    def crime(self):
        return self._crime

    @property
    def x1_permission(self):
        return self._x1_permission

    @property
    def x2n3n4_comb(self):
        return self._x2n3n4_comb

    @property
    def yscore(self):
        return self._yscore
