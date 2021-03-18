import json
import os


class QuarkRule:

    __slots__ = ['_crime', '_permission', '_api', '_score', '_label', '_file']

    def __init__(self, json_filename):
        with open(json_filename) as json_file:
            json_obj = json.loads(json_file.read())
            self._crime = json_obj['crime']
            self._permission = json_obj['permission']
            self._api = json_obj['api']
            self._score = json_obj['score']
            self._label = json_obj['label']
            self._file = json_filename

    def __repr__(self):
        return f"<RuleObject-{self.rule_filename}>"

    def __eq__(self, obj):
        return isinstance(obj, QuarkRule) and self._file == obj._file

    def __hash__(self):
        return hash(self._file)

    @property
    def crime(self):
        return self._crime

    @property
    def permission(self):
        return self._permission

    @property
    def api(self):
        return self._api

    @property
    def score(self):
        return self._score

    @property
    def label(self):
        return self._label

    @property
    def filepath(self):
        return self._file
