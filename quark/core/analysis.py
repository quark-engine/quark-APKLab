CONF_STAGE_NONE = 0
CONF_STAGE_1 = 1
CONF_STAGE_2 = 2
CONF_STAGE_3 = 3
CONF_STAGE_4 = 4
CONF_STAGE_5 = 5


class QuarkAnalysis(object):

    def __init__(self):
        self.rule_results = {}

    def add_rule(self, rule):
        assert rule not in self.rule_results
        # Permissions, Native Apis, Sequences, Invoke Paths, Used Registers
        self.rule_results[rule] = (CONF_STAGE_NONE, [False, None, None, None, None])

    def set_rule_pass(self, rule, level, key, value=None):
        assert rule in self.rule_results
        assert CONF_STAGE_NONE < level <= CONF_STAGE_5

        keys = ['Permission', 'NativeApi', 'Sequence', 'InvokePath', 'UsedRegister']
        assert key in keys

        self.rule_results[rule][0] = level

        if value:
            self.rule_results[rule][1][keys.index(key)] = value

    def get_rule_result(self, rule):
        if rule in self.rule_results:
            return self.rule_results[rule]

        return None

    def get_json_report(self):
        crimes = {}
        for rule in self.rule_results:
            passed_stage, rule_result = self.rule_results[rule]
            report = {
                'crime': rule.crime,
                'score': rule.yscore,
                'weight': self._get_rule_confience(rule, passed_stage),
                'confidence': f'{passed_stage/CONF_STAGE_5 * 100}%',
                'permissions': [],
                'native_api': [],
                'combination': [],
                'sequence': [],
                'register': []
            }

            # TODO - Finish json report

    @staticmethod
    def _get_rule_confience(rule, confidence):
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * rule.yscore) / 2 ** 4
