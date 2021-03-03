from collections import defaultdict, namedtuple
from quark.core.rule import QuarkRule


CONF_STAGE_NONE = 0
CONF_STAGE_1 = 1
CONF_STAGE_2 = 2
CONF_STAGE_3 = 3
CONF_STAGE_4 = 4
CONF_STAGE_5 = 5

Sequence = namedtuple(
    'Sequence', 'parent, first_api_tree, second_api_tree')

class Behavior:
    __slots__=['related_rule','reached_stage','api_objects','sequence','registers']

    def __init__(self, rule:QuarkRule):
        self.related_rule = rule
        
        self.reached_stage = CONF_STAGE_NONE
        self.api_objects = None
        self.sequence = None
        self.registers = None

class QuarkAnalysis(object):

    def __init__(self):
        self._rule_results = {}
        self._score_sum = 0
        self._weighted_sum = 0

    def add_rule(self, rule) -> Behavior:
        if rule in self._rule_results:
            return None
        # Permissions, Native Apis, Sequences, Used Registers
        behavior = Behavior(rule)
        self._rule_results[rule] = []
        self._score_sum += rule.yscore

        return behavior

    def set_passed(self, behavior, level):
        assert CONF_STAGE_NONE <= level <= CONF_STAGE_5
        behavior.reached_stage = level

        rule = behavior.related_rule
        assert rule in self._rule_results
        self._rule_results[rule].append(behavior)

    @property
    def passed_behaviors(self):
        return self._rule_results

    @property
    def weighted_sum(self):
        return self._weighted_sum

    def get_level_threshold(self):
        return [self._score_sum / 2 ** (5 - level) for level in range(1, 5)]

    def get_thread_level(self):
        thresholds = self.get_level_threshold()

        if self._weighted_sum <= thresholds[1]:
            return 'Low Risk'
        elif self._weighted_sum <= thresholds[3]:
            return 'Mederate Risk'
        else:
            return 'High Risk'

    def get_json_report(self):
        crimes = {}
        for rule in self._rule_results:
            passed_stage, rule_result = self._rule_results[rule]
            report = {
                'crime': rule.crime,
                'score': rule.yscore,
                'weight': self.get_rule_confidence(rule, passed_stage),
                'confidence': f'{passed_stage/CONF_STAGE_5 * 100}%',
                'permissions': [],
                'native_api': [],
                'combination': [],
                'sequence': [],
                'register': []
            }

            if passed_stage >= CONF_STAGE_1:
                report['permissions'] = rule_result['permissions']

            if passed_stage >= CONF_STAGE_2:
                report['native_api'] = [{
                    'class': api.classname,
                    'method': api.methodname
                } for api in rule_result['native_api']]

            if passed_stage >= CONF_STAGE_3:
                # Nothing to log
                pass

            if passed_stage >= CONF_STAGE_4:
                report['sequence'] = []

                for first_result, second_result in rule_result:
                    first_result = list(first_result)
                    first_result.reverse()

                    for bytecode, method in first_result:
                        # TODO
                        pass

            if passed_stage >= CONF_STAGE_5:
                report['register'] = rule_result['register']

    @staticmethod
    def get_rule_confidence(rule, confidence):
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * rule.yscore) / 2 ** 4
