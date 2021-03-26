from collections import defaultdict, namedtuple

from quark.common.bytecode import Bytecode
from quark.core.rule import QuarkRule

CONF_STAGE_NONE = 0
CONF_STAGE_1 = 1
CONF_STAGE_2 = 2
CONF_STAGE_3 = 3
CONF_STAGE_4 = 4
CONF_STAGE_5 = 5

Sequence = namedtuple(
    'Sequence', 'parent, tree_list')


class Behavior:
    __slots__ = ['related_rule', 'reached_stage',
                 'api_objects', 'sequence', 'registers']

    def __init__(self, rule: QuarkRule):
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
        self._score_sum += rule.score

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
        crime_list = []
        for rule, behavior_list in self._rule_results.items():
            max_stage = max(
                (behavior.reached_stage for behavior in behavior_list))
            report = {
                'crime': rule.crime,
                'score': rule.score,
                'weight': self.get_rule_confidence(rule, max_stage),
                'confidence': f'{max_stage/CONF_STAGE_5 * 100}%'
            }

            if max_stage >= CONF_STAGE_1:
                report['permissions'] = rule.permission

            if max_stage >= CONF_STAGE_2:
                report['matched_api'] = rule.api

            if max_stage >= CONF_STAGE_3:
                report['combination'] = list([self._generate_invoke_report(
                    beh.sequence) for beh in behavior_list if beh.reached_stage == CONF_STAGE_3])

            if max_stage >= CONF_STAGE_4:
                report['sequence'] = list([self._generate_invoke_report(
                    beh.sequence) for beh in behavior_list if beh.reached_stage >= CONF_STAGE_4])

            if max_stage >= CONF_STAGE_5:
                report['register'] = []

                for behavior in behavior_list:
                    if behavior.reached_stage!=CONF_STAGE_5:
                        continue
                    register_report = {
                        'parent': str(behavior.sequence.parent),
                        'reg_index': behavior.registers
                    }

                    report['register'].append(register_report)

            crime_list.append(report)

        return crime_list

    @staticmethod
    def get_rule_confidence(rule, confidence):
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * rule.score) / 2 ** 4

    @staticmethod
    def _generate_invoke_report(sequence_obj):
        parent = sequence_obj.parent
        tree_list = sequence_obj.tree_list

        call_graph = {
            'parent': str(parent),
            'call_graph': []
        }

        for tree in tree_list:
            path = []

            for method in tree.rsearch(parent):
                if method is tree.root:
                    break

                method_item = {
                    'caller': str(method),
                    'invoke_at': [str(bytecode) for bytecode in tree.get_node(method).data]
                }
                path.append(method_item)

            call_graph['call_graph'].append({
                'api': str(tree.root),
                'path': path
            })

        return call_graph
