from quark.core.rule import QuarkRule


CONF_STAGE_NONE = 0
CONF_STAGE_1 = 1
CONF_STAGE_2 = 2
CONF_STAGE_3 = 3
CONF_STAGE_4 = 4
CONF_STAGE_5 = 5

PROC_STAGE_APIINFO = -1
PROC_STAGE_COMMON_PARENT = -2
PROC_STAGE_SEQUENCE = -3
PROC_STAGE_REGISTER = -4

class Task(object):

    __slots__ = [
        'related_rule',
        'reached_stage',
        'process_stage',

        'permissions',
        'native_apis',
        'first_tree',
        'second_tree',
        'parent',
        'sequence',
        'used_registers'
        ]

    def __init__(self, rule: QuarkRule):
        self.related_rule = rule
        self.process_stage = PROC_STAGE_APIINFO

        self.permissions = None
        self.native_apis = None
        self.first_tree = None
        self.second_tree = None
        self.parent = None
        self.sequence = None
        self.used_registers = None

class QuarkAnalysis(object):

    def __init__(self):
        self._rule_results = {}
        self._score_sum = 0
        self._weighted_sum = 0

    def add_rule(self, rule) -> Task:
        assert rule not in self._rule_results
        # Permissions, Native Apis, Sequences, Used Registers
        task = Task(rule)
        self._rule_results[rule] = []
        self._score_sum += rule.yscore

        return task

    def set_passed(self, task, level):
        assert CONF_STAGE_NONE <= level <= CONF_STAGE_5
        task.reached_stage = level
        task.process_stage = None

        rule = task.related_rule
        assert rule in self._rule_results

        self._rule_results[rule].append(task)

    @property
    def passed_tasks(self):
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
