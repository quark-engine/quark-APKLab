import logging

from copy import copy
from re import escape
from typing import Sequence
from treelib import Tree

from quark.android.apk import Apkinfo
from quark.common.method import MethodId
from quark.core.analysis import (CONF_STAGE_1, CONF_STAGE_2, CONF_STAGE_3,
                                 CONF_STAGE_4, CONF_STAGE_5, CONF_STAGE_NONE,
                                 Behavior, QuarkAnalysis, Sequence)
from quark.core.rule import QuarkRule

MAX_REG_COUNT = 257
RETURN_REG_INDEX = 256


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk):
        self.apkinfo = Apkinfo(apk)
        self._report = QuarkAnalysis()
        self._apkinfo_stack = []
        self._sequence_stack = []
        self._register_stack = []

    @property
    def report(self):
        return self._report

    def get_invoke_tree(self, method: MethodId, search_depth=3):
        tree = Tree(deep=search_depth, identifier=method.address)

        # Parent method with invoke address list
        tree.create_node(identifier=method, data=[])

        for _ in range(search_depth):
            for leaf in tree.leaves():
                uppers = self.apkinfo.find_upper_methods(leaf.identifier)
                for offset, upper in uppers:
                    bytecode = self.apkinfo.find_bytecode_by_addr(upper.dexindex, offset)
                    if not tree.contains(upper):
                        tree.create_node(
                            identifier=upper, data=[bytecode], parent=leaf)
                    else:
                        tree.get_node(upper).data.append(bytecode)

        return tree

    def check_register_in_method(self, method: MethodId, registers, start_bytecode=None, end_bytecode=None, reset_bytecodes=None):
        old_registers = copy(registers)
        # Fetch target ranger of instructions
        instructions = [ins for ins in self.apkinfo.get_function_bytecode(
            method, start_bytecode.address if start_bytecode else -1, end_bytecode.address if end_bytecode else -1)]
        instructions.reverse()

        # Apply all opcode reversely and remove those were override
        TRANSITION_TYPE_1 = (
            # If destination register exists. It will appear at the least.
            # Otherwise , destination is the parameter or the return register.
            'invoke', 'filled', 'return'
        )
        TRANSITION_TYPE_2 = (
            # First register is destination, second one is source.
            'move', 'neg', 'not', 'int', 'long', 'float', 'double', 'array'
        )
        NEW_TYPE = (
            # Given registers will be override.
            'const', 'new'
        )
        NOP_TYPE = (
            # Instructions needed to skip.
            'monitor', 'instance', 'goto', 'if', 'add', 'sub', 'rsub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl',
            'shr', 'ushr', 'check', 'cmp', 'iget', 'iput', 'aget', 'aput'
        )

        reset_offsets = (bytecode.address for bytecode in reset_bytecodes)

        for ins in instructions:
            # print(f'{ins.address} {str(ins)}')

            # Combine two sets of registers if a reset offset comes
            if ins.address in reset_offsets:
                for reg_index in range(MAX_REG_COUNT):
                    registers[reg_index] = registers[reg_index] ^ old_registers[reg_index]
                continue

            prefix = ins.mnemonic.split('-')[0]

            # Transition
            if prefix in TRANSITION_TYPE_1:
                if ins.parameter and registers[RETURN_REG_INDEX]:
                    # invoke-kind, filled-new-array
                    registers[RETURN_REG_INDEX] = False
                    for reg_index in ins.registers:
                        registers[reg_index] = True

            elif prefix in TRANSITION_TYPE_2:
                if len(ins.registers) > 1:
                    if registers[ins.registers[0]]:
                        registers[ins.registers[0]] = False
                        registers[ins.registers[1]] = True
                elif registers[ins.registers[0]]:
                    # move-result
                    registers[ins.registers[0]] = False
                    registers[RETURN_REG_INDEX] = True

            elif prefix in NEW_TYPE:
                for reg_index in ins.registers:
                    registers[reg_index] = False
            elif prefix not in NOP_TYPE:
                # TODO - warning
                pass

        return registers

    def check_register_downward(self, invoke_nodes: list, registers):
        # Check registers reversely from common parent to api
        if len(invoke_nodes) <= 2:
            return registers
        invoke_nodes.reverse()
        invoke_nodes.pop()  # Pop out the api

        while len(invoke_nodes) > 2 and any(registers):
            current_node = invoke_nodes.pop()
            first_bytecode = min(current_node.data)
            self.check_register_in_method(
                current_node.identifier, registers, start_bytecode=first_bytecode, reset_bytecodes=current_node.data)

        return registers

    def check_register_upward(self, invoke_nodes: list, registers):
        # Check registers reversely from api to common parent
        if len(invoke_nodes) <= 2:
            return registers
        invoke_nodes.pop()  # Popup api node

        while len(invoke_nodes) > 2 and any(registers):
            current_node = invoke_nodes.pop()
            least_bytecode = max(current_node.data)
            self.check_register_in_method(
                current_node.identifier, registers, end_bytecode=least_bytecode, reset_bytecodes=current_node.data)

        return registers

    def check_register(self, sequence: Sequence, registers=None):
        first_tree = sequence.tree_list[0]
        second_tree = sequence.tree_list[1]
        parent = sequence.parent

        first_node = [first_tree.get_node(method)
                      for method in first_tree.rsearch(parent)]
        second_node = [second_tree.get_node(method)
                       for method in second_tree.rsearch(parent)]

        if registers is None:
            # Setup the registers and adjust end_offset
            upper_node = second_node[-2]
            least_bytecode = max(upper_node.data)

            if not least_bytecode:
                logging.warning(
                    f'Unable fetch bytecode at {least_bytecode} with {upper_node.identifier}, skip this scanning.')
                return [False for _ in range(MAX_REG_COUNT)]

            registers = [False for _ in range(MAX_REG_COUNT)]
            for reg_index in least_bytecode.registers:
                registers[reg_index] = True

        first_invoke_for_first_api = min(first_tree.get_node(parent).data)

        reset_offsets = second_tree.get_node(parent).data
        least_invoke_for_second_api = max(reset_offsets)

        if(first_invoke_for_first_api >= least_invoke_for_second_api):
            logging.error(
                f'Address for first api is less than address for second api @ {parent}')
            return [False]

        registers = self.check_register_upward(second_node, registers)
        registers = self.check_register_in_method(
            parent, registers, first_invoke_for_first_api, least_invoke_for_second_api, reset_offsets)
        registers = self.check_register_downward(first_node, registers)

        return registers

    def run_apkinfo_phase(self, behavior: Behavior):
        rule = behavior.related_rule

        # Stage 1 - Check Permission
        passed_permissions = (
            permission for permission in rule.permission if permission in self.apkinfo.permissions)

        if len(list(passed_permissions)) != len(rule.permission):
            return CONF_STAGE_NONE

        api_object = []
        for api in rule.api:
            methods = self.apkinfo.find_methods(
                api['class'], api['method'], api['descriptor'])
            try:
                api_object.append(next(methods))
            except StopIteration:
                break

        behavior.api_objects = api_object

        # Stage 2 - All native apis exist
        return CONF_STAGE_1 if len(api_object) < len(rule.api) else CONF_STAGE_2

    def run_sequence_phase(self, behavior: Behavior):
        # Check if apis exist in the same call graph
        trees = [self.get_invoke_tree(api)
                 for api in behavior.api_objects]  # tree list

        # Test each combination of trees
        for first_index in range(len(trees)):
            for second_index in range(first_index+1, len(trees)):
                first_tree = trees[first_index]
                second_tree = trees[second_index]

                first_all_methods = {
                    node.identifier for node in first_tree.all_nodes()}
                second_all_methods = {
                    node.identifier for node in second_tree.all_nodes()}
                common_parents = first_all_methods.intersection(
                    second_all_methods)

                # Stage 3 - Check combination
                # Stage 4 - Check sequence
                # Check invoke address
                passing_3_list = []
                passing_4_list = []
                for parent in common_parents:
                    # Test sequence of invoke addresses from two methods
                    first_bytecode_for_first_method = min(
                        first_tree.get_node(parent).data)
                    least_bytecode_for_second_method = max(
                        second_tree.get_node(parent).data)

                    cloned_behavior = copy(behavior)
                    cloned_behavior.sequence = Sequence(
                        parent, (trees[first_index], trees[second_index]))
                    if first_bytecode_for_first_method < least_bytecode_for_second_method:
                        passing_4_list.append(cloned_behavior)
                    else:
                        passing_3_list.append(cloned_behavior)

        return passing_3_list, passing_4_list

    def run_register_phase(self, behavior: Behavior):
        # Stage 5 - Handling the same register
        registers = self.check_register(behavior.sequence)

        if any(registers):
            critical_indexes = [
                index for index, is_critical in enumerate(registers) if is_critical]

            behavior.registers = critical_indexes
            return CONF_STAGE_5
        else:
            return CONF_STAGE_4

    def analysis_rule(self, rule: QuarkRule):
        self.add_rule(rule)
        self.run_analysis()

    def add_rule(self, rule: QuarkRule):
        behavior = self._report.add_rule(rule)
        if behavior is None:
            return False

        self._apkinfo_stack.append(behavior)
        return True

    def run_analysis(self):
        while self._apkinfo_stack or self._register_stack:
            if self._apkinfo_stack:
                behavior = self._apkinfo_stack.pop()
                result = self.run_apkinfo_phase(behavior)

                if result != CONF_STAGE_2:
                    self._report.set_passed(behavior, result)
                    continue

                passing_3_list, passing_4_list = self.run_sequence_phase(
                    behavior)

                if passing_3_list or passing_4_list:
                    for passing in passing_3_list:
                        self._report.set_passed(passing, CONF_STAGE_3)

                    self._register_stack.extend(passing_4_list)
                    # for passing in passing_4_list:
                    #     self._report.set_passed(passing, CONF_STAGE_4)

                else:
                    self._report.set_passed(behavior, CONF_STAGE_2)

            if self._register_stack:
                behavior = self._register_stack.pop()
                result = self.run_register_phase(behavior)
                self._report.set_passed(behavior, result)

    def get_json_report(self):
        return {
            'md5': self.apkinfo.md5,
            'apk_filename': self.apkinfo.filename,
            'size_bytes': self.apkinfo.filesize,
            'threat_level': self._report.get_thread_level(),
            'total_score': self._report.weighted_sum,
            'crimes': self._report.get_json_report()
        }
