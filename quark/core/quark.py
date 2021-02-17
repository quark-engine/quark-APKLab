from copy import copy
from typing import Sequence
from treelib import Tree

from quark.android.apk import Apkinfo
from quark.common.method import MethodId
from quark.core.analysis import PROC_STAGE_APIINFO, PROC_STAGE_COMMON_PARENT, PROC_STAGE_REGISTER, PROC_STAGE_SEQUENCE, QuarkAnalysis, CONF_STAGE_NONE, CONF_STAGE_2, CONF_STAGE_3, CONF_STAGE_4, CONF_STAGE_5, CONF_STAGE_1
from quark.core.rule import QuarkRule

MAX_REG_COUNT = 257
RETURN_REG_INDEX = 256


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk):
        self.apkinfo = Apkinfo(apk)
        self._report = QuarkAnalysis()

    @property
    def analysis_report(self):
        return self._report

    def find_common_parent(self, first: MethodId, second: MethodId, search_depth=3):
        assert not first == second

        first_tree, second_tree = (
            Tree(deep=search_depth), Tree(deep=search_depth))
        first_tree.create_node(identifier=first.address, data=None)
        second_tree.create_node(identifier=second.address, data=None)

        second_leaves = {second}
        first_leaves = {first}

        parents = set()
        while not search_depth == 0 and (first_leaves or second_leaves):
            # Check if common parent presents
            for method in second_leaves:
                if first_tree.contains(method.address):
                    parents.add(method)
            for method in first_leaves:
                if second_tree.contains(method.address):
                    parents.add(method)

            second_leaves.difference_update(parents)
            first_leaves.difference_update(parents)

            # Expand trees
            second_next_leaves = set()
            for method in second_leaves:
                for addr, upper in self.apkinfo.find_upper_methods(method):
                    if not second_tree.contains(upper.address):
                        second_tree.create_node(
                            identifier=upper.address, data=addr, parent=method.address)
                    second_next_leaves.add(upper)
            second_leaves = second_next_leaves

            first_next_leaves = set()
            for method in first_leaves:
                for addr, upper in self.apkinfo.find_upper_methods(method):
                    if not first_tree.contains(upper.address):
                        first_tree.create_node(
                            identifier=upper.address, data=addr, parent=method.address)
                    first_next_leaves.add(upper)
            first_leaves = first_next_leaves

            search_depth = search_depth-1

        return first_tree, second_tree, parents

    def check_register_in_method(self, method: MethodId, registers, start_offset=-1, end_offset=-1):
        """
        * end_offset_included
        """

        # Fetch target ranger of instructions
        instructions = [ins for ins in self.apkinfo.get_function_bytecode(
            method, start_offset, end_offset)]
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

        for ins in instructions:
            # print(f'{ins.address} {str(ins)}')

            prefix = ins.mnemonic.split('-')[0]

            # Transition
            if prefix in TRANSITION_TYPE_1:
                if ins.parameter and registers[RETURN_REG_INDEX]:
                    # invoke-kind, filled-new-array
                    registers[RETURN_REG_INDEX] = False
                    for reg_index in ins.registers:
                        registers[reg_index] = True

            elif prefix in TRANSITION_TYPE_2:
                if registers[ins.registers[0]]:
                    registers[ins.registers[0]] = False
                    registers[ins.registers[1]] = True

            elif prefix in NEW_TYPE:
                for reg_index in ins.registers:
                    registers[reg_index] = False
            elif prefix not in NOP_TYPE:
                # TODO - warning
                pass

        return registers

    def check_register_upward(self, method: MethodId, invoke_path: list, parent: MethodId, registers):
        # Currently must have a least one parent (the common parent)
        assert len(invoke_path) > 1
        invoke_path.pop()

        while any(registers) and invoke_path:
            direct_invoke_address, direct_parent = invoke_path.pop()
            self.check_register_in_method(
                direct_parent, registers, -1, direct_invoke_address)

        return registers

    def check_register_downward(self, method: MethodId, invoke_path: list, parent: MethodId, registers):
        assert len(invoke_path) > 1
        invoke_path.pop()

        invoke_path.reverse()

        invoke_address, _ = invoke_path.pop()
        while any(registers) and invoke_path:
            next_invoke_address, child_method = invoke_path[-1]
            registers = self.check_register_in_method(
                child_method, registers, invoke_address, -1)
            invoke_address = next_invoke_address

        return registers

    def check_register(self, first: MethodId, first_tree: Tree, second: MethodId, second_tree: Tree, parent: MethodId,
                       registers=None):
        first_node = [first_tree.get_node(
            method_address) for method_address in first_tree.rsearch(parent.address)]

        second_node = [second_tree.get_node(method_address) for method_address in
                       second_tree.rsearch(parent.address)]
        # invoke_address = [..., invoke_address2, invoke_address1, None]

        if registers is None:
            # Setup the registers and adjust end_offset
            second_direct_invoke_address, second_direct_invoke_method = second_node[
                -2].data, self.apkinfo.find_methods_by_addr(
                second_node[-2].identifier)
            start_instructions = list(self.apkinfo.get_function_bytecode(second_direct_invoke_method,
                                                                         second_direct_invoke_address,
                                                                         second_direct_invoke_address + 1))[0]

            registers = [False for _ in range(MAX_REG_COUNT)]
            for reg_index in start_instructions.registers:
                registers[reg_index] = True

        first_last_invoke_address = first_node[0].data
        second_last_invoke_address = second_node[0].data

        second_path = [(node.data, self.apkinfo.find_methods_by_addr(
            node.identifier)) for node in second_node]

        registers = self.check_register_upward(
            second, second_path, parent, registers)
        # del second_path

        registers = self.check_register_in_method(parent, registers, first_last_invoke_address,
                                                  second_last_invoke_address)

        first_path = [(node.data, self.apkinfo.find_methods_by_addr(
            node.identifier)) for node in first_node]
        registers = self.check_register_downward(
            first, first_path, parent, registers)
        # del first_path

        return registers

    def analysis(self, rule: QuarkRule):
        # Log rule
        task_stack = [self._report.add_rule(rule)]

        while task_stack:
            task = task_stack.pop()
            rule = task.related_rule

            if task.process_stage == PROC_STAGE_APIINFO:
                # Stage 1 - Check Permission
                passed_permissions = (
                    permission for permission in rule.x1_permission if permission in self.apkinfo.permissions)

                task.permissions = rule.x1_permission
                
                if len(rule.x1_permission) != len(task.permissions):
                    self._report.set_passed(task, CONF_STAGE_NONE)
                    continue

                api_object = []
                for api in rule.x2n3n4_comb:
                    methods = self.apkinfo.find_methods(
                        api['class'], api['method'], api['descriptor'])
                    if methods:
                        api_object.append(methods[0])

                task.native_apis = api_object

                if len(api_object) == 0:
                    self._report.set_passed(task, CONF_STAGE_1)
                    continue

                # Stage 2 - Contain native api
                if len(api_object) < len(rule.x2n3n4_comb):
                    self._report.set_passed(task, CONF_STAGE_2)
                    continue
                # Stage 3 - All native apis exist
                task.process_stage = PROC_STAGE_COMMON_PARENT
                
            if task.process_stage == PROC_STAGE_COMMON_PARENT:
                # Check if apis exist in the same call graph
                # TODO - make invoke.address as identifier of tree node, method address stores at the data property of nodes.
                #        To support same method with different child.
                task.first_tree, task.second_tree, parents = self.find_common_parent(
                    api_object[0], api_object[1])

                if not parents:
                    self._report.set_passed(task, CONF_STAGE_3)
                    continue

                task.process_stage = PROC_STAGE_SEQUENCE
                for parent in parents:
                    cloned_task = copy(task)
                    cloned_task.parent = parent

                    task_stack.append(cloned_task)

                continue

            if task.process_stage == PROC_STAGE_SEQUENCE:
                # Stage 4 - Check sequence
                first_invoke_address = [task.first_tree.get_node(method_addr).data for method_addr in
                                    task.first_tree.rsearch(task.parent.address)]
                first_invoke_address.pop()  # Drop None at the last
                second_invoke_address = [task.second_tree.get_node(method_addr).data for method_addr in
                                        task.second_tree.rsearch(task.parent.address)]
                second_invoke_address.pop()  # Drop None at the last

                for first_addr, second_addr in zip(first_invoke_address, second_invoke_address):
                    if first_addr > second_addr:
                        break

                    elif first_addr < second_addr:
                        task.process_stage = PROC_STAGE_REGISTER
                        break

                # Check if task matches stage 4
                if task.process_stage != PROC_STAGE_REGISTER:
                    self._report.set_passed(task, CONF_STAGE_3)
                    continue

                # # Record stage 4 result
                # result = []
                # for parent in parents:
                #     first_node = [first_tree.get_node(
                #         method_addr) for method_addr in first_tree.rsearch(parent.address)]
                #     second_node = [second_tree.get_node(
                #         method_addr) for method_addr in second_tree.rsearch(parent.address)]

                #     first_method = [self.apkinfo.find_methods_by_addr(
                #         node.identifer) for node in first_node]
                #     second_method = [self.apkinfo.find_methods_by_addr(
                #         node.identifer) for node in second_node]

                #     first_result = [(self.apkinfo.get_function_bytecode(
                #         method, node.data, node.data+26), method) for method, node in zip(first_method, first_node)]
                #     second_result = [(self.apkinfo.get_function_bytecode(
                #         method, node.data, node.data+26), method) for method, node in zip(second_method, second_node)]

                #     result.append(first_result, second_result)


            if task.process_stage == PROC_STAGE_REGISTER:
                # Stage 5 - Handling the same register
                # Currently scan the first parents.
                permissions = task.permissions
                try:
                    registers = self.check_register(permissions[0], task.first_tree, permissions[1], task.second_tree, task.parent)
                except Exception:
                    pass

                if any(registers):
                    critical_indexes = [index for index, is_critical in enumerate(registers) if is_critical]
                    
                    task.used_registers = critical_indexes
                    self._report.set_passed(task, CONF_STAGE_5)
                else:
                    self._report.set_passed(task, CONF_STAGE_4)

    def get_json_report(self):
        return {
            'md5': self.apkinfo.md5,
            'apk_filename': self.apkinfo.filename,
            'size_bytes': self.apkinfo.filesize,
            'threat_level': self._report.get_thread_level(),
            'total_score': self._report.weighted_sum,
            'crimes': self._report.get_json_report()
        }
