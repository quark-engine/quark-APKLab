from treelib import Tree

from quark.android.apk import Apkinfo
from quark.common.method import MethodId
from quark.core.analysis import QuarkAnalysis, CONF_STAGE_NONE, CONF_STAGE_2, CONF_STAGE_3, CONF_STAGE_4, \
    CONF_STAGE_5, CONF_STAGE_1
from quark.core.rule import QuarkRule

MAX_SEARCH_LAYER = 3
CHECK_LIST = "".join(["\t[" + "\u2713" + "]"])

MAX_REG_COUNT = 257
RETURN_REG_INDEX = 256


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk):
        self.apkinfo = Apkinfo(apk)
        self._report = QuarkAnalysis()

    def find_common_parent(self, first: MethodId, second: MethodId, search_depth=3):
        assert not first == second

        first_tree, second_tree = (Tree(deep=search_depth), Tree(deep=search_depth))
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
                        second_tree.create_node(identifier=upper.address, data=addr, parent=method.address)
                    second_next_leaves.add(upper)
            second_leaves = second_next_leaves

            first_next_leaves = set()
            for method in first_leaves:
                for addr, upper in self.apkinfo.find_upper_methods(method):
                    if not first_tree.contains(upper.address):
                        first_tree.create_node(identifier=upper.address, data=addr, parent=method.address)
                    first_next_leaves.add(upper)
            first_leaves = first_next_leaves

        return first_tree, second_tree, parents

    def check_register_in_method(self, method: MethodId, registers, start_offset=-1, end_offset=-1):
        """
        * end_offset_included
        """

        # Fetch target ranger of instructions
        instructions = [ins for ins in self.apkinfo.get_function_bytecode(method, start_offset, end_offset)]
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
            self.check_register_in_method(direct_parent, registers, -1, direct_invoke_address)

        return registers

    def check_register_downward(self, method: MethodId, invoke_path: list, parent: MethodId, registers):
        assert len(invoke_path) > 1
        invoke_path.pop()

        invoke_path.reverse()

        invoke_address, _ = invoke_path.pop()
        while any(registers) and invoke_path:
            next_invoke_address, child_method = invoke_path[-1]
            registers = self.check_register_in_method(child_method, registers, invoke_address, -1)
            invoke_address = next_invoke_address

        return registers

    def check_register(self, first: MethodId, first_tree: Tree, second: MethodId, second_tree: Tree, parent: MethodId,
                       registers=None):
        first_node = [first_tree.get_node(method_address) for method_address in first_tree.rsearch(parent.address)]

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

        second_path = [(node.data, self.apkinfo.find_methods_by_addr(node.identifier)) for node in second_node]

        registers = self.check_register_upward(second, second_path, parent, registers)
        # del second_path

        registers = self.check_register_in_method(parent, registers, first_last_invoke_address,
                                                  second_last_invoke_address)

        first_path = [(node.data, self.apkinfo.find_methods_by_addr(node.identifier)) for node in first_node]
        registers = self.check_register_downward(first, first_path, parent, registers)
        # del first_path

        return registers

    def analysis(self, rule: QuarkRule):
        # Log rule
        self._report.add_rule(rule)

        # Stage 1 - Check Permission
        passed_permissions = ( permission for permission in rule.x1_permission if permission in self.apkinfo.permissions)

        # Stage 1 passes
        self._report.set_rule_pass(rule, CONF_STAGE_1, 'Permission', rule.x1_permission)

        if len(passed_permissions) != self.apkinfo.permissions:
            return

        # Stage 2 - Contain native api
        # Stage 3 - All native apis exist
        # TODO - make invoke.address as identifier of tree node, method address stores at the data property of nodes.
        #        To support same method with different child.
        rule_api = []
        for api in rule.x2n3n4_comb:
            methods = self.apkinfo.find_methods(api['class'], api['method'], api['descriptor'])
            if methods:
                rule_api.append(methods[0])

        if len(rule_api) == 0:
            return

        # Stage 2 passes
        self._report.set_rule_pass(rule, CONF_STAGE_2, 'NativeApi', rule_api)

        if rule_api != 2:
            return

        # Stage 3 passes
        self._report.set_rule_pass(rule, CONF_STAGE_3)

        # Stage 4 - Check sequence
        # Score the most danger condition.
        # Check if apis exist in the same call graph
        first_tree, second_tree, parents = self.find_common_parent(rule_api[0], rule_api[1])
        if not parents:
            return

        passed_parents = []
        for parent in parents:
            first_invoke_address = [first_tree.get_node(method_addr).data for method_addr in
                                    first_tree.rsearch(parent.address)]
            first_invoke_address.pop()  # Drop None at the last
            second_invoke_address = [second_tree.get_node(method_addr).data for method_addr in
                                     second_tree.rsearch(parent.address)]
            second_invoke_address.pop()  # Drop None at the last

            for first_addr, second_addr in zip(first_invoke_address, second_invoke_address):
                if first_addr > second_addr:
                    break
                elif first_addr < second_addr:
                    passed_parents.append(parent)

        if not passed_parents:
            return

        # Record stage 4 result
        self._report.set_rule_pass(rule, CONF_STAGE_4, 'Sequence', rule.x2n3n4_comb)
        # self._report.set_rule_pass(rule, CONF_STAGE_4, 'InvokePath', )
        # TODO - need to check what to pass.

        # Stage 5 - Handling the same register
        # Currently scan the first parents.
        passed_registers = []
        for parent in parents:
            try:
                registers = self.check_register(rule_api[0], first_tree, rule_api[1], second_tree, parent)
            except Exception:
                continue

            if any(registers):
                critical_indexes = [ index for index, is_critical in enumerate(registers) if is_critical]
                passed_registers.append(critical_indexes)

        self._report.set_rule_pass(rule, CONF_STAGE_5, 'UsedRegister', passed_registers)