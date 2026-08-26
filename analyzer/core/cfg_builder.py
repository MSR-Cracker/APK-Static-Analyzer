"""Control Flow Graph (CFG) Builder: Builds basic block control flow graphs with branch edge classification."""
from typing import List, Dict, Set, Optional
from analyzer.models import DexMethod, MethodCFG, CFGBlock, InstructionDetail


class CFGBuilder:
    """Constructs focused Basic Block Control Flow Graphs for key verification methods."""

    @staticmethod
    def build_for_method(method: DexMethod) -> Optional[MethodCFG]:
        if not method.instructions:
            return None

        instructions = method.instructions
        # Identify block leader offsets
        leaders: Set[int] = {instructions[0].offset}

        # Step 1: Discover all block entry points (leaders)
        for idx, inst in enumerate(instructions):
            if inst.branch_target is not None:
                leaders.add(inst.branch_target)
                # Next instruction is also a leader (fallthrough block)
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].offset)
            elif inst.opcode_name.startswith("return") or inst.opcode_name == "throw":
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].offset)

        sorted_leaders = sorted(list(leaders))
        blocks: List[CFGBlock] = []

        # Step 2: Form basic blocks between consecutive leaders
        for b_idx, start_off in enumerate(sorted_leaders):
            next_start = sorted_leaders[b_idx + 1] if b_idx + 1 < len(sorted_leaders) else 999999
            
            block_insts_objs = [
                inst for inst in instructions
                if start_off <= inst.offset < next_start
            ]
            if not block_insts_objs:
                continue

            block_insts = [
                f"0x{inst.offset:04x}: {inst.opcode_name} {inst.operands}"
                for inst in block_insts_objs
            ]

            last_inst = block_insts_objs[-1]
            end_off = last_inst.offset
            block_id = f"BB_{start_off:04x}"

            successors: List[str] = []
            true_edge: Optional[str] = None
            false_edge: Optional[str] = None
            is_exit = False

            if last_inst.opcode_name.startswith("return") or last_inst.opcode_name == "throw":
                is_exit = True
            elif last_inst.opcode_name.startswith("goto"):
                if last_inst.branch_target is not None:
                    target_id = f"BB_{last_inst.branch_target:04x}"
                    successors.append(target_id)
            elif last_inst.opcode_name.startswith("if-"):
                # Branch taken target (Condition Met)
                if last_inst.branch_target is not None:
                    target_id = f"BB_{last_inst.branch_target:04x}"
                    successors.append(target_id)
                    true_edge = target_id
                # Fallthrough target (Condition Not Met)
                if next_start != 999999:
                    fallthrough_id = f"BB_{next_start:04x}"
                    successors.append(fallthrough_id)
                    false_edge = fallthrough_id
            else:
                # Normal linear flow to next leader
                if next_start != 999999:
                    successors.append(f"BB_{next_start:04x}")

            blocks.append(CFGBlock(
                id=block_id,
                start_offset=start_off,
                end_offset=end_off,
                instructions=block_insts,
                successors=successors,
                predecessors=[],
                true_edge=true_edge,
                false_edge=false_edge,
                is_entry=(b_idx == 0),
                is_exit=is_exit,
            ))

        # Step 3: Compute predecessors across all blocks
        block_map = {b.id: b for b in blocks}
        for b in blocks:
            for succ_id in b.successors:
                if succ_id in block_map:
                    if b.id not in block_map[succ_id].predecessors:
                        block_map[succ_id].predecessors.append(b.id)

        return MethodCFG(
            method_signature=f"{method.class_name}->{method.method_name}{method.signature}",
            class_name=method.class_name,
            dex_file=method.dex_file,
            blocks=blocks,
        )
