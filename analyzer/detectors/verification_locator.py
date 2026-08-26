"""Boolean Verification Locator: Traces invoke-* call sites, move-result data flow, and conditional branch gating."""
from typing import List, Dict, Set, Tuple, Optional
from analyzer.models import (
    DexMethod, BooleanMethodCandidate, BooleanVerificationLocation,
    CallSiteFinding, StatusState, InstructionDetail
)
from analyzer.detectors.base import BaseDetector


class BooleanVerificationLocator(BaseDetector):
    """Deep cross-DEX control-flow and data-flow locator for boolean verification call sites."""

    def __init__(self, methods: List[DexMethod], candidates: List[BooleanMethodCandidate]):
        super().__init__(methods)
        self.candidates = candidates

    def detect(self) -> Tuple[List[BooleanVerificationLocation], List[CallSiteFinding]]:
        verification_locations: List[BooleanVerificationLocation] = []
        call_sites: List[CallSiteFinding] = []

        if not self.candidates or not self.methods:
            return [], []

        # Index candidates by matching keys (canonical signature and simple name)
        cand_map: Dict[str, BooleanMethodCandidate] = {}
        for cand in self.candidates:
            cand_map[f"{cand.class_name}->{cand.method_name}{cand.signature}"] = cand
            cand_map[f"{cand.class_name}->{cand.method_name}"] = cand

        # Iterate through every method and its disassembled instructions
        for caller_m in self.methods:
            instructions = caller_m.instructions
            if not instructions:
                continue

            for idx, inst in enumerate(instructions):
                # Check for invocation opcodes (invoke-virtual, direct, static, super, interface, range)
                if not (inst.opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72) or inst.opcode in (0x74, 0x75, 0x76, 0x77, 0x78)):
                    continue

                if not inst.referenced_method:
                    continue

                # Match against candidates
                target_cand = None
                if inst.referenced_method in cand_map:
                    target_cand = cand_map[inst.referenced_method]
                else:
                    base_ref = inst.referenced_method.split("(")[0]
                    if base_ref in cand_map:
                        target_cand = cand_map[base_ref]

                if not target_cand:
                    continue

                # We found a verified call site!
                caller_sig = f"{caller_m.class_name}->{caller_m.method_name}{caller_m.signature}"
                if caller_sig not in target_cand.callers:
                    target_cand.callers.append(caller_sig)

                # Data-flow analysis: Trace return value register
                move_result_reg: Optional[str] = None
                following_insts: List[str] = []
                conditional_branch: Optional[str] = None
                branch_offset: Optional[int] = None
                true_target: str = ""
                false_target: str = ""
                true_effect: str = "UNKNOWN"
                false_effect: str = "UNKNOWN"
                effect_summary: str = ""

                # Look at immediate and subsequent instructions
                tracked_regs: Set[str] = set()

                for f_idx in range(idx + 1, min(idx + 8, len(instructions))):
                    f_inst = instructions[f_idx]
                    following_insts.append(f"0x{f_inst.offset:04x}: {f_inst.opcode_name} {f_inst.operands}")

                    # Step 1: Capture move-result
                    if f_idx == idx + 1 and f_inst.opcode in (0x0A, 0x0B, 0x0C):
                        move_result_reg = f_inst.operands.strip()
                        tracked_regs.add(move_result_reg)
                        continue

                    # Step 2: Track register moves (aliases)
                    if f_inst.opcode in (0x01, 0x02, 0x03) and len(f_inst.registers) >= 2:
                        dst_reg, src_reg = f_inst.registers[0], f_inst.registers[1]
                        if src_reg in tracked_regs:
                            tracked_regs.add(dst_reg)

                    # Step 3: Check conditional branches testing tracked register
                    if f_inst.opcode_name.startswith("if-") and (not conditional_branch):
                        has_tracked_reg = any(r in tracked_regs for r in f_inst.registers) if tracked_regs else (f_idx <= idx + 2)
                        if has_tracked_reg or f_idx <= idx + 2:
                            conditional_branch = f_inst.opcode_name
                            branch_offset = f_inst.offset

                            if f_inst.branch_target is not None:
                                true_target = f"0x{f_inst.branch_target:04x}"
                            fallthrough_off = f_inst.offset + 2
                            false_target = f"0x{fallthrough_off:04x}"

                            # Semantics of Dalvik if-eqz vs if-nez
                            if f_inst.opcode == 0x38:  # if-eqz vX (if vX == 0 / false)
                                true_effect = "Paywall / Feature Locked (v==0)"
                                false_effect = "Premium / Unlocked Feature Path (v!=0)"
                                effect_summary = f"Gating: if {move_result_reg or 'result'} is FALSE, jumps to {true_target} (Lock/Paywall); otherwise proceeds to unlocked feature path."
                            elif f_inst.opcode == 0x39:  # if-nez vX (if vX != 0 / true)
                                true_effect = "Premium / Unlocked Feature Path (v!=0)"
                                false_effect = "Paywall / Feature Locked (v==0)"
                                effect_summary = f"Gating: if {move_result_reg or 'result'} is TRUE, jumps to {true_target} (Unlocked Feature); otherwise falls through to Paywall/Lock."
                            else:
                                true_effect = f"Branch condition met -> {true_target}"
                                false_effect = f"Branch condition not met -> {false_target}"
                                effect_summary = f"Conditional branch {f_inst.opcode_name} on {', '.join(f_inst.registers)}"
                            break

                # Create CallSiteFinding
                cs_finding = CallSiteFinding(
                    caller_class=caller_m.class_name,
                    caller_method=caller_m.method_name,
                    caller_signature=caller_m.signature,
                    dex_file=caller_m.dex_file,
                    source_apk=caller_m.source_apk,
                    instruction_offset=inst.offset,
                    called_class=target_cand.class_name,
                    called_method=target_cand.method_name,
                    called_signature=target_cand.signature,
                    arguments=inst.registers,
                    move_result_register=move_result_reg,
                    following_instructions=following_insts,
                    conditional_branch=conditional_branch,
                    branch_offset=branch_offset,
                    true_branch_target=true_target,
                    false_branch_target=false_target,
                    true_branch_effect=true_effect,
                    false_branch_effect=false_effect,
                    effect_summary=effect_summary,
                    bytecode_snippet=caller_m.bytecode_snippet or "",
                )
                call_sites.append(cs_finding)

                # If a conditional branch was located, create a BooleanVerificationLocation
                if conditional_branch and branch_offset is not None:
                    verif_loc = BooleanVerificationLocation(
                        dex_file=caller_m.dex_file,
                        source_apk=caller_m.source_apk,
                        class_name=caller_m.class_name,
                        method_name=caller_m.method_name,
                        method_signature=caller_m.signature,
                        called_boolean_method=target_cand.method_name,
                        called_boolean_class=target_cand.class_name,
                        instruction_offset=inst.offset,
                        branch_opcode=conditional_branch,
                        result_register=move_result_reg or "v0",
                        true_branch_target=true_target,
                        false_branch_target=false_target,
                        true_branch_effect=true_effect,
                        false_branch_effect=false_effect,
                        effect=effect_summary,
                        evidence=[
                            f"Invokes boolean check '{target_cand.class_name}->{target_cand.method_name}' at offset 0x{inst.offset:04x}",
                            f"Captures return value in register '{move_result_reg or 'vX'}'",
                            f"Evaluates access condition using '{conditional_branch}' at offset 0x{branch_offset:04x}",
                            f"Path bifurcation: True -> {true_target} ({true_effect}); False -> {false_target} ({false_effect})",
                        ],
                        bytecode_snippet=caller_m.bytecode_snippet or "",
                    )
                    verification_locations.append(verif_loc)
                    # UPGRADE candidate to CONFIRMED since verified call site with branch gating exists!
                    target_cand.status = StatusState.CONFIRMED

        return verification_locations, call_sites
