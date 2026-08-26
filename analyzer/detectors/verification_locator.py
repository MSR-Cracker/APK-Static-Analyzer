"""Boolean Verification & Call Site Locator: Traces data flow from boolean calls to conditionals across all DEX files."""
from typing import List, Dict, Set, Tuple, Optional
from analyzer.models import (
    DexMethod, BooleanMethodCandidate, BooleanVerificationLocation, CallSiteFinding
)
from analyzer.detectors.base import BaseDetector


class BooleanVerificationLocator(BaseDetector):
    """Traces invoke-* -> move-result vX -> if-* branch flows to map gating locations."""

    def __init__(self, methods: List[DexMethod], candidates: List[BooleanMethodCandidate]):
        super().__init__(methods)
        self.candidates = candidates

    def detect(self) -> Tuple[List[BooleanVerificationLocation], List[CallSiteFinding]]:
        verifications: List[BooleanVerificationLocation] = []
        call_sites: List[CallSiteFinding] = []

        # Map candidate identifiers
        candidate_map: Dict[str, BooleanMethodCandidate] = {}
        for c in self.candidates:
            candidate_map[f"{c.class_name}->{c.method_name}"] = c
            candidate_map[f"{c.class_name}.{c.method_name}"] = c
            candidate_map[f"{c.class_name}->{c.method_name}{c.signature}"] = c

        for caller_m in self.methods:
            if not caller_m.instructions:
                continue

            instructions = caller_m.instructions
            for idx, inst in enumerate(instructions):
                # Look for invocations of boolean candidates
                if not inst.opcode_name.startswith("invoke-"):
                    continue

                target_ref = inst.referenced_method or ""
                target_base = target_ref.split("(")[0]

                cand = candidate_map.get(target_ref) or candidate_map.get(target_base)
                if not cand:
                    # Also check if target_ref matches method_name of a candidate on same class
                    for c in self.candidates:
                        if c.class_name in target_ref and f"->{c.method_name}" in target_ref:
                            cand = c
                            break

                if not cand:
                    continue

                # We found a call site!
                call_offset = inst.offset
                args = inst.registers

                # Look ahead for move-result
                result_reg: Optional[str] = None
                branch_opcode: Optional[str] = None
                branch_inst = None
                following_lines: List[str] = []

                # Scan up to 8 instructions following the invocation
                for lookahead in range(1, min(9, len(instructions) - idx)):
                    next_inst = instructions[idx + lookahead]
                    following_lines.append(f"0x{next_inst.offset:04x}: {next_inst.opcode_name} {next_inst.operands}")

                    if next_inst.opcode_name in ("move-result", "move-result/from16", "move-result/16"):
                        if not result_reg:
                            result_reg = next_inst.registers[0] if next_inst.registers else "v0"

                    elif next_inst.opcode_name.startswith("if-"):
                        # Check if conditional tests our result_reg
                        if result_reg and result_reg in next_inst.registers:
                            branch_opcode = next_inst.opcode_name
                            branch_inst = next_inst
                            break
                        elif not result_reg and lookahead <= 2:
                            # Direct test
                            branch_opcode = next_inst.opcode_name
                            branch_inst = next_inst
                            result_reg = next_inst.registers[0] if next_inst.registers else "v0"
                            break

                # Determine branch targets and effects
                true_target_str = "UNKNOWN"
                false_target_str = "UNKNOWN"
                true_effect = "UNKNOWN"
                false_effect = "UNKNOWN"
                effect_summary = f"Direct gate check on {cand.method_name}()"
                evidence: List[str] = []

                if branch_inst and branch_inst.branch_target is not None:
                    taken_target = branch_inst.branch_target
                    fallthrough_target = instructions[idx + lookahead + 1].offset if (idx + lookahead + 1 < len(instructions)) else branch_inst.offset + 2

                    true_target_str = f"0x{taken_target:04x}"
                    false_target_str = f"0x{fallthrough_target:04x}"

                    # Semantic effect analysis on branches
                    # if-nez (branch taken when != 0 / TRUE)
                    # if-eqz (branch taken when == 0 / FALSE)
                    if branch_opcode == "if-nez":
                        true_effect = "Condition TRUE: executes branch target (Premium feature path)"
                        false_effect = "Condition FALSE: fallthrough to lock / paywall path"
                        effect_summary = f"Validates '{cand.method_name}() == true' -> unlocks feature path at 0x{taken_target:04x}"
                    elif branch_opcode == "if-eqz":
                        true_effect = "Condition FALSE: jumps to locked / paywall / exit handler"
                        false_effect = "Condition TRUE: fallthrough unlocks premium feature path"
                        effect_summary = f"Checks '{cand.method_name}() == false' -> jumps to paywall handler at 0x{taken_target:04x}"
                    else:
                        true_effect = f"Branch taken to 0x{taken_target:04x}"
                        false_effect = f"Fallthrough to 0x{fallthrough_target:04x}"

                    evidence.append(f"Result register '{result_reg}' evaluated with '{branch_opcode}' at offset 0x{branch_inst.offset:04x}")
                    evidence.append(f"Taken Target: {true_target_str} ({true_effect})")
                    evidence.append(f"Fallthrough Target: {false_target_str} ({false_effect})")

                snippet_lines = [f"0x{inst.offset:04x}: {inst.opcode_name} {inst.operands}"] + following_lines
                snippet_text = "\n".join(snippet_lines)

                # Record Call Site Finding
                cs = CallSiteFinding(
                    caller_class=caller_m.class_name,
                    caller_method=caller_m.method_name,
                    caller_signature=caller_m.signature,
                    dex_file=caller_m.dex_file,
                    source_apk=caller_m.source_apk,
                    instruction_offset=call_offset,
                    called_class=cand.class_name,
                    called_method=cand.method_name,
                    called_signature=cand.signature,
                    arguments=args,
                    move_result_register=result_reg,
                    following_instructions=following_lines,
                    conditional_branch=branch_opcode,
                    branch_offset=branch_inst.offset if branch_inst else None,
                    true_branch_target=true_target_str,
                    false_branch_target=false_target_str,
                    true_branch_effect=true_effect,
                    false_branch_effect=false_effect,
                    effect_summary=effect_summary,
                    bytecode_snippet=snippet_text,
                )
                call_sites.append(cs)

                # If a conditional branch was located, record as a Verification Location
                if branch_opcode and result_reg:
                    verif = BooleanVerificationLocation(
                        dex_file=caller_m.dex_file,
                        source_apk=caller_m.source_apk,
                        class_name=caller_m.class_name,
                        method_name=caller_m.method_name,
                        method_signature=caller_m.signature,
                        called_boolean_method=cand.method_name,
                        called_boolean_class=cand.class_name,
                        instruction_offset=call_offset,
                        branch_opcode=branch_opcode,
                        result_register=result_reg,
                        true_branch_target=true_target_str,
                        false_branch_target=false_target_str,
                        true_branch_effect=true_effect,
                        false_branch_effect=false_effect,
                        effect=effect_summary,
                        evidence=evidence,
                        bytecode_snippet=snippet_text,
                    )
                    verifications.append(verif)

        return verifications, call_sites
