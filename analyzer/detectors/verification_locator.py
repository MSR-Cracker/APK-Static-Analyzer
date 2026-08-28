"""Boolean Verification Locator.

Traces boolean verification call sites using:

    invoke-* -> move-result -> register aliases -> conditional branch

The locator only upgrades a boolean candidate to CONFIRMED when the
returned register can be reasonably connected to a conditional branch.
"""

from typing import List, Dict, Set, Tuple, Optional

from analyzer.models import (
    DexMethod,
    BooleanMethodCandidate,
    BooleanVerificationLocation,
    CallSiteFinding,
    StatusState,
    InstructionDetail,
)

from analyzer.detectors.base import BaseDetector


class BooleanVerificationLocator(BaseDetector):
    """Cross-DEX control-flow/data-flow locator for boolean verification calls."""

    INVOKE_OPCODES = {
        0x6E,  # invoke-virtual
        0x6F,  # invoke-super
        0x70,  # invoke-direct
        0x71,  # invoke-static
        0x72,  # invoke-interface
        0x74,  # invoke-virtual/range
        0x75,  # invoke-super/range
        0x76,  # invoke-direct/range
        0x77,  # invoke-static/range
        0x78,  # invoke-interface/range
    }

    MOVE_RESULT_OPCODES = {
        0x0A,  # move-result
        0x0B,  # move-result-wide
        0x0C,  # move-result-object
    }

    # Boolean conditions.
    CONDITIONAL_OPCODES = {
        0x32,  # if-eq
        0x33,  # if-ne
        0x34,  # if-lt
        0x35,  # if-ge
        0x36,  # if-gt
        0x37,  # if-le
        0x38,  # if-eqz
        0x39,  # if-nez
        0x3A,  # if-ltz
        0x3B,  # if-gez
        0x3C,  # if-gtz
        0x3D,  # if-lez
    }

    # Register-producing move operations that preserve the value.
    REGISTER_MOVE_OPCODES = {
        0x01,  # move
        0x02,  # move/from16
        0x03,  # move/16
        0x07,  # move-object
        0x08,  # move-object/from16
        0x09,  # move-object/16
    }

    def __init__(
        self,
        methods: List[DexMethod],
        candidates: List[BooleanMethodCandidate],
    ):
        super().__init__(methods)
        self.candidates = candidates

    # ------------------------------------------------------------------
    # Candidate indexing
    # ------------------------------------------------------------------

    def _build_candidate_map(
        self,
    ) -> Dict[str, BooleanMethodCandidate]:
        """Build exact and class/method indexes for candidate lookup."""

        cand_map: Dict[str, BooleanMethodCandidate] = {}

        for candidate in self.candidates:
            full_key = (
                f"{candidate.class_name}"
                f"->{candidate.method_name}"
                f"{candidate.signature}"
            )

            base_key = (
                f"{candidate.class_name}"
                f"->{candidate.method_name}"
            )

            cand_map[full_key] = candidate

            # Keep the first candidate for a base key. Exact signatures
            # remain preferred.
            if base_key not in cand_map:
                cand_map[base_key] = candidate

        return cand_map

    def _find_candidate(
        self,
        referenced_method: str,
        candidate_map: Dict[str, BooleanMethodCandidate],
    ) -> Optional[BooleanMethodCandidate]:
        """Resolve a referenced method against the candidate index."""

        if not referenced_method:
            return None

        # Exact signature.
        candidate = candidate_map.get(referenced_method)

        if candidate:
            return candidate

        # Class->method without signature.
        base_ref = referenced_method.split("(", 1)[0]
        candidate = candidate_map.get(base_ref)

        if candidate:
            return candidate

        return None

    # ------------------------------------------------------------------
    # Instruction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _instruction_registers(
        instruction: InstructionDetail,
    ) -> List[str]:
        """Return normalized register operands."""

        return [
            reg
            for reg in (instruction.registers or [])
            if isinstance(reg, str)
            and reg.startswith("v")
        ]

    @staticmethod
    def _is_invoke(
        instruction: InstructionDetail,
    ) -> bool:
        return instruction.opcode in (
            BooleanVerificationLocator.INVOKE_OPCODES
        )

    @staticmethod
    def _is_conditional(
        instruction: InstructionDetail,
    ) -> bool:
        return instruction.opcode in (
            BooleanVerificationLocator.CONDITIONAL_OPCODES
        )

    @staticmethod
    def _is_move(
        instruction: InstructionDetail,
    ) -> bool:
        return instruction.opcode in (
            BooleanVerificationLocator.REGISTER_MOVE_OPCODES
        )

    @staticmethod
    def _is_move_result(
        instruction: InstructionDetail,
    ) -> bool:
        return instruction.opcode in (
            BooleanVerificationLocator.MOVE_RESULT_OPCODES
        )

    # ------------------------------------------------------------------
    # Branch helpers
    # ------------------------------------------------------------------

    def _branch_registers(
        self,
        instruction: InstructionDetail,
    ) -> Set[str]:
        """Get registers actually tested by a conditional branch."""

        return set(
            self._instruction_registers(
                instruction
            )
        )

    def _branch_fallthrough(
        self,
        instruction: InstructionDetail,
    ) -> int:
        """Calculate fallthrough in Dalvik code-unit offsets.

        InstructionDetail.offset is already stored in code units.
        """

        # All supported conditional if-* instructions are 22t/21t
        # and occupy 2 code units.
        return instruction.offset + 2

    def _branch_targets(
        self,
        instruction: InstructionDetail,
    ) -> Tuple[str, str]:
        """Return true/branch target and fallthrough target."""

        if instruction.branch_target is not None:
            true_target = (
                f"0x{instruction.branch_target:04x}"
            )
        else:
            true_target = ""

        false_target = (
            f"0x{self._branch_fallthrough(instruction):04x}"
        )

        return true_target, false_target

    # ------------------------------------------------------------------
    # Branch semantics
    # ------------------------------------------------------------------

    def _describe_branch(
        self,
        instruction: InstructionDetail,
        result_register: Optional[str],
        true_target: str,
        false_target: str,
    ) -> Tuple[str, str, str, str]:
        """Describe the semantic meaning of the branch."""

        opcode = instruction.opcode
        reg = result_register or "result"

        if opcode == 0x38:
            # if-eqz
            return (
                "Paywall / Feature Locked (result == false)",
                "Premium / Unlocked Feature Path (result != false)",
                (
                    f"Gating: if {reg} == 0, execution jumps to "
                    f"{true_target}; otherwise execution continues "
                    f"through {false_target}."
                ),
                "FALSE -> locked path; TRUE -> unlocked path",
            )

        if opcode == 0x39:
            # if-nez
            return (
                "Premium / Unlocked Feature Path (result == true)",
                "Paywall / Feature Locked (result == false)",
                (
                    f"Gating: if {reg} != 0, execution jumps to "
                    f"{true_target}; otherwise execution continues "
                    f"through {false_target}."
                ),
                "TRUE -> unlocked path; FALSE -> locked path",
            )

        if opcode == 0x32:
            return (
                "Branch taken when compared values are equal",
                "Branch not taken when compared values differ",
                (
                    f"Boolean comparison branch using {reg}; "
                    f"taken -> {true_target}, fallthrough -> "
                    f"{false_target}."
                ),
                "Equality comparison",
            )

        if opcode == 0x33:
            return (
                "Branch taken when compared values differ",
                "Branch not taken when compared values are equal",
                (
                    f"Boolean comparison branch using {reg}; "
                    f"taken -> {true_target}, fallthrough -> "
                    f"{false_target}."
                ),
                "Inequality comparison",
            )

        if opcode == 0x34:
            condition = "< 0"
        elif opcode == 0x35:
            condition = ">= 0"
        elif opcode == 0x36:
            condition = "> 0"
        elif opcode == 0x37:
            condition = "<= 0"
        elif opcode == 0x3A:
            condition = "< 0"
        elif opcode == 0x3B:
            condition = ">= 0"
        elif opcode == 0x3C:
            condition = "> 0"
        elif opcode == 0x3D:
            condition = "<= 0"
        else:
            condition = "condition"

        return (
            f"Branch condition true ({reg} {condition})",
            f"Branch condition false ({reg} {condition})",
            (
                f"Conditional branch tests {reg} "
                f"({instruction.opcode_name}); taken -> "
                f"{true_target}, fallthrough -> {false_target}."
            ),
            f"Conditional test: {condition}",
        )

    # ------------------------------------------------------------------
    # Data-flow tracing
    # ------------------------------------------------------------------

    def _trace_boolean_result(
        self,
        instructions: List[InstructionDetail],
        invoke_index: int,
        window: int = 12,
    ) -> Tuple[
        Optional[str],
        Set[str],
        Optional[InstructionDetail],
        List[str],
    ]:
        """Trace invoke result into a conditional branch.

        Returns:

            result register,
            aliases,
            matching branch,
            following instruction strings
        """

        following: List[str] = []

        result_register: Optional[str] = None
        tracked_registers: Set[str] = set()

        max_index = min(
            invoke_index + window + 1,
            len(instructions),
        )

        for idx in range(
            invoke_index + 1,
            max_index,
        ):
            instruction = instructions[idx]

            following.append(
                (
                    f"0x{instruction.offset:04x}: "
                    f"{instruction.opcode_name} "
                    f"{instruction.operands}"
                )
            )

            # ----------------------------------------------------------
            # The instruction immediately after invoke must normally
            # contain move-result. If another instruction occurs first,
            # the invoke result cannot be safely associated with a
            # later register.
            # ----------------------------------------------------------

            if idx == invoke_index + 1:
                if self._is_move_result(
                    instruction
                ):
                    regs = self._instruction_registers(
                        instruction
                    )

                    if regs:
                        result_register = regs[0]
                        tracked_registers.add(
                            result_register
                        )
                        continue

                # A boolean invoke without move-result is not enough
                # to prove a branch uses its result.
                break

            # ----------------------------------------------------------
            # Register-preserving moves.
            # ----------------------------------------------------------

            if self._is_move(instruction):
                regs = self._instruction_registers(
                    instruction
                )

                if len(regs) >= 2:
                    destination = regs[0]
                    source = regs[1]

                    if source in tracked_registers:
                        tracked_registers.add(
                            destination
                        )

                        continue

                    # Writing to a tracked register destroys the
                    # previous value.
                    if destination in tracked_registers:
                        tracked_registers.discard(
                            destination
                        )

                continue

            # ----------------------------------------------------------
            # Branch testing tracked result.
            # ----------------------------------------------------------

            if self._is_conditional(
                instruction
            ):
                branch_regs = self._branch_registers(
                    instruction
                )

                if (
                    tracked_registers
                    and branch_regs.intersection(
                        tracked_registers
                    )
                ):
                    return (
                        result_register,
                        tracked_registers,
                        instruction,
                        following,
                    )

                # A conditional branch that does not use the tracked
                # register is irrelevant. Continue looking only if it
                # does not overwrite tracked state.
                continue

            # ----------------------------------------------------------
            # Conservative invalidation.
            #
            # If an instruction writes to a tracked register through
            # something other than a simple move, the previous boolean
            # value should no longer be considered reliable.
            # ----------------------------------------------------------

            written_registers = self._written_registers(
                instruction
            )

            if written_registers.intersection(
                tracked_registers
            ):
                tracked_registers.difference_update(
                    written_registers
                )

                if not tracked_registers:
                    break

        return (
            result_register,
            tracked_registers,
            None,
            following,
        )

    def _written_registers(
        self,
        instruction: InstructionDetail,
    ) -> Set[str]:
        """Best-effort destination register identification.

        InstructionDetail does not explicitly expose a destination field,
        so this uses known Dalvik instruction families.
        """

        opcode = instruction.opcode
        regs = self._instruction_registers(
            instruction
        )

        if not regs:
            return set()

        # Destination is normally the first register for these families.
        destination_opcodes = {
            # move-result
            0x0A, 0x0B, 0x0C,

            # move
            0x01, 0x02, 0x03,
            0x04, 0x05, 0x06,
            0x07, 0x08, 0x09,

            # const
            0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C,

            # new-instance / new-array
            0x22, 0x23,

            # array get
            0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A,

            # instance get
            0x52, 0x53, 0x54, 0x55,
            0x56, 0x57, 0x58,

            # static get
            0x60, 0x61, 0x62, 0x63,
            0x64, 0x65, 0x66,

            # arithmetic / conversion
            0x7B, 0x7C, 0x7D, 0x7E,
            0x7F, 0x80, 0x81, 0x82,
            0x83, 0x84, 0x85, 0x86,
            0x87, 0x88, 0x89, 0x8A,
            0x8B, 0x8C, 0x8D, 0x8E,
            0x8F,

            0x90, 0x91, 0x92, 0x93,
            0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9A,

            0xB0, 0xB1, 0xB2, 0xB3,
            0xB4, 0xB5, 0xB6, 0xB7,
            0xB8, 0xB9, 0xBA,

            0xD0, 0xD1, 0xD2, 0xD3,
            0xD4, 0xD5, 0xD6, 0xD7,
            0xD8, 0xD9, 0xDA, 0xDB,
            0xDC, 0xDD, 0xDE, 0xDF,
            0xE0, 0xE1, 0xE2,
        }

        if opcode in destination_opcodes:
            return {regs[0]}

        return set()

    # ------------------------------------------------------------------
    # Main detection
    # ------------------------------------------------------------------

    def detect(
        self,
    ) -> Tuple[
        List[BooleanVerificationLocation],
        List[CallSiteFinding],
    ]:
        """Locate boolean verification call sites."""

        verification_locations: List[
            BooleanVerificationLocation
        ] = []

        call_sites: List[
            CallSiteFinding
        ] = []

        if not self.candidates or not self.methods:
            return [], []

        candidate_map = self._build_candidate_map()

        # Avoid duplicate confirmation entries.
        confirmed_locations: Set[
            Tuple[str, str, int, str]
        ] = set()

        for caller_method in self.methods:
            instructions = (
                caller_method.instructions
            )

            if not instructions:
                continue

            for index, instruction in enumerate(
                instructions
            ):
                # ------------------------------------------------------
                # Only inspect invoke-*.
                # ------------------------------------------------------

                if not self._is_invoke(
                    instruction
                ):
                    continue

                if not instruction.referenced_method:
                    continue

                candidate = self._find_candidate(
                    instruction.referenced_method,
                    candidate_map,
                )

                if not candidate:
                    continue

                caller_signature = (
                    f"{caller_method.class_name}"
                    f"->{caller_method.method_name}"
                    f"{caller_method.signature}"
                )

                # Keep candidate caller graph synchronized.
                if (
                    caller_signature
                    not in candidate.callers
                ):
                    candidate.callers.append(
                        caller_signature
                    )

                # ------------------------------------------------------
                # Trace result register and branch.
                # ------------------------------------------------------

                (
                    result_register,
                    tracked_registers,
                    branch_instruction,
                    following_instructions,
                ) = self._trace_boolean_result(
                    instructions,
                    index,
                )

                conditional_branch: Optional[str] = None
                branch_offset: Optional[int] = None

                true_target = ""
                false_target = ""

                true_effect = "UNKNOWN"
                false_effect = "UNKNOWN"

                effect_summary = ""

                if branch_instruction:
                    conditional_branch = (
                        branch_instruction.opcode_name
                    )

                    branch_offset = (
                        branch_instruction.offset
                    )

                    (
                        true_target,
                        false_target,
                    ) = self._branch_targets(
                        branch_instruction
                    )

                    (
                        true_effect,
                        false_effect,
                        effect_summary,
                        _,
                    ) = self._describe_branch(
                        branch_instruction,
                        result_register,
                        true_target,
                        false_target,
                    )

                # ------------------------------------------------------
                # Call-site finding is useful even if a branch was not
                # found. This distinguishes "called" from "verified gate".
                # ------------------------------------------------------

                call_site = CallSiteFinding(
                    caller_class=caller_method.class_name,
                    caller_method=caller_method.method_name,
                    caller_signature=caller_method.signature,
                    dex_file=caller_method.dex_file,
                    source_apk=caller_method.source_apk,
                    instruction_offset=instruction.offset,
                    called_class=candidate.class_name,
                    called_method=candidate.method_name,
                    called_signature=candidate.signature,
                    arguments=instruction.registers or [],
                    move_result_register=result_register,
                    following_instructions=following_instructions,
                    conditional_branch=conditional_branch,
                    branch_offset=branch_offset,
                    true_branch_target=true_target,
                    false_branch_target=false_target,
                    true_branch_effect=true_effect,
                    false_branch_effect=false_effect,
                    effect_summary=effect_summary,
                    bytecode_snippet=(
                        caller_method.bytecode_snippet
                        or ""
                    ),
                )

                call_sites.append(
                    call_site
                )

                # ------------------------------------------------------
                # No result/branch means this is only a call site.
                # Do NOT mark candidate CONFIRMED.
                # ------------------------------------------------------

                if (
                    not result_register
                    or not branch_instruction
                    or branch_offset is None
                ):
                    continue

                # ------------------------------------------------------
                # Deduplicate exact location.
                # ------------------------------------------------------

                location_key = (
                    caller_method.dex_file,
                    caller_signature,
                    instruction.offset,
                    candidate.class_name
                    + "->"
                    + candidate.method_name,
                )

                if location_key in confirmed_locations:
                    continue

                confirmed_locations.add(
                    location_key
                )

                # ------------------------------------------------------
                # Build evidence.
                # ------------------------------------------------------

                evidence = [
                    (
                        "Boolean candidate invoked at "
                        f"offset 0x{instruction.offset:04x}: "
                        f"'{candidate.class_name}"
                        f"->{candidate.method_name}"
                        f"{candidate.signature}'"
                    ),
                    (
                        "Return value captured in register "
                        f"'{result_register}'"
                    ),
                    (
                        "Return register remains tracked through "
                        f"{len(tracked_registers)} register alias(es)"
                    ),
                    (
                        f"Conditional branch '{conditional_branch}' "
                        f"uses the returned boolean value at "
                        f"offset 0x{branch_offset:04x}"
                    ),
                    (
                        f"Branch target: {true_target}; "
                        f"fallthrough: {false_target}"
                    ),
                    effect_summary,
                ]

                verification_location = (
                    BooleanVerificationLocation(
                        dex_file=caller_method.dex_file,
                        source_apk=caller_method.source_apk,
                        class_name=caller_method.class_name,
                        method_name=caller_method.method_name,
                        method_signature=caller_method.signature,
                        called_boolean_method=candidate.method_name,
                        called_boolean_class=candidate.class_name,
                        instruction_offset=instruction.offset,
                        branch_opcode=conditional_branch,
                        result_register=result_register,
                        true_branch_target=true_target,
                        false_branch_target=false_target,
                        true_branch_effect=true_effect,
                        false_branch_effect=false_effect,
                        effect=effect_summary,
                        evidence=evidence,
                        bytecode_snippet=(
                            caller_method.bytecode_snippet
                            or ""
                        ),
                    )
                )

                verification_locations.append(
                    verification_location
                )

                # ------------------------------------------------------
                # Only now is the candidate CONFIRMED.
                # ------------------------------------------------------

                candidate.status = (
                    StatusState.CONFIRMED
                )

        return (
            verification_locations,
            call_sites,
        )
