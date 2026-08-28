"""Constructor Analyzer.

Inspects <init> and <clinit> methods for billing bootstrap,
premium-state initialization, local entitlement caching, and
remote verification.

The analyzer uses a cheap pre-filter before scanning instructions
so large applications with tens of thousands of constructors remain
practical to analyze.
"""

from typing import List, Set

from analyzer.models import DexMethod, ConstructorFinding
from analyzer.detectors.base import BaseDetector


class ConstructorAnalyzer(BaseDetector):
    """Analyzes constructors for monetization-related state bootstrapping."""

    MONETIZATION_CLASS_KEYWORDS = (
        "billing",
        "purchase",
        "premium",
        "subscription",
        "entitlement",
        "license",
        "paywall",
        "checkout",
        "inapp",
        "iap",
        "useraccount",
        "session",
        "payment",
    )

    BILLING_CALLEE_KEYWORDS = (
        "billingclient",
        "billingclient.newbuilder",
        "launchbillingflow",
        "querypurchases",
        "querypurchasesasync",
        "queryproductdetails",
        "purchases.getinstance",
        "customerinfo",
        "activeentitlements",
        "inappbillingservice",
    )

    LOCAL_STATE_KEYWORDS = (
        "sharedpreferences",
        "getboolean",
        "getstring",
        "getint",
        "getlong",
        "preferences",
        "datastore",
        "room",
        "sqlite",
    )

    NETWORK_KEYWORDS = (
        "retrofit",
        "okhttp",
        "httpurlconnection",
        "volley",
        "apiclient",
        "network",
        "request",
        "enqueue",
        "execute",
    )

    PREMIUM_FIELD_KEYWORDS = (
        "premium",
        "pro",
        "vip",
        "purchased",
        "purchase",
        "entitled",
        "entitlement",
        "is_sub",
        "issubscribed",
        "subscribed",
        "subscription",
        "license",
        "unlocked",
        "ispaid",
    )

    REMOTE_CONFIG_KEYWORDS = (
        "remoteconfig",
        "remote_config",
        "firebase.remoteconfig",
        "fetch",
        "config",
        "experiment",
    )

    def _contains_any(
        self,
        value: str,
        keywords,
    ) -> bool:
        value = (value or "").lower()
        return any(
            keyword in value
            for keyword in keywords
        )

    def _is_monetization_class(
        self,
        class_name: str,
    ) -> bool:
        return self._contains_any(
            class_name,
            self.MONETIZATION_CLASS_KEYWORDS,
        )

    def _quick_callee_flags(
        self,
        callees,
    ):
        """Cheaply classify constructor callees.

        Returns:
            (billing, local, network, remote_config, relevant)
        """

        initializes_billing = False
        reads_local = False
        has_network = False
        loads_remote_config = False

        # Avoid repeatedly lower-casing the same strings.
        for callee in callees or []:
            callee_lower = callee.lower()

            if self._contains_any(
                callee_lower,
                self.BILLING_CALLEE_KEYWORDS,
            ):
                initializes_billing = True

            if self._contains_any(
                callee_lower,
                self.LOCAL_STATE_KEYWORDS,
            ):
                reads_local = True

            if self._contains_any(
                callee_lower,
                self.NETWORK_KEYWORDS,
            ):
                has_network = True

            if self._contains_any(
                callee_lower,
                self.REMOTE_CONFIG_KEYWORDS,
            ):
                loads_remote_config = True

        relevant = (
            initializes_billing
            or reads_local
            or has_network
            or loads_remote_config
        )

        return (
            initializes_billing,
            reads_local,
            has_network,
            loads_remote_config,
            relevant,
        )

    def _find_premium_assignments(
        self,
        method: DexMethod,
    ) -> List[str]:
        """Find premium-related iput/sput field assignments."""

        assigned_fields: List[str] = []

        for inst in method.instructions or []:
            opcode_name = (
                inst.opcode_name or ""
            ).lower()

            if not (
                opcode_name.startswith("iput")
                or opcode_name.startswith("sput")
            ):
                continue

            field = (
                inst.referenced_field
                or ""
            )

            if not field:
                continue

            if self._contains_any(
                field,
                self.PREMIUM_FIELD_KEYWORDS,
            ):
                if field not in assigned_fields:
                    assigned_fields.append(
                        field
                    )

        return assigned_fields

    def _build_finding(
        self,
        method: DexMethod,
        initializes_billing: bool,
        reads_local: bool,
        has_network: bool,
        loads_remote_config: bool,
        assigned_fields: List[str],
    ) -> ConstructorFinding:
        """Build one normalized constructor finding."""

        sets_premium = bool(
            assigned_fields
        )

        evidence: List[str] = []

        if initializes_billing:
            evidence.append(
                "Initializes Billing SDK/client "
                "(SDK bootstrap evidence, not verification by itself)."
            )

        if reads_local:
            evidence.append(
                "Reads local persisted state/preferences."
            )

        if has_network:
            evidence.append(
                "References network/API interaction."
            )

        if loads_remote_config:
            evidence.append(
                "References remote/configuration loading."
            )

        if assigned_fields:
            evidence.append(
                "Assigns premium/entitlement-related "
                f"fields: {assigned_fields[:3]}"
            )

        # --------------------------------------------------------------
        # Verification decision.
        #
        # Billing SDK initialization alone is explicitly NOT verification.
        # Verification requires an entitlement-related field assignment
        # combined with local state or a network path.
        # --------------------------------------------------------------

        verification = "NO"

        if sets_premium and reads_local:
            verification = "YES"
            evidence.append(
                "Constructor initializes premium/entitlement state "
                "from local persisted state."
            )

        elif sets_premium and has_network:
            verification = "YES"
            evidence.append(
                "Constructor initializes premium/entitlement state "
                "in the presence of a network/API path."
            )

        elif sets_premium:
            verification = "UNKNOWN"
            evidence.append(
                "Constructor assigns premium/entitlement fields, "
                "but no local or network verification source was proven."
            )

        elif initializes_billing:
            verification = "NO"
            evidence.append(
                "Billing client bootstrap detected without proven "
                "entitlement verification."
            )

        network_interaction = (
            "YES"
            if has_network
            else "NO"
        )

        field_name = (
            assigned_fields[0]
            if assigned_fields
            else ""
        )

        return ConstructorFinding(
            dex_file=method.dex_file,
            class_name=method.class_name,
            constructor_signature=(
                f"{method.method_name}"
                f"{method.signature}"
            ),
            verification=verification,
            network_interaction=network_interaction,
            source_apk=method.source_apk,
            initializes_billing_client=(
                initializes_billing
            ),
            sets_premium_flags=sets_premium,
            reads_local_state=reads_local,
            loads_remote_config=(
                loads_remote_config
            ),
            called_methods=list(
                method.callees or []
            ),
            evidence=evidence,
            boolean_field_initialized=field_name,
            snippet=(
                method.bytecode_snippet
                or method.decompiled_source
            ),
        )

    def detect(self) -> List[ConstructorFinding]:
        """Analyze only constructors with meaningful monetization evidence."""

        findings: List[ConstructorFinding] = []

        # --------------------------------------------------------------
        # Fast constructor selection.
        #
        # This is important for large APK/APKS files. Do not deeply scan
        # every constructor's instructions unless it has a reason to be
        # considered.
        # --------------------------------------------------------------

        constructors = (
            method
            for method in self.methods
            if method.is_constructor
        )

        for method in constructors:
            class_is_relevant = (
                self._is_monetization_class(
                    method.class_name
                )
            )

            (
                initializes_billing,
                reads_local,
                has_network,
                loads_remote_config,
                callee_relevant,
            ) = self._quick_callee_flags(
                method.callees
            )

            # ----------------------------------------------------------
            # Cheap pre-filter.
            #
            # Non-monetization constructors with no interesting callees
            # cannot produce a useful constructor finding, so skip them
            # without scanning their bytecode instructions.
            # ----------------------------------------------------------

            if not (
                class_is_relevant
                or callee_relevant
            ):
                continue

            # ----------------------------------------------------------
            # Only now inspect iput/sput instructions.
            # ----------------------------------------------------------

            assigned_fields = (
                self._find_premium_assignments(
                    method
                )
            )

            # A class name alone is not sufficient evidence. Keep the
            # constructor only if there is actual monetization-related
            # behavior.
            if not (
                class_is_relevant
                or initializes_billing
                or reads_local
                or has_network
                or loads_remote_config
                or assigned_fields
            ):
                continue

            finding = self._build_finding(
                method=method,
                initializes_billing=(
                    initializes_billing
                ),
                reads_local=reads_local,
                has_network=has_network,
                loads_remote_config=(
                    loads_remote_config
                ),
                assigned_fields=assigned_fields,
            )

            findings.append(
                finding
            )

        # --------------------------------------------------------------
        # Highest-value findings first.
        #
        # YES verification
        #   > premium assignments
        #   > billing initialization/local/network
        #   > generic monetization class
        # --------------------------------------------------------------

        def sort_key(
            finding: ConstructorFinding,
        ):
            if finding.verification == "YES":
                verification_rank = 0
            elif finding.verification == "UNKNOWN":
                verification_rank = 1
            else:
                verification_rank = 2

            evidence_rank = 0

            if finding.sets_premium_flags:
                evidence_rank -= 3

            if finding.initializes_billing_client:
                evidence_rank -= 2

            if finding.reads_local_state:
                evidence_rank -= 2

            if finding.network_interaction == "YES":
                evidence_rank -= 2

            if finding.loads_remote_config:
                evidence_rank -= 1

            return (
                verification_rank,
                evidence_rank,
                finding.class_name.lower(),
                finding.constructor_signature.lower(),
            )

        findings.sort(
            key=sort_key
        )

        return findings
