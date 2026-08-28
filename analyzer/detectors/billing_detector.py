"""Billing Detector.

Detects billing / monetization implementations from static DEX analysis.

Supported families include:
    - Google Play Billing
    - Legacy In-App Billing AIDL
    - RevenueCat
    - Qonversion
    - Adapty
    - Stripe
    - Braintree / PayPal
    - Adyen
    - Razorpay
    - Custom / application-owned billing logic

The detector reports evidence and confidence. It does not modify or bypass
billing, purchase, entitlement, or verification logic.
"""

from typing import List, Dict, Set, Tuple

from analyzer.models import (
    DexMethod,
    BillingFinding,
    Confidence,
)

from analyzer.detectors.base import BaseDetector


class BillingDetector(BaseDetector):
    """Deep multi-vendor billing detector."""

    # ------------------------------------------------------------------
    # Google Play Billing
    # ------------------------------------------------------------------

    GOOGLE_PLAY_BILLING_CLASSES = {
        "com.android.billingclient.api.BillingClient",
        "com.android.billingclient.api.BillingClientImpl",
        "com.android.billingclient.api.Purchase",
        "com.android.billingclient.api.PurchaseHistoryRecord",
        "com.android.billingclient.api.PurchasesUpdatedListener",
        "com.android.billingclient.api.BillingFlowParams",
        "com.android.billingclient.api.SkuDetails",
        "com.android.billingclient.api.SkuDetailsParams",
        "com.android.billingclient.api.QueryProductDetailsParams",
        "com.android.billingclient.api.ProductDetails",
        "com.android.billingclient.api.ProductDetailsResponseListener",
        "com.android.billingclient.api.AcknowledgePurchaseParams",
        "com.android.billingclient.api.ConsumeParams",
        "com.android.billingclient.api.PurchasesResult",
        "com.android.billingclient.api.BillingResult",
    }

    GOOGLE_PLAY_PACKAGE_PREFIXES = (
        "com.android.billingclient.",
        "com.android.billingclient",
    )

    GOOGLE_PLAY_METHOD_PATTERNS = (
        "billingclient",
        "launchbillingflow",
        "querypurchases",
        "querypurchasesasync",
        "queryproductdetails",
        "queryproductdetailsasync",
        "acknowledgepurchase",
        "consumeasync",
        "consumepurchase",
        "isfeatureenabledbilling",
        "getconnectionstate",
        "startconnection",
        "endconnection",
    )

    # ------------------------------------------------------------------
    # Legacy AIDL
    # ------------------------------------------------------------------

    AIDL_CLASSES = {
        "com.android.vending.billing.IInAppBillingService",
        "com.android.vending.billing.IInAppBillingService$Stub",
        "com.android.vending.billing.IInAppBillingService$Stub$Proxy",
    }

    AIDL_PACKAGE_PREFIXES = (
        "com.android.vending.billing.",
    )

    AIDL_METHOD_PATTERNS = (
        "iinappbillingservice",
        "getpurchases",
        "getpurchase",
        "getbuyintent",
        "getbuyintenttoimmediate",
        "consume",
        "consumepurchase",
        "iscapable",
    )

    # ------------------------------------------------------------------
    # RevenueCat
    # ------------------------------------------------------------------

    REVENUECAT_CLASSES = {
        "com.revenuecat.purchases.Purchases",
        "com.revenuecat.purchases.PurchasesConfiguration",
        "com.revenuecat.purchases.CustomerInfo",
        "com.revenuecat.purchases.PurchaserInfo",
        "com.revenuecat.purchases.EntitlementInfos",
        "com.revenuecat.purchases.EntitlementInfo",
        "com.revenuecat.purchases.interfaces.ReceiveCustomerInfoCallback",
    }

    REVENUECAT_PACKAGE = "com.revenuecat.purchases"

    REVENUECAT_METHOD_PATTERNS = (
        "customerinfo",
        "getcustomerinfo",
        "activeentitlements",
        "purchase",
        "restorepurchases",
        "getofferings",
        "purchasepackage",
        "purchaseproduct",
    )

    # ------------------------------------------------------------------
    # Qonversion
    # ------------------------------------------------------------------

    QONVERSION_CLASSES = {
        "com.qonversion.android.sdk.Qonversion",
        "com.qonversion.android.sdk.dto.QUser",
        "com.qonversion.android.sdk.dto.QEntitlement",
    }

    QONVERSION_PACKAGE = (
        "com.qonversion.android"
    )

    # ------------------------------------------------------------------
    # Adapty
    # ------------------------------------------------------------------

    ADAPTY_CLASSES = {
        "com.adapty.Adapty",
        "com.adapty.models.AdaptyProfile",
        "com.adapty.models.AdaptyPaywall",
        "com.adapty.models.AdaptyAccessLevel",
    }

    ADAPTY_PACKAGE = "com.adapty"

    # ------------------------------------------------------------------
    # Payment gateways
    # ------------------------------------------------------------------

    PAYMENT_GATEWAY_PATTERNS = {
        "Stripe": (
            "com.stripe.android",
            "com.stripe.android.PaymentConfiguration",
        ),
        "Braintree / PayPal": (
            "com.braintreepayments.api",
            "com.paypal.android",
        ),
        "Adyen": (
            "com.adyen.checkout",
        ),
        "Razorpay": (
            "com.razorpay",
            "com.razorpay.Checkout",
        ),
    }

    # ------------------------------------------------------------------
    # Generic monetization signals
    # ------------------------------------------------------------------

    MONETIZATION_CLASS_KEYWORDS = (
        "billing",
        "purchase",
        "subscription",
        "entitlement",
        "paywall",
        "payment",
        "checkout",
        "receipt",
        "transaction",
        "license",
        "iap",
        "inapp",
    )

    MONETIZATION_METHOD_KEYWORDS = (
        "purchase",
        "buy",
        "subscribe",
        "subscription",
        "billing",
        "payment",
        "checkout",
        "receipt",
        "transaction",
        "entitlement",
        "license",
        "verify",
        "validate",
    )

    PURCHASE_STRING_PATTERNS = (
        "inapp_purchase",
        "in-app-purchase",
        "purchase_token",
        "purchasetoken",
        "order_id",
        "orderid",
        "product_id",
        "productid",
        "subscription_id",
        "subscriptionid",
        "entitlement",
        "receipt",
        "billingclient",
        "com.android.vending.billing",
        "com.android.billingclient",
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unique_append(
        values: List[str],
        value: str,
    ) -> None:
        """Append a value only once."""

        if value and value not in values:
            values.append(
                value
            )

    @staticmethod
    def _contains_any(
        text: str,
        patterns,
    ) -> bool:
        """Case-insensitive substring matching."""

        if not text:
            return False

        lower = text.lower()

        return any(
            pattern.lower() in lower
            for pattern in patterns
        )

    @staticmethod
    def _contains_pattern(
        text: str,
        patterns,
    ) -> List[str]:
        """Return all matching patterns."""

        if not text:
            return []

        lower = text.lower()

        return [
            pattern
            for pattern in patterns
            if pattern.lower() in lower
        ]

    # ------------------------------------------------------------------
    # Main detector
    # ------------------------------------------------------------------

    def detect(self) -> BillingFinding:
        """Analyze all available DEX methods."""

        evidence: List[str] = []

        billing_classes: Set[str] = set()
        billing_methods: Set[str] = set()

        providers: List[str] = []

        has_google_play = False
        has_aidl = False
        has_revenuecat = False
        has_qonversion = False
        has_adapty = False
        has_custom = False

        google_play_version = "Unknown"

        # --------------------------------------------------------------
        # Build class inventory.
        # --------------------------------------------------------------

        unique_classes: Set[str] = {
            (
                method.class_name or ""
            )
            for method in self.methods
            if method.class_name
        }

        unique_types: Set[str] = set()

        for method in self.methods:
            unique_types.update(
                method.types_referenced or []
            )

        all_class_evidence = (
            unique_classes
            | unique_types
        )

        # --------------------------------------------------------------
        # 1. Google Play Billing
        # --------------------------------------------------------------

        found_gpb = (
            unique_classes
            .intersection(
                self.GOOGLE_PLAY_BILLING_CLASSES
            )
        )

        gpb_package_classes = {
            class_name
            for class_name in all_class_evidence
            if any(
                class_name.startswith(prefix)
                for prefix in self.GOOGLE_PLAY_PACKAGE_PREFIXES
            )
        }

        if found_gpb or gpb_package_classes:
            has_google_play = True

            self._unique_append(
                providers,
                "Google Play Billing Library",
            )

            billing_classes.update(
                found_gpb
            )

            billing_classes.update(
                gpb_package_classes
            )

            evidence.append(
                (
                    "Google Play Billing classes/packages "
                    f"detected: "
                    f"{sorted(list(gpb_package_classes or found_gpb))[:5]}"
                )
            )

            # Version-family estimation.
            has_product_details = any(
                (
                    "ProductDetails"
                    in class_name
                )
                for class_name
                in gpb_package_classes
            )

            has_sku_details = any(
                (
                    "SkuDetails"
                    in class_name
                )
                for class_name
                in gpb_package_classes
            )

            if has_product_details:
                google_play_version = (
                    "v5+ family "
                    "(ProductDetails API)"
                )
            elif has_sku_details:
                google_play_version = (
                    "v3-v4 family "
                    "(SkuDetails API)"
                )
            else:
                google_play_version = (
                    "Detected; exact version unknown"
                )

        # --------------------------------------------------------------
        # 2. Legacy AIDL
        # --------------------------------------------------------------

        found_aidl = (
            unique_classes
            .intersection(
                self.AIDL_CLASSES
            )
        )

        aidl_package_classes = {
            class_name
            for class_name in all_class_evidence
            if any(
                class_name.startswith(prefix)
                for prefix in self.AIDL_PACKAGE_PREFIXES
            )
        }

        if found_aidl or aidl_package_classes:
            has_aidl = True

            self._unique_append(
                providers,
                "In-App Billing AIDL",
            )

            billing_classes.update(
                found_aidl
            )

            billing_classes.update(
                aidl_package_classes
            )

            evidence.append(
                (
                    "Legacy IInAppBillingService "
                    "AIDL interface detected."
                )
            )

        # --------------------------------------------------------------
        # 3. RevenueCat
        # --------------------------------------------------------------

        found_rc = (
            unique_classes
            .intersection(
                self.REVENUECAT_CLASSES
            )
        )

        revenuecat_classes = {
            class_name
            for class_name in all_class_evidence
            if class_name.startswith(
                self.REVENUECAT_PACKAGE
            )
        }

        if found_rc or revenuecat_classes:
            has_revenuecat = True

            self._unique_append(
                providers,
                "RevenueCat SDK",
            )

            billing_classes.update(
                revenuecat_classes
            )

            evidence.append(
                (
                    "RevenueCat Purchases SDK "
                    "classes/packages detected."
                )
            )

        # --------------------------------------------------------------
        # 4. Qonversion
        # --------------------------------------------------------------

        qonversion_classes = {
            class_name
            for class_name in all_class_evidence
            if class_name.startswith(
                self.QONVERSION_PACKAGE
            )
        }

        if qonversion_classes:
            has_qonversion = True

            self._unique_append(
                providers,
                "Qonversion SDK",
            )

            billing_classes.update(
                qonversion_classes
            )

            evidence.append(
                "Qonversion SDK detected."
            )

        # --------------------------------------------------------------
        # 5. Adapty
        # --------------------------------------------------------------

        adapty_classes = {
            class_name
            for class_name in all_class_evidence
            if class_name.startswith(
                self.ADAPTY_PACKAGE
            )
        }

        if adapty_classes:
            has_adapty = True

            self._unique_append(
                providers,
                "Adapty SDK",
            )

            billing_classes.update(
                adapty_classes
            )

            evidence.append(
                "Adapty SDK detected."
            )

        # --------------------------------------------------------------
        # 6. Payment gateways
        # --------------------------------------------------------------

        for provider_name, patterns in (
            self.PAYMENT_GATEWAY_PATTERNS.items()
        ):
            matched = {
                class_name
                for class_name in all_class_evidence
                if any(
                    pattern.lower()
                    in class_name.lower()
                    for pattern in patterns
                )
            }

            if matched:
                self._unique_append(
                    providers,
                    provider_name,
                )

                billing_classes.update(
                    matched
                )

                evidence.append(
                    (
                        f"{provider_name} SDK integration "
                        f"detected: "
                        f"{sorted(matched)[:3]}"
                    )
                )

        # --------------------------------------------------------------
        # 7. Deep method analysis
        # --------------------------------------------------------------

        custom_method_count = 0
        monetization_method_count = 0

        for method in self.methods:
            class_name = (
                method.class_name or ""
            )

            method_name = (
                method.method_name or ""
            )

            class_lower = (
                class_name.lower()
            )

            method_lower = (
                method_name.lower()
            )

            method_repr = (
                f"{class_name}->{method_name}"
            )

            callee_text = " ".join(
                method.callees or []
            ).lower()

            field_text = " ".join(
                method.fields_referenced or []
            ).lower()

            type_text = " ".join(
                method.types_referenced or []
            ).lower()

            string_text = " ".join(
                method.strings_referenced or []
            ).lower()

            # ----------------------------------------------------------
            # Google Billing method calls
            # ----------------------------------------------------------

            google_hits = self._contains_pattern(
                callee_text,
                self.GOOGLE_PLAY_METHOD_PATTERNS,
            )

            if google_hits:
                has_google_play = True

                self._unique_append(
                    providers,
                    "Google Play Billing Library",
                )

                billing_methods.add(
                    method_repr
                )

                evidence.append(
                    (
                        f"Method '{method_repr}' calls "
                        "Google Play Billing API "
                        f"pattern(s): {google_hits[:4]}"
                    )
                )

            # ----------------------------------------------------------
            # AIDL method calls
            # ----------------------------------------------------------

            aidl_hits = self._contains_pattern(
                callee_text,
                self.AIDL_METHOD_PATTERNS,
            )

            if (
                aidl_hits
                or "iinappbillingservice"
                in callee_text
            ):
                has_aidl = True

                self._unique_append(
                    providers,
                    "In-App Billing AIDL",
                )

                billing_methods.add(
                    method_repr
                )

                evidence.append(
                    (
                        f"Method '{method_repr}' "
                        "references legacy billing "
                        "IPC/AIDL."
                    )
                )

            # ----------------------------------------------------------
            # RevenueCat calls
            # ----------------------------------------------------------

            if (
                self._contains_any(
                    callee_text,
                    (
                        self.REVENUECAT_PACKAGE,
                        "purchases.getinstance",
                        "customerinfo",
                        "activeentitlements",
                        "restorepurchases",
                    ),
                )
            ):
                has_revenuecat = True

                self._unique_append(
                    providers,
                    "RevenueCat SDK",
                )

                billing_methods.add(
                    method_repr
                )

                evidence.append(
                    (
                        f"Method '{method_repr}' "
                        "references RevenueCat purchase/"
                        "entitlement APIs."
                    )
                )

            # ----------------------------------------------------------
            # Qonversion calls
            # ----------------------------------------------------------

            if (
                self.QONVERSION_PACKAGE
                in callee_text
                or "qonversion"
                in callee_text
            ):
                has_qonversion = True

                self._unique_append(
                    providers,
                    "Qonversion SDK",
                )

                billing_methods.add(
                    method_repr
                )

            # ----------------------------------------------------------
            # Adapty calls
            # ----------------------------------------------------------

            if (
                self.ADAPTY_PACKAGE
                in callee_text
                or "adapty"
                in callee_text
            ):
                has_adapty = True

                self._unique_append(
                    providers,
                    "Adapty SDK",
                )

                billing_methods.add(
                    method_repr
                )

            # ----------------------------------------------------------
            # Generic monetization class/method evidence
            # ----------------------------------------------------------

            class_hits = self._contains_pattern(
                class_lower,
                self.MONETIZATION_CLASS_KEYWORDS,
            )

            method_hits = self._contains_pattern(
                method_lower,
                self.MONETIZATION_METHOD_KEYWORDS,
            )

            if class_hits or method_hits:
                monetization_method_count += 1

                billing_classes.add(
                    class_name
                )

            # ----------------------------------------------------------
            # Custom billing evidence from fields/types
            # ----------------------------------------------------------

            custom_field_hits = self._contains_pattern(
                field_text,
                self.MONETIZATION_CLASS_KEYWORDS,
            )

            custom_type_hits = self._contains_pattern(
                type_text,
                self.MONETIZATION_CLASS_KEYWORDS,
            )

            if (
                custom_field_hits
                or custom_type_hits
            ):
                custom_method_count += 1

                billing_classes.add(
                    class_name
                )

                if not (
                    has_google_play
                    or has_aidl
                    or has_revenuecat
                    or has_qonversion
                    or has_adapty
                ):
                    billing_methods.add(
                        method_repr
                    )

            # ----------------------------------------------------------
            # Purchase-related string constants
            # ----------------------------------------------------------

            string_hits = self._contains_pattern(
                string_text,
                self.PURCHASE_STRING_PATTERNS,
            )

            if string_hits:
                custom_method_count += 1

                self._unique_append(
                    billing_classes,
                    class_name,
                )

                evidence.append(
                    (
                        f"Method '{method_repr}' "
                        "references purchase/billing "
                        f"string pattern(s): "
                        f"{string_hits[:5]}"
                    )
                )

        # --------------------------------------------------------------
        # 8. Determine custom architecture
        # --------------------------------------------------------------

        official_provider_present = any(
            (
                has_google_play,
                has_aidl,
                has_revenuecat,
                has_qonversion,
                has_adapty,
            )
        )

        if (
            not official_provider_present
            and (
                custom_method_count >= 2
                or monetization_method_count >= 3
            )
        ):
            has_custom = True

            self._unique_append(
                providers,
                "Custom In-App Purchase Architecture",
            )

            evidence.append(
                (
                    "No recognized commercial billing SDK "
                    "was required to explain the detected "
                    "purchase/entitlement-related code; "
                    "multiple application-owned billing "
                    "signals were found."
                )
            )

        # --------------------------------------------------------------
        # 9. Remove generic/false-positive classes where possible
        # --------------------------------------------------------------

        billing_classes = {
            class_name
            for class_name in billing_classes
            if class_name
        }

        billing_methods = {
            method_name
            for method_name in billing_methods
            if method_name
        }

        # --------------------------------------------------------------
        # 10. Deduplicate evidence/providers
        # --------------------------------------------------------------

        providers = list(
            dict.fromkeys(
                providers
            )
        )

        unique_evidence = list(
            dict.fromkeys(
                evidence
            )
        )

        # --------------------------------------------------------------
        # 11. Confidence calculation
        # --------------------------------------------------------------

        evidence_score = 0

        if has_google_play:
            evidence_score += 3

        if has_aidl:
            evidence_score += 3

        if has_revenuecat:
            evidence_score += 3

        if has_qonversion:
            evidence_score += 2

        if has_adapty:
            evidence_score += 2

        if billing_methods:
            evidence_score += 2

        if billing_classes:
            evidence_score += 1

        if custom_method_count >= 2:
            evidence_score += 1

        if len(unique_evidence) >= 5:
            evidence_score += 1

        if evidence_score >= 6:
            confidence = Confidence.HIGH
        elif evidence_score >= 3:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        if not providers:
            unique_evidence.append(
                (
                    "No recognized commercial billing SDK, "
                    "legacy billing AIDL interface, or "
                    "sufficient custom billing evidence "
                    "was detected."
                )
            )

            confidence = Confidence.LOW

        return BillingFinding(
            has_google_play=has_google_play,
            has_aidl=has_aidl,
            has_revenuecat=has_revenuecat,
            has_qonversion=has_qonversion,
            has_adapty=has_adapty,
            has_custom=has_custom,
            google_play_version=(
                google_play_version
                if has_google_play
                else None
            ),
            providers_detected=providers,
            billing_classes=sorted(
                billing_classes
            ),
            billing_methods=sorted(
                billing_methods
            ),
            evidence=unique_evidence,
            confidence=confidence,
        )
