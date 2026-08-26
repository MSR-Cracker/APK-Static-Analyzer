"""Billing Detector: Identifies Google Play Billing (v3-v7), AIDL, RevenueCat, Qonversion, Adapty, Stripe, and custom implementations."""
from typing import List, Dict, Set
from analyzer.models import DexMethod, BillingFinding, Confidence
from analyzer.detectors.base import BaseDetector


class BillingDetector(BaseDetector):
    """Deep multi-vendor billing detector checking SDK classes, AIDL interfaces, methods, and Dalvik calls."""

    GOOGLE_PLAY_BILLING_CLASSES = {
        "com.android.billingclient.api.BillingClient",
        "com.android.billingclient.api.BillingClientImpl",
        "com.android.billingclient.api.Purchase",
        "com.android.billingclient.api.PurchaseHistoryRecord",
        "com.android.billingclient.api.PurchasesUpdatedListener",
        "com.android.billingclient.api.BillingFlowParams",
        "com.android.billingclient.api.SkuDetailsParams",
        "com.android.billingclient.api.QueryProductDetailsParams",
        "com.android.billingclient.api.ProductDetailsResponseListener",
        "com.android.billingclient.api.AcknowledgePurchaseParams",
        "com.android.billingclient.api.ConsumeParams",
    }

    AIDL_CLASSES = {
        "com.android.vending.billing.IInAppBillingService",
        "com.android.vending.billing.IInAppBillingService$Stub",
        "com.android.vending.billing.IInAppBillingService$Stub$Proxy",
    }

    REVENUECAT_CLASSES = {
        "com.revenuecat.purchases.Purchases",
        "com.revenuecat.purchases.PurchasesConfiguration",
        "com.revenuecat.purchases.CustomerInfo",
        "com.revenuecat.purchases.PurchaserInfo",
        "com.revenuecat.purchases.interfaces.ReceiveCustomerInfoCallback",
    }

    QONVERSION_CLASSES = {
        "com.qonversion.android.sdk.Qonversion",
        "com.qonversion.android.sdk.dto.QUser",
        "com.qonversion.android.sdk.dto.QEntitlement",
    }

    ADAPTY_CLASSES = {
        "com.adapty.Adapty",
        "com.adapty.models.AdaptyProfile",
    }

    PAYMENT_GATEWAY_PATTERNS = {
        "Stripe": ["com.stripe.android", "com.stripe.android.PaymentConfiguration"],
        "Braintree / PayPal": ["com.braintreepayments.api", "com.paypal.android"],
        "Adyen": ["com.adyen.checkout"],
        "Razorpay": ["com.razorpay.Checkout"],
    }

    def detect(self) -> BillingFinding:
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

        unique_classes = {m.class_name for m in self.methods}

        # 1. Google Play Billing check
        found_gpb = unique_classes.intersection(self.GOOGLE_PLAY_BILLING_CLASSES)
        if found_gpb:
            has_google_play = True
            providers.append("Google Play Billing Library")
            billing_classes.update(found_gpb)
            evidence.append(f"Google Play Billing classes present: {list(found_gpb)[:3]}")

            # Check for version indicators
            if any("ProductDetails" in c for c in found_gpb):
                google_play_version = "v5.x - v7.x (ProductDetails / Subscriptions)"
            elif any("SkuDetails" in c for c in found_gpb):
                google_play_version = "v3.x - v4.x (SkuDetails)"

        # 2. AIDL check
        found_aidl = unique_classes.intersection(self.AIDL_CLASSES)
        if found_aidl:
            has_aidl = True
            providers.append("In-App Billing AIDL (Legacy IInAppBillingService)")
            billing_classes.update(found_aidl)
            evidence.append("Found legacy IInAppBillingService AIDL IPC interface")

        # 3. RevenueCat check
        found_rc = unique_classes.intersection(self.REVENUECAT_CLASSES)
        if found_rc or any("com.revenuecat.purchases" in c for c in unique_classes):
            has_revenuecat = True
            providers.append("RevenueCat SDK")
            evidence.append("RevenueCat Purchases SDK detected")

        # 4. Qonversion / Adapty check
        if any("com.qonversion.android" in c for c in unique_classes):
            has_qonversion = True
            providers.append("Qonversion SDK")
            evidence.append("Qonversion SDK detected")

        if any("com.adapty" in c for c in unique_classes):
            has_adapty = True
            providers.append("Adapty SDK")
            evidence.append("Adapty SDK detected")

        # 5. Payment gateways
        for name, patterns in self.PAYMENT_GATEWAY_PATTERNS.items():
            for pat in patterns:
                if any(pat in c for c in unique_classes):
                    providers.append(name)
                    evidence.append(f"{name} SDK integration detected ({pat})")
                    break

        # 6. Deep method scan for billing API calls
        for m in self.methods:
            m_lower = m.method_name.lower()
            c_lower = m.class_name.lower()

            if any(b_kw in c_lower for b_kw in ["billing", "purchase", "subscription", "entitlement", "paywall"]):
                billing_classes.add(m.class_name)

            for callee in m.callees:
                callee_lower = callee.lower()
                if "billingclient" in callee_lower or "launchbillingflow" in callee_lower or "querypurchases" in callee_lower:
                    has_google_play = True
                    billing_methods.add(f"{m.class_name}->{m.method_name}")
                    evidence.append(f"Method '{m.method_name}' calls Google Play Billing API '{callee}'")
                elif "iinappbillingservice" in callee_lower:
                    has_aidl = True
                    billing_methods.add(f"{m.class_name}->{m.method_name}")
                    evidence.append(f"Method '{m.method_name}' invokes legacy AIDL IPC: '{callee}'")
                elif "purchases.getinstance" in callee_lower or "customerinfo" in callee_lower:
                    has_revenuecat = True
                    billing_methods.add(f"{m.class_name}->{m.method_name}")

            for s in m.strings_referenced:
                s_lower = s.lower()
                if "com.android.vending.billing.inapp" in s_lower or "inapp_purchase" in s_lower or "subs" in s_lower:
                    evidence.append(f"References in-app billing SKU/action string: '{s}'")

        # Check for Custom / Unknown Billing if no official SDK but custom keywords
        if not providers and (len(billing_classes) >= 1 or len(billing_methods) >= 1):
            has_custom = True
            providers.append("Custom In-App Purchase Architecture")
            evidence.append("Custom payment/entitlement management logic detected")

        # Deduplicate evidence
        unique_ev = sorted(list(set(evidence)))

        if providers:
            confidence = Confidence.HIGH if len(unique_ev) >= 2 else Confidence.MEDIUM
        else:
            confidence = Confidence.LOW
            unique_ev.append("No commercial billing libraries or AIDL payment interfaces detected")

        return BillingFinding(
            has_google_play=has_google_play,
            has_aidl=has_aidl,
            has_revenuecat=has_revenuecat,
            has_qonversion=has_qonversion,
            has_adapty=has_adapty,
            has_custom=has_custom,
            google_play_version=google_play_version if has_google_play else None,
            providers_detected=providers,
            billing_classes=sorted(list(billing_classes)),
            billing_methods=sorted(list(billing_methods)),
            evidence=unique_ev,
            confidence=confidence,
        )
