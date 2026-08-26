"""Detector for Billing, Payment SDKs, and in-app purchase implementations."""
import re
from typing import List, Dict, Set
from analyzer.models import DexMethod, BillingFinding
from analyzer.detectors.base import BaseDetector


class BillingDetector(BaseDetector):
    """Detects Google Play Billing, RevenueCat, Stripe, PayPal, and custom purchase mechanisms."""

    GOOGLE_PLAY_PATTERNS = [
        "com.android.billingclient",
        "BillingClient",
        "PurchasesUpdatedListener",
        "acknowledgePurchase",
        "consumePurchase",
        "queryPurchases",
        "queryPurchasesAsync",
        "queryProductDetailsAsync",
        "querySkuDetailsAsync",
        "ProductDetails",
        "SkuDetails",
        "Purchase",
        "Purchase$PurchasesResult",
        "BillingResult",
        "BillingFlowParams",
    ]

    REVENUECAT_PATTERNS = [
        "com.revenuecat.purchases",
        "Purchases.sharedInstance",
        "getCustomerInfo",
        "getOfferings",
        "purchasePackage",
        "EntitlementInfo",
    ]

    STRIPE_PATTERNS = [
        "com.stripe.android",
        "PaymentSheet",
        "PaymentLauncher",
        "createPaymentMethod",
        "confirmPayment",
    ]

    PAYPAL_PATTERNS = [
        "com.paypal.android",
        "PayPalCheckout",
        "PayPalDataCollector",
    ]

    WEBVIEW_PAYMENT_PATTERNS = [
        "WebView",
        "loadUrl",
        "addJavascriptInterface",
        "checkout",
        "stripe.com",
        "paypal.com",
        "pay.google.com",
    ]

    def detect(self) -> BillingFinding:
        providers: Set[str] = set()
        features: Set[str] = set()
        billing_classes: Set[str] = set()
        billing_methods: Set[str] = set()
        evidence: List[str] = []

        has_play_billing = False
        has_revenuecat = False
        has_stripe = False
        has_paypal = False
        has_webview = False
        has_custom = False

        for m in self.methods:
            # Check Google Play Billing
            for pat in self.GOOGLE_PLAY_PATTERNS:
                if pat.lower() in m.class_name.lower() or pat.lower() in m.method_name.lower():
                    has_play_billing = True
                    providers.add("Google Play Billing")
                    features.add(f"Play Billing ({pat})")
                    billing_classes.add(m.class_name)
                    billing_methods.add(f"{m.class_name}->{m.method_name}")
                # Check callees
                for callee in m.callees:
                    if pat.lower() in callee.lower():
                        has_play_billing = True
                        providers.add("Google Play Billing")
                        billing_methods.add(f"{m.class_name}->{m.method_name}")
                        if f"Invokes {pat}" not in evidence:
                            evidence.append(f"Method {m.class_name}->{m.method_name} in {m.dex_file} invokes {callee}")

            # Check RevenueCat
            for pat in self.REVENUECAT_PATTERNS:
                if pat.lower() in m.class_name.lower() or any(pat.lower() in c.lower() for c in m.callees):
                    has_revenuecat = True
                    providers.add("RevenueCat")
                    features.add("RevenueCat SDK")
                    billing_classes.add(m.class_name)
                    if "RevenueCat detected" not in evidence:
                        evidence.append(f"RevenueCat references found in {m.class_name} ({m.dex_file})")

            # Check Stripe
            for pat in self.STRIPE_PATTERNS:
                if pat.lower() in m.class_name.lower() or any(pat.lower() in c.lower() for c in m.callees):
                    has_stripe = True
                    providers.add("Stripe Android SDK")
                    billing_classes.add(m.class_name)

            # Check PayPal
            for pat in self.PAYPAL_PATTERNS:
                if pat.lower() in m.class_name.lower() or any(pat.lower() in c.lower() for c in m.callees):
                    has_paypal = True
                    providers.add("PayPal SDK")
                    billing_classes.add(m.class_name)

            # Check WebView payment flows
            for s in m.strings_referenced:
                for w_pat in ["checkout", "payment/verify", "pay.google.com", "stripe.com/checkout", "paypal.com/checkout"]:
                    if w_pat in s.lower():
                        has_webview = True
                        providers.add("WebView / Web Checkout")
                        evidence.append(f"Payment URL string '{s}' found in {m.class_name}->{m.method_name}")

            # Check custom purchase APIs
            for s in m.strings_referenced:
                if any(kw in s.lower() for kw in ["/api/purchase", "/api/subscription", "/verify_receipt", "/validate_token"]):
                    has_custom = True
                    providers.add("Custom Backend Purchase API")
                    evidence.append(f"Custom purchase API endpoint string '{s}' referenced in {m.class_name}->{m.method_name} ({m.dex_file})")

        if not providers:
            # Check for general purchase keyword classes
            for m in self.methods:
                if re.search(r"(?:Billing|Purchase|Subscription|Premium|Entitlement|InApp)", m.class_name, re.IGNORECASE):
                    has_custom = True
                    providers.add("Custom In-App Billing / Store Manager")
                    billing_classes.add(m.class_name)

        return BillingFinding(
            providers_detected=sorted(list(providers)),
            features_detected=sorted(list(features)),
            billing_classes=sorted(list(billing_classes))[:30],
            billing_methods=sorted(list(billing_methods))[:30],
            has_play_billing=has_play_billing,
            has_revenuecat=has_revenuecat,
            has_stripe=has_stripe,
            has_paypal=has_paypal,
            has_webview_payment=has_webview,
            has_custom_billing=has_custom,
            evidence=evidence[:25],
        )
