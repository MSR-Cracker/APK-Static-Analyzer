"""Network Analyzer: Extracts endpoints, domains, Retrofit/OkHttp/Volley/WebView flows, and maps them to payment routines."""
import re
from urllib.parse import urlparse
from typing import List, Dict, Set, Tuple
from analyzer.models import DexMethod, NetworkEndpoint
from analyzer.detectors.base import BaseDetector


class NetworkAnalyzer(BaseDetector):
    """Discovers remote URLs, API domains, Retrofit annotations, and maps them to billing logic."""

    URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+(?:\:[0-9]+)?(?:/[^\s"\'<>{}\\]*)?')
    DOMAIN_REGEX = re.compile(r'https?://([a-zA-Z0-9.-]+)')

    PURCHASE_ENDPOINT_KEYWORDS = [
        "verify", "purchase", "subscription", "receipt", "validate",
        "entitlement", "license", "order", "checkout", "billing", "token", "auth/status"
    ]

    def detect(self) -> List[NetworkEndpoint]:
        endpoints: List[NetworkEndpoint] = []
        seen_urls: Set[str] = set()

        for m in self.methods:
            # Check client library usage
            client_lib = "HttpURLConnection"
            for callee in m.callees:
                if "retrofit" in callee.lower():
                    client_lib = "Retrofit"
                elif "okhttp" in callee.lower():
                    client_lib = "OkHttp"
                elif "volley" in callee.lower():
                    client_lib = "Volley"
                elif "webview" in callee.lower():
                    client_lib = "WebView"

            # Check strings for URLs
            for s in m.strings_referenced:
                urls = self.URL_REGEX.findall(s)
                for u in urls:
                    if u in seen_urls:
                        continue
                    seen_urls.add(u)

                    parsed = urlparse(u)
                    domain = parsed.netloc or ""

                    # Correlation analysis
                    is_purchase = any(kw in u.lower() for kw in self.PURCHASE_ENDPOINT_KEYWORDS)
                    relevance_level = "LOW"
                    relevance_reason = ""

                    if is_purchase:
                        relevance_level = "HIGH"
                        relevance_reason = f"Endpoint URL matches purchase/receipt validation path keyword and is referenced in {m.class_name}->{m.method_name}"
                    elif any(b_kw in m.class_name.lower() for b_kw in ["billing", "purchase", "pay", "entitlement"]):
                        is_purchase = True
                        relevance_level = "MEDIUM"
                        relevance_reason = f"Endpoint is referenced directly from billing/entitlement class '{m.class_name}'"
                    elif "google.com" in domain or "googleapis.com" in domain:
                        relevance_level = "LOW"
                        relevance_reason = "Google service / API infrastructure endpoint"
                    else:
                        relevance_level = "NONE"
                        relevance_reason = "General application network endpoint"

                    http_method = None
                    if any(kw in u.lower() for kw in ["/verify", "/validate", "/checkout", "/order", "entitlement"]):
                        http_method = "POST"
                    elif "get" in m.method_name.lower():
                        http_method = "GET"

                    ep = NetworkEndpoint(
                        url=u,
                        domain=domain,
                        http_method=http_method,
                        client_library=client_lib,
                        referenced_from_class=m.class_name,
                        referenced_from_method=m.method_name,
                        dex_file=m.dex_file,
                        source_apk=m.source_apk,
                        is_purchase_related=is_purchase,
                        relevance_level=relevance_level,
                        relevance_reason=relevance_reason,
                    )
                    endpoints.append(ep)

        # Sort with purchase-related endpoints first
        rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NONE": 3}
        endpoints.sort(key=lambda e: (rank.get(e.relevance_level, 4), e.domain))
        return endpoints
