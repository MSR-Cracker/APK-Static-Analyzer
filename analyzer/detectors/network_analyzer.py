"""Network Analyzer.

Static analysis of network endpoints and their relationship to application
payment/purchase-related code.

This detector is informational only:
it discovers URLs, domains, networking libraries, HTTP hints, and correlations
with methods that appear relevant to purchase/billing/entitlement logic.

It does not modify, bypass, disable, or patch application verification logic.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Set, Tuple, Optional

from analyzer.models import DexMethod, NetworkEndpoint
from analyzer.detectors.base import BaseDetector


class NetworkAnalyzer(BaseDetector):
    """Discovers network endpoints and correlates them with analyzed methods."""

    # ------------------------------------------------------------------
    # URL / domain detection
    # ------------------------------------------------------------------

    URL_REGEX = re.compile(
        r"""(?i)\b
        https?://
        [a-z0-9.-]+
        (?::[0-9]{1,5})?
        (?:/[^\s"'<>`{}\\]*)?
        """,
        re.VERBOSE,
    )

    DOMAIN_REGEX = re.compile(
        r"""(?i)\b
        https?://
        ([a-z0-9.-]+)
        (?::[0-9]{1,5})?
        """,
        re.VERBOSE,
    )

    # ------------------------------------------------------------------
    # Relevance indicators
    # ------------------------------------------------------------------

    PURCHASE_ENDPOINT_KEYWORDS = (
        "verify",
        "verification",
        "purchase",
        "purchases",
        "subscription",
        "subscriptions",
        "receipt",
        "receipts",
        "validate",
        "validation",
        "entitlement",
        "entitlements",
        "license",
        "licence",
        "order",
        "orders",
        "checkout",
        "billing",
        "payment",
        "payments",
        "transaction",
        "transactions",
        "iap",
        "inapp",
        "in-app",
        "token",
        "auth/status",
        "purchase/status",
        "subscription/status",
        "entitlement/status",
    )

    PURCHASE_CLASS_KEYWORDS = (
        "billing",
        "purchase",
        "payment",
        "paywall",
        "entitlement",
        "subscription",
        "receipt",
        "checkout",
        "transaction",
        "license",
        "iap",
        "inapp",
    )

    PURCHASE_METHOD_KEYWORDS = (
        "purchase",
        "buy",
        "billing",
        "payment",
        "subscribe",
        "subscription",
        "receipt",
        "verify",
        "validate",
        "validation",
        "entitlement",
        "license",
        "transaction",
        "checkout",
        "order",
    )

    NETWORK_LIBRARY_NAMES = (
        ("retrofit", "Retrofit"),
        ("okhttp", "OkHttp"),
        ("volley", "Volley"),
        ("webview", "WebView"),
        ("httpurlconnection", "HttpURLConnection"),
        ("apache.http", "ApacheHttp"),
        ("java.net.http", "JavaHttpClient"),
        ("ktor", "Ktor"),
        ("ktor.client", "Ktor"),
        ("fuel", "Fuel"),
        ("unirest", "Unirest"),
    )

    # Methods/classes commonly involved in HTTP operations.
    HTTP_METHOD_HINTS = {
        "get": "GET",
        "post": "POST",
        "put": "PUT",
        "patch": "PATCH",
        "delete": "DELETE",
        "head": "HEAD",
        "options": "OPTIONS",
    }

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(
        self,
        methods: List[DexMethod],
        *args,
        **kwargs,
    ):
        super().__init__(
            methods,
            *args,
            **kwargs,
        )

        self._url_locations: Dict[
            str,
            List[Tuple[str, str, str]],
        ] = {}

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(
        url: str,
    ) -> str:
        """Normalize a discovered URL without changing its meaning."""

        if not url:
            return ""

        value = url.strip()

        # Remove common punctuation that can be adjacent to a URL in a
        # string literal.
        value = value.rstrip(
            ".,;:)]}>\"'"
        )

        return value

    @staticmethod
    def _normalize_text(
        value: str,
    ) -> str:
        """Normalize text for case-insensitive keyword matching."""

        if not value:
            return ""

        return re.sub(
            r"[^a-z0-9]+",
            " ",
            value.lower(),
        ).strip()

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------

    def _extract_urls(
        self,
        value: str,
    ) -> List[str]:
        """Extract unique HTTP(S) URLs from a string."""

        if not value:
            return []

        found: List[str] = []
        seen: Set[str] = set()

        try:
            matches = self.URL_REGEX.findall(
                value
            )
        except Exception:
            return []

        for match in matches:
            url = self._normalize_url(
                match
            )

            if not url:
                continue

            # Ignore obviously malformed schemes/hosts.
            try:
                parsed = urlparse(
                    url
                )

                if parsed.scheme.lower() not in (
                    "http",
                    "https",
                ):
                    continue

                if not parsed.netloc:
                    continue

            except Exception:
                continue

            if url not in seen:
                seen.add(url)
                found.append(url)

        return found

    # ------------------------------------------------------------------
    # Networking library detection
    # ------------------------------------------------------------------

    def _detect_client_library(
        self,
        method: DexMethod,
    ) -> str:
        """
        Detect the most likely networking library used by a method.

        Evidence is gathered from:
            - callees
            - referenced fields
            - referenced types
            - class name
            - method name
        """

        evidence: List[str] = []

        evidence.append(
            method.class_name or ""
        )

        evidence.append(
            method.method_name or ""
        )

        evidence.extend(
            method.callees or []
        )

        evidence.extend(
            method.fields_referenced or []
        )

        evidence.extend(
            method.types_referenced or []
        )

        text = " ".join(
            evidence
        ).lower()

        for marker, library_name in (
            self.NETWORK_LIBRARY_NAMES
        ):
            if marker in text:
                return library_name

        # If the method directly references a URL but no library can be
        # identified, avoid falsely claiming HttpURLConnection.
        return "Unknown"

    # ------------------------------------------------------------------
    # Purchase relevance
    # ------------------------------------------------------------------

    def _keyword_hits(
        self,
        text: str,
        keywords,
    ) -> List[str]:
        """Return matching keywords from a normalized text."""

        normalized = self._normalize_text(
            text
        )

        if not normalized:
            return []

        hits: List[str] = []

        for keyword in keywords:
            normalized_keyword = (
                self._normalize_text(
                    keyword
                )
            )

            if not normalized_keyword:
                continue

            if normalized_keyword in normalized:
                hits.append(
                    keyword
                )

        return hits

    def _calculate_relevance(
        self,
        method: DexMethod,
        url: str,
        domain: str,
    ) -> Tuple[
        bool,
        str,
        str,
        List[str],
    ]:
        """
        Calculate endpoint relevance.

        Returns:
            is_purchase_related
            relevance_level
            reason
            evidence
        """

        url_hits = self._keyword_hits(
            url,
            self.PURCHASE_ENDPOINT_KEYWORDS,
        )

        class_hits = self._keyword_hits(
            method.class_name,
            self.PURCHASE_CLASS_KEYWORDS,
        )

        method_hits = self._keyword_hits(
            method.method_name,
            self.PURCHASE_METHOD_KEYWORDS,
        )

        callee_text = " ".join(
            method.callees or []
        )

        callee_hits = self._keyword_hits(
            callee_text,
            self.PURCHASE_METHOD_KEYWORDS,
        )

        evidence: List[str] = []

        for hit in url_hits:
            evidence.append(
                f"url:{hit}"
            )

        for hit in class_hits:
            evidence.append(
                f"class:{hit}"
            )

        for hit in method_hits:
            evidence.append(
                f"method:{hit}"
            )

        for hit in callee_hits:
            evidence.append(
                f"callee:{hit}"
            )

        # Strongest evidence: endpoint itself has purchase semantics.
        if url_hits:
            return (
                True,
                "HIGH",
                (
                    "Endpoint path/query contains "
                    "purchase, billing, receipt, "
                    "subscription, entitlement, "
                    "license, payment, or "
                    "verification-related terminology."
                ),
                evidence,
            )

        # Strong class + method relationship.
        if class_hits and method_hits:
            return (
                True,
                "HIGH",
                (
                    "Endpoint is referenced by a method "
                    "whose class and method names both "
                    "indicate purchase/billing logic."
                ),
                evidence,
            )

        # Purchase-related method.
        if method_hits:
            return (
                True,
                "MEDIUM",
                (
                    "Endpoint is referenced directly from "
                    "a purchase/billing-related method."
                ),
                evidence,
            )

        # Purchase-related class.
        if class_hits:
            return (
                True,
                "MEDIUM",
                (
                    "Endpoint is referenced from a class "
                    "whose name indicates billing, purchase, "
                    "payment, entitlement, or subscription logic."
                ),
                evidence,
            )

        # A purchase-related callee can provide useful indirect evidence.
        if callee_hits:
            return (
                True,
                "MEDIUM",
                (
                    "The endpoint's method calls another "
                    "method whose name suggests purchase/"
                    "billing/verification logic."
                ),
                evidence,
            )

        # Google infrastructure is not automatically purchase-related.
        if (
            "google.com" in domain.lower()
            or "googleapis.com" in domain.lower()
        ):
            return (
                False,
                "LOW",
                (
                    "Google service/API infrastructure "
                    "endpoint without direct purchase evidence."
                ),
                [],
            )

        return (
            False,
            "NONE",
            "General application network endpoint.",
            [],
        )

    # ------------------------------------------------------------------
    # HTTP method inference
    # ------------------------------------------------------------------

    def _infer_http_method(
        self,
        method: DexMethod,
        url: str,
        client_library: str,
    ) -> Optional[str]:
        """
        Infer HTTP method when static evidence is strong enough.

        This intentionally returns None when evidence is insufficient rather
        than guessing.
        """

        normalized_url = (
            url.lower()
        )

        # Strong URL/path hints.
        if any(
            token in normalized_url
            for token in (
                "/verify",
                "/validate",
                "/validation",
                "/purchase",
                "/checkout",
                "/billing",
                "/payment",
                "/receipt",
                "/entitlement",
                "/subscription",
            )
        ):
            return "POST"

        # Method names are useful but not definitive.
        method_lower = (
            method.method_name
            or ""
        ).lower()

        for name, http_method in (
            self.HTTP_METHOD_HINTS.items()
        ):
            if (
                method_lower == name
                or method_lower.startswith(
                    name + "_"
                )
                or method_lower.startswith(
                    name
                )
            ):
                return http_method

        # Search callees for explicit HTTP verbs.
        callee_text = " ".join(
            method.callees or []
        ).lower()

        explicit_patterns = (
            (r"\bget\b", "GET"),
            (r"\bpost\b", "POST"),
            (r"\bput\b", "PUT"),
            (r"\bpatch\b", "PATCH"),
            (r"\bdelete\b", "DELETE"),
        )

        for pattern, http_method in explicit_patterns:
            if re.search(
                pattern,
                callee_text,
            ):
                return http_method

        return None

    # ------------------------------------------------------------------
    # Endpoint creation
    # ------------------------------------------------------------------

    def _create_endpoint(
        self,
        method: DexMethod,
        url: str,
        client_library: str,
    ) -> NetworkEndpoint:
        """Create one NetworkEndpoint model."""

        parsed = urlparse(
            url
        )

        domain = (
            parsed.hostname
            or ""
        )

        is_purchase, relevance_level, reason, evidence = (
            self._calculate_relevance(
                method,
                url,
                domain,
            )
        )

        http_method = (
            self._infer_http_method(
                method,
                url,
                client_library,
            )
        )

        endpoint = NetworkEndpoint(
            url=url,
            domain=domain,
            http_method=http_method,
            client_library=client_library,
            referenced_from_class=method.class_name,
            referenced_from_method=method.method_name,
            dex_file=method.dex_file,
            source_apk=method.source_apk,
            is_purchase_related=is_purchase,
            relevance_level=relevance_level,
            relevance_reason=reason,
        )

        # Some versions of models.NetworkEndpoint may expose additional
        # fields. Populate them only when present to remain backward
        # compatible with the current model.
        if hasattr(
            endpoint,
            "evidence",
        ):
            try:
                endpoint.evidence = evidence
            except Exception:
                pass

        return endpoint

    # ------------------------------------------------------------------
    # Main detector
    # ------------------------------------------------------------------

    def detect(
        self,
    ) -> List[NetworkEndpoint]:
        """
        Analyze all methods and return discovered network endpoints.

        Important behavior:
            The same URL may legitimately occur in multiple methods.
            Therefore deduplication is performed on:

                URL + class + method + DEX + source APK

            rather than URL alone.

        This preserves cross-reference information needed by the purchase
        analysis stage.
        """

        endpoints: List[
            NetworkEndpoint
        ] = []

        seen: Set[
            Tuple[str, str, str, str, str]
        ] = set()

        self._url_locations = {}

        for method in self.methods:
            client_library = (
                self._detect_client_library(
                    method
                )
            )

            # strings_referenced is the main source of URL literals.
            strings = (
                method.strings_referenced
                or []
            )

            for string_value in strings:
                if not string_value:
                    continue

                urls = self._extract_urls(
                    string_value
                )

                for url in urls:
                    key = (
                        url,
                        method.dex_file or "",
                        method.source_apk or "",
                        method.class_name or "",
                        method.method_name or "",
                    )

                    if key in seen:
                        continue

                    seen.add(
                        key
                    )

                    self._url_locations.setdefault(
                        url,
                        [],
                    ).append(
                        (
                            method.dex_file or "",
                            method.class_name or "",
                            method.method_name or "",
                        )
                    )

                    endpoint = (
                        self._create_endpoint(
                            method,
                            url,
                            client_library,
                        )
                    )

                    endpoints.append(
                        endpoint
                    )

        # ------------------------------------------------------------------
        # Stable sorting
        # ------------------------------------------------------------------

        rank = {
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 2,
            "NONE": 3,
        }

        endpoints.sort(
            key=lambda endpoint: (
                rank.get(
                    endpoint.relevance_level,
                    4,
                ),
                (
                    endpoint.domain
                    or ""
                ).lower(),
                (
                    endpoint.url
                    or ""
                ).lower(),
                (
                    endpoint.source_apk
                    or ""
                ).lower(),
                (
                    endpoint.dex_file
                    or ""
                ).lower(),
                (
                    endpoint.referenced_from_class
                    or ""
                ).lower(),
                (
                    endpoint.referenced_from_method
                    or ""
                ).lower(),
            )
        )

        return endpoints

    # ------------------------------------------------------------------
    # Cross-reference helpers
    # ------------------------------------------------------------------

    def get_url_locations(
        self,
        url: str,
    ) -> List[Dict[str, str]]:
        """
        Return all known methods referencing a URL.

        Useful for the higher-level analysis engine when it wants to trace
        endpoint -> method -> caller relationships.
        """

        locations = (
            self._url_locations.get(
                url,
                [],
            )
        )

        return [
            {
                "dex_file": dex_file,
                "class_name": class_name,
                "method_name": method_name,
            }
            for dex_file, class_name, method_name
            in locations
        ]

    def get_purchase_endpoints(
        self,
        endpoints: Optional[
            List[NetworkEndpoint]
        ] = None,
    ) -> List[NetworkEndpoint]:
        """Return only endpoints marked as purchase-related."""

        if endpoints is None:
            endpoints = self.detect()

        return [
            endpoint
            for endpoint in endpoints
            if endpoint.is_purchase_related
        ]
