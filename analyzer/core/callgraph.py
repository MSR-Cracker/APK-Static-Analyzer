"""Targeted Call Graph builder focusing on payment, verification, boolean check, and network paths."""
from typing import List, Dict, Set, Any
from analyzer.models import DexMethod, CallGraphData, CallGraphNode, CallGraphEdge, BooleanMethodCandidate, NetworkEndpoint


class PaymentCallGraphBuilder:
    """Builds a concise, payment-focused call graph connecting Activities -> Boolean checks -> Verification -> Network."""

    def __init__(self, methods: List[DexMethod], boolean_candidates: List[BooleanMethodCandidate], network_endpoints: List[NetworkEndpoint]):
        self.methods = methods
        self.boolean_candidates = boolean_candidates
        self.network_endpoints = network_endpoints
        self.nodes: Dict[str, CallGraphNode] = {}
        self.edges: Set[Tuple[str, str, str]] = set()

    def build(self) -> CallGraphData:
        # Build method lookup
        method_map: Dict[str, DexMethod] = {
            f"{m.class_name}->{m.method_name}": m for m in self.methods
        }

        # 1. Add boolean candidate nodes
        top_candidates = sorted(self.boolean_candidates, key=lambda c: c.score, reverse=True)[:5]
        for cand in top_candidates:
            cand_id = f"{cand.class_name}->{cand.method_name}"
            self.nodes[cand_id] = CallGraphNode(
                id=cand_id,
                label=f"{cand.class_name.split('.')[-1]}.{cand.method_name}()",
                type="boolean_check",
                dex_file=cand.dex_file,
                details={
                    "class": cand.class_name,
                    "method": cand.method_name,
                    "signature": cand.signature,
                    "confidence": cand.confidence.value,
                    "dex": cand.dex_file,
                }
            )

            # Trace callers (e.g. Activities/UI components)
            for caller in cand.callers[:4]:
                caller_clean = caller.replace("()", "")
                caller_class = caller_clean.split("->")[0] if "->" in caller_clean else caller_clean
                caller_type = "activity" if "Activity" in caller_class or "Fragment" in caller_class else "entrypoint"
                
                if caller_clean not in self.nodes:
                    self.nodes[caller_clean] = CallGraphNode(
                        id=caller_clean,
                        label=f"{caller_class.split('.')[-1]}",
                        type=caller_type,
                        details={"class": caller_class}
                    )
                self.edges.add((caller_clean, cand_id, "checks entitlement"))

            # Trace callees (e.g. verification methods, billing client, preferences)
            for callee in cand.callees[:5]:
                callee_clean = callee.split("(")[0]
                callee_class = callee_clean.split("->")[0] if "->" in callee_clean else callee_clean
                callee_name = callee_clean.split("->")[1] if "->" in callee_clean else ""
                
                c_type = "billing" if any(k in callee_class.lower() or k in callee_name.lower() for k in ("billing", "purchase", "pay", "revenue", "sku")) else "verification"
                
                if callee_clean not in self.nodes:
                    self.nodes[callee_clean] = CallGraphNode(
                        id=callee_clean,
                        label=f"{callee_class.split('.')[-1]}.{callee_name}()",
                        type=c_type,
                        details={"class": callee_class, "method": callee_name}
                    )
                self.edges.add((cand_id, callee_clean, "calls"))

        # 2. Connect network endpoints if referenced in callees or callers
        for ep in self.network_endpoints:
            if ep.is_purchase_related:
                ep_id = f"url:{ep.url}"
                if ep_id not in self.nodes:
                    self.nodes[ep_id] = CallGraphNode(
                        id=ep_id,
                        label=ep.url[:35] + ("..." if len(ep.url) > 35 else ""),
                        type="network",
                        dex_file=ep.dex_file,
                        details={"url": ep.url, "domain": ep.domain, "http_method": ep.http_method or "POST"}
                    )
                # Link from referenced method
                ref_id = f"{ep.referenced_from_class}->{ep.referenced_from_method}"
                if ref_id in self.nodes:
                    self.edges.add((ref_id, ep_id, "HTTP verify"))
                elif top_candidates:
                    # Link to strongest candidate's verification callee or candidate itself
                    self.edges.add((top_candidates[0].class_name + "->" + top_candidates[0].method_name, ep_id, "Remote verify"))

        # Build sample flow path
        sample_path = []
        if top_candidates:
            strongest = top_candidates[0]
            if strongest.callers:
                sample_path.append(strongest.callers[0].replace("()", ""))
            sample_path.append(f"{strongest.class_name}->{strongest.method_name}()")
            if strongest.callees:
                sample_path.append(strongest.callees[0])
            for ep in self.network_endpoints:
                if ep.is_purchase_related:
                    sample_path.append(ep.url)
                    break

        graph_edges = [
            CallGraphEdge(source=s, target=t, label=lbl) for (s, t, lbl) in self.edges
        ]

        return CallGraphData(
            nodes=list(self.nodes.values()),
            edges=graph_edges,
            sample_flow_path=sample_path
        )
