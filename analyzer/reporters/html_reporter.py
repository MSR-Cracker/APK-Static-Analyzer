"""HTML Reporter: Generates a comprehensive, interactive, standalone static analysis dashboard report."""
import os
import html
from typing import List, Dict, Any, Optional
from analyzer.models import AnalysisReport, ClassificationType, Confidence, ObfuscationStatus


class HtmlReporter:
    """Renders the AnalysisReport into a modern, responsive HTML report in output/report.html."""

    def __init__(self, report: AnalysisReport, output_path: str = "output/report.html"):
        self.report = report
        self.output_path = output_path

    def _badge(self, text: str, color_type: str = "neutral") -> str:
        colors = {
            "green": "background-color: #def7ec; color: #03543f; border: 1px solid #84e1bc;",
            "red": "background-color: #fde8e8; color: #9b1c1c; border: 1px solid #f8b4b4;",
            "yellow": "background-color: #fef08a; color: #713f12; border: 1px solid #fde047;",
            "blue": "background-color: #e1effe; color: #1e429f; border: 1px solid #a4cafe;",
            "purple": "background-color: #edebfe; color: #5521b5; border: 1px solid #cabffd;",
            "neutral": "background-color: #f3f4f6; color: #374151; border: 1px solid #e5e7eb;",
        }
        style = colors.get(color_type, colors["neutral"])
        return f'<span style="display:inline-block; padding: 3px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; {style}">{html.escape(str(text))}</span>'

    def _confidence_badge(self, conf: Any) -> str:
        val = conf.value if hasattr(conf, "value") else str(conf)
        if val == "HIGH":
            return self._badge("HIGH CONFIDENCE", "green")
        if val == "MEDIUM":
            return self._badge("MEDIUM CONFIDENCE", "yellow")
        return self._badge("LOW CONFIDENCE", "neutral")

    def _arch_badge(self, arch: Any) -> str:
        val = arch.value if hasattr(arch, "value") else str(arch)
        if val == "SERVER_SIDE":
            return self._badge("SERVER_SIDE", "purple")
        if val == "CLIENT_SIDE":
            return self._badge("CLIENT_SIDE", "red")
        if val == "MIXED":
            return self._badge("MIXED", "blue")
        return self._badge("UNKNOWN", "neutral")

    def generate(self) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
        r = self.report
        apk = r.apk_info

        # 1. Contained APKs Table
        apks_rows = []
        if apk:
            for a in apk.contained_apks:
                apks_rows.append(f"""
                <tr>
                    <td style="font-weight: 600;">{html.escape(a.get('name', ''))}</td>
                    <td>{self._badge(a.get('split_type', 'split'), 'blue' if a.get('is_base') else 'neutral')}</td>
                    <td>{round(a.get('file_size_bytes', 0) / (1024 * 1024), 2)} MB</td>
                    <td>{a.get('dex_count', 0)}</td>
                    <td>{'<span style="color:#03543f; font-weight:bold;">YES (Base)</span>' if a.get('is_base') else 'Split Module'}</td>
                </tr>
                """)

        # 2. DEX Files Table
        dex_rows = []
        for d in r.dex_files:
            dex_rows.append(f"""
            <tr>
                <td style="font-family: monospace; font-weight:600;">{html.escape(d.name)}</td>
                <td>{html.escape(d.source_apk)}</td>
                <td>{round(d.size_bytes / 1024, 1)} KB</td>
                <td>{d.class_count}</td>
                <td>{d.method_count}</td>
                <td>{self._badge(d.analysis_quality, 'green' if d.analysis_quality == 'FULL' else 'yellow')}</td>
            </tr>
            """)

        # 3. Boolean Candidates Cards
        bool_cards = []
        for idx, b in enumerate(r.boolean_candidates[:15], 1):
            callers_list = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in b.callers[:4]) or "<i>No direct callers mapped</i>"
            evidence_list = "".join(f"<li>{html.escape(e)}</li>" for e in b.purchase_relevance_evidence)
            snippet_html = f"<pre style='background:#1e1e1e; color:#d4d4d4; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto;'>{html.escape(b.decompiled_snippet or 'No bytecode disassembled')}</pre>"
            eid_badge = f"<span style='background:#f3e8ff; color:#6b21a8; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; margin-right:6px;'>{b.evidence_id}</span>" if b.evidence_id else ""

            bool_cards.append(f"""
            <div style="background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 18px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid #f3f4f6; padding-bottom: 8px;">
                    <div>
                        {eid_badge}
                        <span style="font-size: 16px; font-weight: 700; color: #111827;">#{idx} {html.escape(b.method_name)}{html.escape(b.signature)}</span>
                        <span style="margin-left: 8px;">{self._confidence_badge(b.confidence)}</span>
                    </div>
                    <div>
                        <span style="font-size: 14px; font-weight: 600; color: #4b5563;">Score: <strong>{b.score}</strong></span>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; font-size: 13px; margin-bottom: 12px; color: #4b5563;">
                    <div><strong>Enclosing Class:</strong> <code style="color:#2563eb;">{html.escape(b.class_name)}</code></div>
                    <div><strong>DEX File:</strong> {html.escape(b.dex_file)} ({html.escape(b.source_apk)})</div>
                    <div><strong>Static / Native:</strong> {'Static' if b.is_static else 'Instance'} | {'Native' if b.is_native else 'Dalvik'}</div>
                    <div><strong>Return Type:</strong> <code>{html.escape(b.return_type)}</code></div>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong style="font-size: 13px; color: #1f2937;">Why Identified:</strong>
                    <p style="margin: 4px 0 8px 0; font-size: 13px; color: #374151; line-height: 1.5;">{html.escape(b.why_identified)}</p>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong style="font-size: 13px; color: #1f2937;">Evidence & Indicators:</strong>
                    <ul style="margin: 4px 0 8px 18px; font-size: 13px; color: #4b5563;">{evidence_list}</ul>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong style="font-size: 13px; color: #1f2937;">Callers ({len(b.callers)} mapped):</strong>
                    <ul style="margin: 4px 0 8px 18px; font-size: 12px; color: #4b5563;">{callers_list}</ul>
                </div>
                <div>
                    <strong style="font-size: 13px; color: #1f2937;">Disassembled Dalvik Bytecode:</strong>
                    {snippet_html}
                </div>
            </div>
            """)

        # 4. Call Sites & Verification Locations
        verif_cards = []
        for idx, v in enumerate(r.boolean_verification_locations, 1):
            ev_list = "".join(f"<li>{html.escape(e)}</li>" for e in v.evidence)
            eid_badge = f"<span style='background:#f3e8ff; color:#6b21a8; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; margin-right:6px;'>{v.evidence_id}</span>" if v.evidence_id else ""
            verif_cards.append(f"""
            <div style="background: #fdfefe; border: 1px solid #bfdbfe; border-left: 5px solid #3b82f6; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <h4 style="margin:0; font-size:15px; color:#1e40af;">{eid_badge}Verification Location #{idx}: {html.escape(v.class_name)}->{html.escape(v.method_name)}</h4>
                    {self._badge(v.branch_opcode, 'purple')}
                </div>
                <div style="font-size: 13px; color: #374151; margin-bottom: 10px;">
                    <p style="margin:2px 0;"><strong>Called Boolean:</strong> <code>{html.escape(v.called_boolean_class)}->{html.escape(v.called_boolean_method)}</code> (Captured in <code>{html.escape(v.result_register or 'reg')}</code>)</p>
                    <p style="margin:2px 0;"><strong>DEX Location:</strong> {html.escape(v.dex_file)} ({html.escape(v.source_apk)}) @ offset <code>0x{v.instruction_offset:04x}</code></p>
                    <p style="margin:2px 0;"><strong>Branch Behavior:</strong> True Target: <em>{html.escape(v.true_branch_target)}</em> | False Target: <em>{html.escape(v.false_branch_target)}</em></p>
                    <p style="margin:2px 0;"><strong>Observed Effect:</strong> <span style="font-weight:600; color:#047857;">{html.escape(v.effect)}</span></p>
                </div>
                <ul style="font-size: 12px; color: #4b5563; margin: 4px 0 8px 18px;">{ev_list}</ul>
                <pre style="background:#1e1e1e; color:#d4d4d4; padding:10px; border-radius:4px; font-size:12px; overflow-x:auto;">{html.escape(v.bytecode_snippet)}</pre>
            </div>
            """)

        # Call Sites Table
        call_site_rows = []
        for cs in r.call_sites:
            call_site_rows.append(f"""
            <tr>
                <td><code>{html.escape(cs.caller_class)}->{html.escape(cs.caller_method)}</code></td>
                <td><code>{html.escape(cs.called_class)}->{html.escape(cs.called_method)}</code></td>
                <td><code>0x{cs.instruction_offset:04x}</code></td>
                <td>{self._badge(cs.conditional_branch or 'direct', 'blue' if cs.conditional_branch else 'neutral')}</td>
                <td><span style="font-size:12px; color:#047857;">{html.escape(cs.true_branch_effect)}</span></td>
                <td><span style="font-size:12px; color:#b91c1c;">{html.escape(cs.false_branch_effect)}</span></td>
            </tr>
            """)

        # 5. Constructors Table
        ctor_rows = []
        for c in r.constructors:
            ev_list = "<br>".join(html.escape(e) for e in c.evidence)
            verif_badge = self._badge(c.verification, "green" if c.verification == "YES" else ("red" if c.verification == "NO" else "yellow"))
            net_badge = self._badge(c.network_interaction, "purple" if c.network_interaction == "YES" else "neutral")
            ctor_rows.append(f"""
            <tr>
                <td><code style="color:#2563eb;">{html.escape(c.class_name)}</code></td>
                <td>{verif_badge}</td>
                <td>{net_badge}</td>
                <td>{'<span style="color:#047857; font-weight:bold;">YES</span>' if c.initializes_billing_client else 'No'}</td>
                <td>{'<span style="color:#047857; font-weight:bold;">YES</span>' if c.sets_premium_flags else 'No'}</td>
                <td>{'<span style="color:#047857; font-weight:bold;">YES</span>' if c.reads_local_state else 'No'}</td>
                <td style="font-size:12px; color:#4b5563;">{ev_list}</td>
            </tr>
            """)

        # 6. Network Endpoints Table
        net_rows = []
        for ep in r.network_endpoints:
            rel_color = "red" if ep.relevance_level == "HIGH" else ("yellow" if ep.relevance_level == "MEDIUM" else "neutral")
            net_rows.append(f"""
            <tr>
                <td style="word-break: break-all;"><a href="{html.escape(ep.url)}" target="_blank" style="color:#2563eb; text-decoration:none;">{html.escape(ep.url)}</a></td>
                <td><strong>{html.escape(ep.domain)}</strong></td>
                <td>{self._badge(ep.relevance_level, rel_color)}</td>
                <td>{self._badge(ep.client_library, 'blue')}</td>
                <td><code>{html.escape(ep.referenced_from_class)}</code></td>
                <td style="font-size:12px; color:#4b5563;">{html.escape(ep.relevance_reason)}</td>
            </tr>
            """)

        # 7. Evidence Inventory Table
        evidence_rows = []
        for ev in r.evidence_inventory:
            evidence_rows.append(f"""
            <tr>
                <td><strong style="color:#6b21a8;">{html.escape(ev.id)}</strong></td>
                <td>{self._badge(ev.category, 'purple')}</td>
                <td><strong>{html.escape(ev.summary)}</strong></td>
                <td style="font-size:12px; color:#4b5563;">{html.escape(ev.description)}</td>
                <td>{self._confidence_badge(ev.confidence)}</td>
            </tr>
            """)

        # 8. CFG Diagrams
        cfg_cards = []
        for cfg in r.cfgs[:4]:
            blocks_html = []
            for b in cfg.blocks:
                insts_txt = "\n".join(b.instructions)
                succs_txt = ", ".join(b.successors) if b.successors else "None (Exit)"
                blocks_html.append(f"""
                <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:6px; padding:10px; margin-bottom:10px; font-family:monospace; font-size:12px;">
                    <div style="display:flex; justify-content:space-between; font-weight:700; color:#334155; border-bottom:1px solid #e2e8f0; padding-bottom:4px; margin-bottom:6px;">
                        <span>{html.escape(b.id)} ({'ENTRY' if b.is_entry else ('EXIT' if b.is_exit else 'BODY')})</span>
                        <span>Offset: 0x{b.start_offset:04x} - 0x{b.end_offset:04x}</span>
                    </div>
                    <pre style="margin:0; color:#0f172a; white-space:pre-wrap;">{html.escape(insts_txt)}</pre>
                    <div style="margin-top:6px; font-size:11px; color:#64748b;">
                        <span>Successors: <strong>{html.escape(succs_txt)}</strong></span>
                        {f" | True Edge: <span style='color:#059669;'>{b.true_edge}</span>" if b.true_edge else ""}
                        {f" | False Edge: <span style='color:#dc2626;'>{b.false_edge}</span>" if b.false_edge else ""}
                    </div>
                </div>
                """)
            cfg_cards.append(f"""
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin-bottom:16px;">
                <h4 style="margin:0 0 10px 0; color:#0f172a;">CFG: {html.escape(cfg.method_signature)} <span style="font-size:12px; color:#64748b;">({html.escape(cfg.dex_file)})</span></h4>
                {''.join(blocks_html)}
            </div>
            """)

        ai = r.ai_reasoning
        ai_chain_items = "".join(f"<li>{html.escape(c)}</li>" for c in ai.reasoning_chain) if ai else ""
        discrepancy_box = ""
        if ai and ai.has_discrepancy:
            discrepancy_box = f"""
            <div style="background:#fff1f2; border:1px solid #fecdd3; border-left:5px solid #e11d48; border-radius:6px; padding:14px; margin-bottom:16px;">
                <strong style="color:#9f1239; font-size:14px;">⚠️ AI / Static Analysis Discrepancy Detected</strong>
                <p style="margin:4px 0 0 0; font-size:13px; color:#881337;">{html.escape(ai.discrepancy_details)}</p>
            </div>
            """

        # Primary values for the executive box
        primary_class = (r.class_analysis.primary_purchase_class if r.class_analysis else "None detected")
        primary_method = (r.class_analysis.primary_boolean_method if r.class_analysis else "None detected")
        primary_dex = (r.class_analysis.primary_boolean_dex if r.class_analysis else "N/A")
        primary_sig = (r.class_analysis.primary_boolean_signature if r.class_analysis else "()Z")
        top_verif_text = (
            f"{r.boolean_verification_locations[0].class_name}->{r.boolean_verification_locations[0].method_name} ({r.boolean_verification_locations[0].branch_opcode})"
            if r.boolean_verification_locations else "None detected"
        )
        top_ctor_text = (
            f"{r.constructors[0].class_name} (Verification: {r.constructors[0].verification})"
            if r.constructors else "None detected"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Static Analysis: {html.escape(apk.package_name if apk else 'App')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #1e293b;
            margin: 0;
            padding: 24px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
        }}
        h1, h2, h3, h4 {{
            color: #0f172a;
            margin-top: 0;
        }}
        h2 {{
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 8px;
            margin-bottom: 16px;
            font-size: 18px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 13px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background-color: #f8fafc;
            font-weight: 600;
            color: #475569;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }}
        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
        }}
        .stat-box {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
        }}
        .stat-label {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #64748b;
            letter-spacing: 0.5px;
        }}
        .stat-value {{
            font-size: 20px;
            font-weight: 700;
            color: #0f172a;
            margin-top: 4px;
        }}
        .exec-summary-box {{
            background: #0f172a;
            color: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            font-family: monospace;
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        .exec-title {{
            font-size: 16px;
            font-weight: bold;
            color: #38bdf8;
            margin-bottom: 12px;
            border-bottom: 1px solid #334155;
            padding-bottom: 6px;
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- REQUIRED EXECUTIVE SUMMARY BLOCK -->
    <div class="exec-summary-box">
        <div class="exec-title">APK ANALYSIS SUMMARY</div>
        <div>Package: <strong>{html.escape(apk.package_name if apk else 'Unknown')}</strong></div>
        <div>Version: {html.escape(apk.version_name if apk else 'N/A')} ({html.escape(apk.version_code if apk else 'N/A')})</div>
        <div>DEX count: {len(r.dex_files)}</div>
        <div>Obfuscated: {html.escape(r.obfuscation.status.value if r.obfuscation else 'NO')}</div>
        <div>Billing detected: {', '.join(r.billing.providers_detected if r.billing else []) or 'None'}</div>
        <div>Payment architecture: {html.escape(r.classification.classification.value if r.classification else 'UNKNOWN')}</div>
        <br>
        <div>Primary purchase class: {html.escape(str(primary_class))}</div>
        <div>Primary purchase method: {html.escape(str(primary_method))}</div>
        <div>DEX: {html.escape(str(primary_dex))}</div>
        <div>Signature: {html.escape(str(primary_sig))}</div>
        <br>
        <div>Boolean verification: {html.escape(str(top_verif_text))}</div>
        <div>Constructor premium check: {html.escape(str(top_ctor_text))}</div>
        <br>
        <div>Confidence: {html.escape(r.classification.confidence.value if r.classification else 'LOW')}</div>
    </div>

    <!-- 1. APK INFORMATION -->
    <div class="card" id="section-1">
        <h2>1. APK Information</h2>
        <div class="grid-3" style="margin-bottom: 16px;">
            <div class="stat-box">
                <div class="stat-label">Application Label</div>
                <div class="stat-value">{html.escape(apk.app_label if apk else 'Android App')}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Container Format</div>
                <div class="stat-value">{html.escape(apk.input_type if apk else 'APK')} ({len(apk.contained_apks if apk else [])} APKs)</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Total Size</div>
                <div class="stat-value">{round((apk.file_size_bytes if apk else 0)/(1024*1024), 2)} MB</div>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Split / APK Name</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>DEX Count</th>
                    <th>Role</th>
                </tr>
            </thead>
            <tbody>{''.join(apks_rows)}</tbody>
        </table>
    </div>

    <!-- 2. DEX INFORMATION -->
    <div class="card" id="section-2">
        <h2>2. DEX Information</h2>
        <table>
            <thead>
                <tr>
                    <th>DEX File Name</th>
                    <th>Source APK</th>
                    <th>Size</th>
                    <th>Class Count</th>
                    <th>Method Count</th>
                    <th>Analysis Quality</th>
                </tr>
            </thead>
            <tbody>{''.join(dex_rows)}</tbody>
        </table>
    </div>

    <!-- 3. OBFUSCATION -->
    <div class="card" id="section-3">
        <h2>3. Obfuscation Analysis</h2>
        <p><strong>Status:</strong> {self._badge(r.obfuscation.status.value if r.obfuscation else 'NO', 'red' if r.obfuscation and r.obfuscation.status.value == 'YES' else 'neutral')} ({self._confidence_badge(r.obfuscation.confidence if r.obfuscation else 'LOW')})</p>
        <ul style="margin:8px 0 0 20px; font-size:13px; color:#475569;">
            {"".join(f"<li>{html.escape(e)}</li>" for e in (r.obfuscation.evidence if r.obfuscation else []))}
        </ul>
    </div>

    <!-- 4. BILLING DETECTION -->
    <div class="card" id="section-4">
        <h2>4. Billing Detection</h2>
        <div class="grid-2" style="margin-bottom: 16px;">
            <div class="stat-box">
                <div class="stat-label">Detected Providers</div>
                <div style="font-size:15px; font-weight:700; color:#0f172a; margin-top:4px;">{', '.join(r.billing.providers_detected if r.billing else []) or 'None'}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Google Play Billing Version</div>
                <div style="font-size:15px; font-weight:700; color:#2563eb; margin-top:4px;">{html.escape(r.billing.google_play_version if r.billing and r.billing.google_play_version else 'N/A')}</div>
            </div>
        </div>
        <strong>Billing Evidence & API Signatures:</strong>
        <ul style="margin:8px 0 0 20px; font-size:13px; color:#475569;">
            {"".join(f"<li>{html.escape(e)}</li>" for e in (r.billing.evidence if r.billing else []))}
        </ul>
    </div>

    <!-- 5. PURCHASE/PREMIUM CLASSES -->
    <div class="card" id="section-5">
        <h2>5. Purchase & Premium Classes</h2>
        <div class="grid-2" style="margin-bottom: 16px;">
            <div class="stat-box">
                <div class="stat-label">Primary Purchase Coordinator</div>
                <div style="font-family:monospace; font-size:14px; font-weight:700; color:#2563eb; margin-top:6px;">{html.escape(str(primary_class))}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Primary Premium Entitlement Model</div>
                <div style="font-family:monospace; font-size:14px; font-weight:700; color:#7c3aed; margin-top:6px;">{html.escape(str(r.class_analysis.primary_premium_class if r.class_analysis else 'None'))}</div>
            </div>
        </div>
        <strong>Class Selection Evidence:</strong>
        <ul style="margin:8px 0 0 20px; font-size:13px; color:#475569;">
            {"".join(f"<li>{html.escape(e)}</li>" for e in (r.class_analysis.evidence if r.class_analysis else []))}
        </ul>
    </div>

    <!-- 6. PURCHASE BOOLEAN CANDIDATES -->
    <div class="card" id="section-6">
        <h2>6. Purchase Boolean Candidates</h2>
        {''.join(bool_cards) if bool_cards else '<p>No boolean purchase candidates identified.</p>'}
    </div>

    <!-- 7. BOOLEAN CALL SITES & DATA-FLOW -->
    <div class="card" id="section-7">
        <h2>7. Boolean Call Sites & Data-Flow</h2>
        <div style="margin-bottom: 16px;">
            {''.join(verif_cards) if verif_cards else '<p>No verification branch locations mapped.</p>'}
        </div>
        <h4>All Cross-DEX Call Sites</h4>
        <table>
            <thead>
                <tr>
                    <th>Caller Method</th>
                    <th>Invoked Boolean</th>
                    <th>Offset</th>
                    <th>Branch</th>
                    <th>True Branch Effect</th>
                    <th>False Branch Effect</th>
                </tr>
            </thead>
            <tbody>{''.join(call_site_rows)}</tbody>
        </table>
    </div>

    <!-- 8. CONTROL FLOW (CFG) -->
    <div class="card" id="section-8">
        <h2>8. Control Flow (CFG)</h2>
        {''.join(cfg_cards) if cfg_cards else '<p>No CFG generated.</p>'}
    </div>

    <!-- 9. CONSTRUCTOR ANALYSIS -->
    <div class="card" id="section-9">
        <h2>9. Constructor Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Class</th>
                    <th>Verification</th>
                    <th>Network Interaction</th>
                    <th>Init Billing SDK</th>
                    <th>Set Premium Flags</th>
                    <th>Read Local State</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>{''.join(ctor_rows)}</tbody>
        </table>
    </div>

    <!-- 10. NETWORK ANALYSIS -->
    <div class="card" id="section-10">
        <h2>10. Network Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Endpoint URL</th>
                    <th>Domain</th>
                    <th>Relevance</th>
                    <th>Client Library</th>
                    <th>Referenced From</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>{''.join(net_rows)}</tbody>
        </table>
    </div>

    <!-- 11. SERVER/CLIENT CLASSIFICATION -->
    <div class="card" id="section-11">
        <h2>11. Server / Client Classification</h2>
        <div style="margin-bottom: 16px;">
            <p><strong>Architecture Decision:</strong> {self._arch_badge(r.classification.classification if r.classification else 'UNKNOWN')} ({self._confidence_badge(r.classification.confidence if r.classification else 'LOW')})</p>
        </div>
        <div class="grid-2">
            <div>
                <h4 style="color:#047857;">Client-Side Grounded Indicators</h4>
                <ul style="font-size:13px; color:#334155;">
                    {"".join(f"<li>{html.escape(e)}</li>" for e in (r.classification.client_side_evidence if r.classification else [])) or '<li>None</li>'}
                </ul>
            </div>
            <div>
                <h4 style="color:#6b21a8;">Server-Side Grounded Indicators</h4>
                <ul style="font-size:13px; color:#334155;">
                    {"".join(f"<li>{html.escape(e)}</li>" for e in (r.classification.server_side_evidence if r.classification else [])) or '<li>None</li>'}
                </ul>
            </div>
        </div>
    </div>

    <!-- 12. EVIDENCE INVENTORY -->
    <div class="card" id="section-12">
        <h2>12. Evidence Inventory</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Category</th>
                    <th>Summary</th>
                    <th>Description</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>{''.join(evidence_rows)}</tbody>
        </table>
    </div>

    <!-- 13. AI REASONING -->
    <div class="card" id="section-13" style="background:#fcfdff; border:1px solid #bfdbfe;">
        <h2 style="color:#1e40af; border-bottom:2px solid #dbeafe;">13. AI Reasoning & Discrepancy Analysis</h2>
        {discrepancy_box}
        <div style="margin-bottom:16px;">
            <h4 style="margin:0 0 6px 0; color:#1e3a8a;">Architecture Summary</h4>
            <p style="margin:0; font-size:14px; color:#1e293b;">{html.escape(ai.architecture_summary if ai else '')}</p>
        </div>
        <div style="margin-bottom:16px;">
            <h4 style="margin:0 0 6px 0; color:#1e3a8a;">Purchase & Entitlement Flow</h4>
            <p style="margin:0; font-size:14px; color:#1e293b;">{html.escape(ai.purchase_flow_explanation if ai else '')}</p>
        </div>
        <div style="margin-bottom:16px;">
            <h4 style="margin:0 0 6px 0; color:#1e3a8a;">Boolean Gate & Verification Behavior</h4>
            <p style="margin:0; font-size:14px; color:#1e293b;">{html.escape(ai.boolean_gate_explanation if ai else '')}</p>
        </div>
        <div style="margin-bottom:16px;">
            <h4 style="margin:0 0 6px 0; color:#991b1b;">Security & Tamper Assessment</h4>
            <p style="margin:0; font-size:14px; color:#991b1b; font-weight:600;">{html.escape(ai.security_assessment if ai else '')}</p>
        </div>
        <div>
            <h4 style="margin:0 0 6px 0; color:#1e3a8a;">Cited Evidence IDs</h4>
            <p style="margin:0 0 10px 0; font-size:13px; color:#6b21a8; font-weight:bold;">{', '.join(ai.cited_evidence_ids if ai else []) or 'None'}</p>
            <h4 style="margin:0 0 6px 0; color:#1e3a8a;">Reasoning Chain</h4>
            <ol style="margin:0; padding-left:20px; font-size:13px; color:#334155;">{ai_chain_items}</ol>
        </div>
    </div>

    <!-- 14. LIMITATIONS & QUALITY -->
    <div class="card" id="section-14">
        <h2>14. Limitations & Analysis Quality</h2>
        <p><strong>Overall Analysis Quality:</strong> {self._badge(r.analysis_quality, 'green' if r.analysis_quality == 'FULL' else 'yellow')}</p>
        <div>
            <strong>Warnings / Limitations:</strong>
            <ul style="margin:8px 0 0 20px; font-size:13px; color:#475569;">
                {"".join(f"<li>{html.escape(w)}</li>" for w in r.warnings_or_errors) if r.warnings_or_errors else '<li>No analysis limitations or unsupported instructions detected.</li>'}
            </ul>
        </div>
    </div>

</div>
</body>
</html>
"""
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return self.output_path
