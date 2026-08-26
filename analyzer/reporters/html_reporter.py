"""HTML Reporter: Generates a self-contained, interactive, responsive HTML report."""
import json
import html
from typing import Dict, Any
from analyzer.models import AnalysisReport


class HtmlReporter:
    """Generates modern, standalone HTML analysis report with tables, call graphs, and evidence."""

    @staticmethod
    def generate(report: AnalysisReport, output_path: str):
        data = report.to_dict()
        apk = data.get("apk", {})
        billing = data.get("billing", {})
        classification = data.get("classification", {})
        boolean_methods = data.get("purchase_boolean_methods", [])
        constructors = data.get("constructors", [])
        network = data.get("network", {})
        call_graph = data.get("call_graph", {})
        evidence_list = data.get("evidence", [])
        gemini = data.get("gemini_interpretation")

        class_type = classification.get("classification", "UNKNOWN")
        class_conf = classification.get("confidence", "Low")

        # Color badges for classification
        badge_colors = {
            "SERVER_SIDE": "bg-emerald-100 text-emerald-800 border-emerald-300",
            "CLIENT_SIDE": "bg-amber-100 text-amber-800 border-amber-300",
            "MIXED": "bg-blue-100 text-blue-800 border-blue-300",
            "UNKNOWN": "bg-slate-100 text-slate-800 border-slate-300",
        }
        badge_class = badge_colors.get(class_type, "bg-slate-100 text-slate-800")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APK Static Analysis Report - {html.escape(str(apk.get("package_name", "APK")))}</title>
  <style>
    :root {{
      --primary: #1e293b;
      --accent: #2563eb;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      background: var(--card-bg);
      padding: 24px;
      border-radius: 12px;
      border: 1px solid var(--border);
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .title h1 {{ font-size: 24px; color: var(--primary); margin-bottom: 4px; }}
    .title p {{ color: var(--text-muted); font-size: 14px; }}
    .badge {{
      display: inline-block;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 14px;
      font-weight: 600;
      border: 1px solid;
    }}
    .badge-server {{ background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }}
    .badge-client {{ background: #fffbeb; color: #92400e; border-color: #fde68a; }}
    .badge-mixed {{ background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }}
    .badge-unknown {{ background: #f1f5f9; color: #475569; border-color: #cbd5e1; }}
    .badge-high {{ background: #dcfce7; color: #166534; }}
    .badge-med {{ background: #fef9c3; color: #854d0e; }}
    .badge-low {{ background: #fee2e2; color: #991b1b; }}
    
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 24px; }}
    .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.02);
      margin-bottom: 24px;
    }}
    .card-title {{
      font-size: 16px;
      font-weight: 700;
      color: var(--primary);
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 2px solid #f1f5f9;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .stat-box {{
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
    }}
    .stat-label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
    .stat-val {{ font-size: 16px; font-weight: 600; color: var(--primary); margin-top: 4px; word-break: break-all; }}
    
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ background: #f8fafc; color: var(--text-muted); font-weight: 600; }}
    tr:hover td {{ background: #fcfcfd; }}
    
    .code-tag {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }}
    .flow-chain {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      padding: 16px;
      background: #f8fafc;
      border-radius: 8px;
      border: 1px solid var(--border);
    }}
    .flow-step {{
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      font-weight: 500;
      font-size: 13px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    }}
    .flow-arrow {{ color: var(--text-muted); font-weight: bold; }}
    
    .evidence-list {{ list-style-type: none; }}
    .evidence-item {{
      padding: 8px 12px;
      background: #f8fafc;
      border-left: 3px solid var(--accent);
      margin-bottom: 8px;
      border-radius: 0 6px 6px 0;
      font-size: 13px;
    }}
    .spotlight {{
      border: 2px solid #3b82f6;
      background: #f0f7ff;
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 16px;
    }}
  </style>
</head>
<body>
  <div class="container">
    
    <!-- Top Header -->
    <div class="header">
      <div class="title">
        <h1>APK Static Analysis & In-App Purchase Report</h1>
        <p>Target: <strong>{html.escape(str(apk.get("file_name", "N/A")))}</strong> &bull; Generated by APK-Static-Analyzer</p>
      </div>
      <div>
        <span class="badge { 'badge-server' if class_type == 'SERVER_SIDE' else ('badge-client' if class_type == 'CLIENT_SIDE' else ('badge-mixed' if class_type == 'MIXED' else 'badge-unknown')) }">
          {class_type} &bull; {class_conf} Confidence
        </span>
      </div>
    </div>

    <!-- 1. APK Overview -->
    <div class="card">
      <div class="card-title">1. APK Overview / نظرة عامة على التطبيق</div>
      <div class="grid-4">
        <div class="stat-box">
          <div class="stat-label">Package Name</div>
          <div class="stat-val">{html.escape(str(apk.get("package_name", "N/A")))}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Version</div>
          <div class="stat-val">{html.escape(str(apk.get("version_name", "1.0")))} ({html.escape(str(apk.get("version_code", "1")))})</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">SDK Levels</div>
          <div class="stat-val">Min: {html.escape(str(apk.get("min_sdk", "N/A")))} | Target: {html.escape(str(apk.get("target_sdk", "N/A")))}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Multi-DEX Count</div>
          <div class="stat-val">{html.escape(str(apk.get("total_dex_count", 0)))} DEX Files</div>
        </div>
      </div>
      
      <div style="font-size: 13px; color: var(--text-muted); margin-top: 8px;">
        <strong>DEX Breakdown:</strong> {", ".join([f"{d.get('name')} ({round(d.get('size_bytes', 0)/1024/1024, 2)} MB)" for d in apk.get("dex_files_info", [])])}
      </div>
    </div>

    <!-- 2. Payment & Billing Detection -->
    <div class="card">
      <div class="card-title">2. Payment Detection / اكتشاف منظومة الدفع</div>
      <div class="grid-2">
        <div class="stat-box">
          <div class="stat-label">Detected Providers</div>
          <div class="stat-val" style="color: #2563eb;">{", ".join(billing.get("providers_detected", [])) or "None detected"}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Architecture Model</div>
          <div class="stat-val">{class_type} ({class_conf} Confidence)</div>
        </div>
      </div>
      <p style="font-size: 14px; margin-top: 8px; color: #334155;">
        <strong>Classification Reasons:</strong> {"; ".join(classification.get("reasons", []))}
      </p>
    </div>

    <!-- 3. Purchase Boolean Detector -->
    <div class="card">
      <div class="card-title">
        <span>3. Purchase Boolean Methods (PurchaseBooleanDetector) / دوال التحقق المنطقية</span>
        <span style="font-size: 12px; color: var(--text-muted);">{len(boolean_methods)} Candidate(s) Found</span>
      </div>

      {f'''
      <div class="spotlight">
        <div style="font-weight: 700; font-size: 14px; color: #1e40af; margin-bottom: 4px;">
          🎯 Primary Candidate Location / الموقع الأبرز لدالة التحقق من الشراء:
        </div>
        <div style="font-size: 13px; font-family: monospace;">
          <strong>DEX:</strong> {html.escape(boolean_methods[0].get("dex_file", ""))}<br>
          <strong>Class:</strong> {html.escape(boolean_methods[0].get("class_name", ""))}<br>
          <strong>Method:</strong> {html.escape(boolean_methods[0].get("method_name", ""))}{html.escape(boolean_methods[0].get("signature", "()Z"))}<br>
          <strong>Source:</strong> {html.escape(boolean_methods[0].get("source_location", ""))}
        </div>
      </div>
      ''' if boolean_methods else '<p style="color: var(--text-muted);">No confident boolean purchase methods discovered.</p>'}

      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>DEX</th>
              <th>Class</th>
              <th>Method</th>
              <th>Signature</th>
              <th>Return</th>
              <th>Confidence</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {''.join([f'''
            <tr>
              <td><span class="code-tag">{html.escape(m.get("dex_file", ""))}</span></td>
              <td><strong class="code-tag">{html.escape(m.get("class_name", ""))}</strong></td>
              <td><span class="code-tag" style="color:#2563eb;">{html.escape(m.get("method_name", ""))}</span></td>
              <td><span class="code-tag">{html.escape(m.get("signature", ""))}</span></td>
              <td><span class="code-tag">boolean / Z</span></td>
              <td><span class="badge {'badge-high' if m.get('confidence')=='High' else ('badge-med' if m.get('confidence')=='Medium' else 'badge-low')}">{m.get('confidence')}</span></td>
              <td style="font-size: 12px; max-width: 300px;">{html.escape("; ".join(m.get("purchase_relevance_evidence", [])[:2]))}</td>
            </tr>
            ''' for m in boolean_methods[:15]])}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 4. Constructor Analysis -->
    <div class="card">
      <div class="card-title">4. Constructor Analysis (&lt;init&gt;) / تحليل دوال البناء</div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>DEX</th>
              <th>Class</th>
              <th>Constructor</th>
              <th>Verification</th>
              <th>Network Interaction</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {''.join([f'''
            <tr>
              <td><span class="code-tag">{html.escape(c.get("dex_file", ""))}</span></td>
              <td><strong class="code-tag">{html.escape(c.get("class_name", ""))}</strong></td>
              <td><span class="code-tag">{html.escape(c.get("constructor_signature", "&lt;init&gt;()V"))}</span></td>
              <td><span class="badge {'badge-high' if c.get('verification')=='YES' else 'badge-unknown'}">{c.get('verification')}</span></td>
              <td><span class="badge {'badge-server' if c.get('network_interaction')=='YES' else 'badge-unknown'}">{c.get('network_interaction')}</span></td>
              <td style="font-size: 12px;">{html.escape("; ".join(c.get("evidence", [])))}</td>
            </tr>
            ''' for c in constructors[:10]])}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 5. Network Analysis -->
    <div class="card">
      <div class="card-title">5. Network Analysis & Payment Endpoints / تحليل الشبكة ونقاط النهاية</div>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Endpoint URL</th>
              <th>Domain</th>
              <th>Method</th>
              <th>Referenced From</th>
              <th>DEX</th>
            </tr>
          </thead>
          <tbody>
            {''.join([f'''
            <tr style="{'background:#fef2f2;' if ep.get('is_purchase_related') else ''}">
              <td>{'<span class="badge badge-server">Purchase API</span>' if ep.get('is_purchase_related') else '<span class="badge badge-unknown">Generic</span>'}</td>
              <td><span class="code-tag" style="word-break:break-all;">{html.escape(ep.get("url", ""))}</span></td>
              <td>{html.escape(ep.get("domain", ""))}</td>
              <td><span class="code-tag">{html.escape(str(ep.get("http_method") or "GET/POST"))}</span></td>
              <td><span class="code-tag">{html.escape(ep.get("referenced_from_class", ""))}->{html.escape(ep.get("referenced_from_method", ""))}</span></td>
              <td><span class="code-tag">{html.escape(ep.get("dex_file", ""))}</span></td>
            </tr>
            ''' for ep in network.get("endpoints", [])[:15]])}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 6. Call Graph -->
    <div class="card">
      <div class="card-title">6. Payment Call Graph / مسار تدفق استدعاء الدفع</div>
      <div class="flow-chain">
        {''.join([f'''
        <div class="flow-step">{html.escape(step)}</div>
        {('<span class="flow-arrow">&rarr;</span>' if i < len(call_graph.get("sample_flow_path", [])) - 1 else '')}
        ''' for i, step in enumerate(call_graph.get("sample_flow_path", []))]) or '<p style="color:var(--text-muted);">No payment flow chain traced.</p>'}
      </div>
    </div>

    <!-- 7. Static Evidence Summary -->
    <div class="card">
      <div class="card-title">7. Summary Evidence / قائمة الأدلة المستخرجة</div>
      <ul class="evidence-list">
        {''.join([f'<li class="evidence-item">{html.escape(str(ev))}</li>' for ev in evidence_list[:20]]) or '<li>No specific evidence recorded.</li>'}
      </ul>
    </div>

    {f'''
    <!-- 8. Gemini AI Interpretation -->
    <div class="card" style="border-left: 4px solid #8b5cf6;">
      <div class="card-title" style="color: #6d28d9;">8. Gemini AI Architectural Interpretation / تفسير الذكاء الاصطناعي</div>
      <div style="background: #f5f3ff; padding: 16px; border-radius: 8px; margin-bottom: 12px; font-size: 14px;">
        <p><strong>Executive Summary:</strong> {html.escape(str(gemini.get("summary", "")))}</p>
        <p style="margin-top: 8px;"><strong>Payment Architecture:</strong> {html.escape(str(gemini.get("payment_architecture", "")))}</p>
        <p style="margin-top: 8px;"><strong>Classification Explanation:</strong> {html.escape(str(gemini.get("classification_explanation", "")))}</p>
      </div>
    </div>
    ''' if gemini else ''}

    <div style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px;">
      APK-Static-Analyzer &bull; Automated Static Reverse Engineering & Entitlement Verification Analysis
    </div>

  </div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
