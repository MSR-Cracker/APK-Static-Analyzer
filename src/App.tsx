import React, { useState, useEffect } from "react";
import {
  Shield,
  FileCode,
  Play,
  Download,
  Terminal,
  Server,
  Smartphone,
  Cpu,
  Layers,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  Search,
  Sparkles,
  RefreshCw,
  ExternalLink,
  Code2,
  Network,
  Copy,
  Check
} from "lucide-react";

interface ApkAnalysisReport {
  apk: {
    package_name?: string;
    version_name?: string;
    version_code?: string;
    min_sdk?: string;
    target_sdk?: string;
    file_name?: string;
    file_size_bytes?: number;
    total_dex_count?: number;
    dex_files_info?: Array<{ name: string; size_bytes: number }>;
    permissions?: string[];
  };
  dex_files: Array<{ name: string }>;
  billing: {
    providers_detected?: string[];
    has_play_billing?: boolean;
    has_revenuecat?: boolean;
    has_stripe?: boolean;
    has_paypal?: boolean;
    has_webview_payment?: boolean;
    has_custom_billing?: boolean;
    billing_classes?: string[];
    evidence?: string[];
  };
  purchase_boolean_methods: Array<{
    dex_file: string;
    class_name: string;
    package: string;
    method_name: string;
    signature: string;
    return_type: string;
    parameters: string[];
    access_flags: string[];
    is_static: boolean;
    is_native: boolean;
    is_abstract: boolean;
    source_location: string;
    confidence: string;
    status: string;
    score: number;
    callers: string[];
    callees: string[];
    purchase_relevance_evidence: string[];
    decompiled_snippet?: string;
  }>;
  constructors: Array<{
    dex_file: string;
    class_name: string;
    constructor_signature: string;
    verification: string;
    network_interaction: string;
    initializes_billing_client: boolean;
    sets_premium_flags: boolean;
    reads_local_state: boolean;
    called_methods: string[];
    evidence: string[];
  }>;
  network: {
    endpoints?: Array<{
      url: string;
      domain: string;
      http_method?: string;
      client_library?: string;
      referenced_from_class?: string;
      referenced_from_method?: string;
      dex_file?: string;
      is_purchase_related?: boolean;
      relevance_reason?: string;
    }>;
  };
  call_graph: {
    nodes?: Array<{ id: string; label: string; type: string; dex_file?: string }>;
    edges?: Array<{ source: string; target: string; label: string }>;
    sample_flow_path?: string[];
  };
  classification: {
    classification: "SERVER_SIDE" | "CLIENT_SIDE" | "MIXED" | "UNKNOWN";
    confidence: "High" | "Medium" | "Low";
    reasons?: string[];
    server_side_evidence?: string[];
    client_side_evidence?: string[];
  };
  evidence: string[];
  analysis_status?: string;
  gemini_interpretation?: {
    summary?: string;
    payment_architecture?: string;
    strongest_boolean_candidate?: { dex?: string; class?: string; method?: string; reason?: string };
    classification_explanation?: string;
    discrepancies?: string[];
    confidence?: string;
  };
}

export default function App() {
  const [samples, setSamples] = useState<any[]>([]);
  const [selectedSample, setSelectedSample] = useState("demo");
  const [customFile, setCustomFile] = useState<File | null>(null);
  const [customFileBase64, setCustomFileBase64] = useState<string | null>(null);
  const [enableGemini, setEnableGemini] = useState(true);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"boolean" | "constructors" | "callgraph" | "network" | "gemini" | "raw" | "github">("boolean");
  const [report, setReport] = useState<ApkAnalysisReport | null>(null);
  const [htmlReport, setHtmlReport] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [copiedYaml, setCopiedYaml] = useState(false);

  // Fetch samples on load and auto-analyze demo APK
  useEffect(() => {
    fetch("/api/samples")
      .then((r) => r.json())
      .then((data) => {
        if (data.samples) {
          setSamples(data.samples);
        }
      })
      .catch(() => {});

    // Initial analysis
    runAnalysis("demo", null);
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setCustomFile(file);
      const reader = new FileReader();
      reader.onload = () => {
        setCustomFileBase64(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const runAnalysis = async (sampleId?: string, fileB64?: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sampleId: sampleId || selectedSample,
          customApkBase64: fileB64 !== undefined ? fileB64 : customFileBase64,
          filename: customFile?.name,
          enableGemini: enableGemini,
        }),
      });
      const data = await res.json();
      if (data.success && data.report) {
        setReport(data.report);
        setHtmlReport(data.htmlReport || "");
      } else {
        setError(data.error || "Static analysis execution failed.");
      }
    } catch (err: any) {
      setError(err.message || "Failed to communicate with analysis server");
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getBadgeClass = (type?: string) => {
    switch (type) {
      case "SERVER_SIDE":
        return "bg-emerald-100 text-emerald-800 border-emerald-300";
      case "CLIENT_SIDE":
        return "bg-amber-100 text-amber-800 border-amber-300";
      case "MIXED":
        return "bg-blue-100 text-blue-800 border-blue-300";
      default:
        return "bg-slate-100 text-slate-800 border-slate-300";
    }
  };

  const filteredBooleans = (report?.purchase_boolean_methods || []).filter((m) => {
    const q = searchTerm.toLowerCase();
    return (
      m.method_name.toLowerCase().includes(q) ||
      m.class_name.toLowerCase().includes(q) ||
      m.dex_file.toLowerCase().includes(q)
    );
  });

  const topCandidate = report?.purchase_boolean_methods?.[0];

  const githubWorkflowYaml = `name: APK In-App Billing Static Analysis
on:
  workflow_dispatch:
    inputs:
      apk_path:
        description: 'Relative path to the APK file in repository (e.g. sample_apks/app.apk)'
        required: false
        default: ''
      apk_url:
        description: 'Direct download URL for the APK to analyze'
        required: false
        default: ''
      enable_gemini:
        description: 'Enable Gemini AI static fact interpretation'
        type: boolean
        required: false
        default: true

jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - name: Execute Static Analysis
        env:
          GEMINI_API_KEY: \${{ secrets.GEMINI_API_KEY }}
        run: |
          python analyze.py --apk target.apk --output-dir output --gemini
      - uses: actions/upload-artifact@v4
        with:
          name: apk-purchase-analysis-report
          path: output/`;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">
      {/* Top Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30 px-6 py-4 shadow-xs">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-600 text-white rounded-xl shadow-xs">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-900 tracking-tight">APK-Static-Analyzer</h1>
                <span className="text-xs px-2.5 py-0.5 bg-blue-50 text-blue-700 border border-blue-200 font-semibold rounded-full">
                  Multi-DEX Engine
                </span>
              </div>
              <p className="text-xs text-slate-500">
                Static Reverse Engineering, In-App Purchase & Boolean Entitlement Locator
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab("github")}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-300 transition-colors"
            >
              <FileCode className="w-3.5 h-3.5" />
              GitHub Action Workflow
            </button>
            {report && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => downloadFile(JSON.stringify(report, null, 2), "analysis.json", "application/json")}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  JSON
                </button>
                <button
                  onClick={() => downloadFile(htmlReport, "report.html", "text/html")}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-lg transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  HTML Report
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-6 py-6 w-full flex-1 space-y-6">
        
        {/* Controls Card */}
        <section className="bg-white p-5 rounded-2xl border border-slate-200 shadow-xs">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
                  Target APK Selection
                </label>
                <div className="flex items-center gap-2">
                  <select
                    value={customFile ? "custom" : selectedSample}
                    onChange={(e) => {
                      if (e.target.value === "custom") {
                        // Keep custom
                      } else {
                        setSelectedSample(e.target.value);
                        setCustomFile(null);
                        setCustomFileBase64(null);
                      }
                    }}
                    className="text-sm bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 font-medium text-slate-800 focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                  >
                    {samples.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.dexCount} DEX files)
                      </option>
                    ))}
                    {customFile && <option value="custom">Custom: {customFile.name}</option>}
                  </select>

                  <label className="cursor-pointer text-xs font-medium px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg border border-slate-300 transition-colors flex items-center gap-1.5">
                    <Smartphone className="w-3.5 h-3.5" />
                    Upload APK
                    <input type="file" accept=".apk" onChange={handleFileUpload} className="hidden" />
                  </label>
                </div>
              </div>

              <div className="flex items-center pt-5">
                <label className="flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableGemini}
                    onChange={(e) => setEnableGemini(e.target.checked)}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
                  />
                  <span className="flex items-center gap-1">
                    <Sparkles className="w-3.5 h-3.5 text-purple-600" />
                    Gemini AI Fact Interpretation
                  </span>
                </label>
              </div>
            </div>

            <button
              onClick={() => runAnalysis(selectedSample, customFileBase64)}
              disabled={loading}
              className="w-full lg:w-auto px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium text-sm rounded-xl shadow-sm transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Analyzing Multi-DEX & In-App Purchases...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  Execute Static Analysis
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-xl text-red-700 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </section>

        {report && (
          <>
            {/* 🎯 SPOTLIGHT CARD: Where is the Purchase Boolean Method located? */}
            <section className="bg-linear-to-br from-blue-50 via-indigo-50/50 to-white p-6 rounded-2xl border-2 border-blue-500 shadow-sm relative overflow-hidden">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="px-2.5 py-0.5 bg-blue-600 text-white text-xs font-bold rounded-md">
                      🎯 Primary Boolean Locator
                    </span>
                    <span className="text-xs font-semibold text-blue-900">
                      دالة الـ Boolean الخاصة بحالة الشراء موجودة فين؟
                    </span>
                  </div>

                  {topCandidate ? (
                    <div className="space-y-1.5 mt-2">
                      <div className="flex flex-wrap items-baseline gap-2">
                        <span className="text-xs px-2 py-0.5 bg-blue-200 text-blue-900 font-mono font-bold rounded-md">
                          DEX: {topCandidate.dex_file}
                        </span>
                        <span className="text-base font-mono font-bold text-slate-900">
                          {topCandidate.class_name}.<span className="text-blue-600">{topCandidate.method_name}</span>()
                        </span>
                        <span className="text-xs px-2 py-0.5 bg-slate-200 font-mono text-slate-800 rounded-md">
                          Return: boolean (Z)
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Signature: {topCandidate.signature} &bull; Source: {topCandidate.source_location}
                      </p>
                      <div className="text-xs text-blue-800 font-medium pt-1">
                        <strong>Evidence:</strong> {topCandidate.purchase_relevance_evidence.join(" • ")}
                      </div>
                    </div>
                  ) : (
                    <p className="text-sm text-slate-500 mt-2">
                      No high-confidence Boolean purchase method discovered in current DEX files.
                    </p>
                  )}
                </div>

                <div className="flex flex-col items-end gap-2 shrink-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500 uppercase font-semibold">Classification:</span>
                    <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getBadgeClass(report.classification?.classification)}`}>
                      {report.classification?.classification} ({report.classification?.confidence} Confidence)
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono">
                    {report.dex_files?.length || 0} DEX Files &bull; {report.apk?.package_name}
                  </div>
                </div>
              </div>
            </section>

            {/* Quick Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="bg-white p-4 rounded-xl border border-slate-200">
                <div className="text-xs uppercase font-semibold text-slate-400">Package Name</div>
                <div className="text-sm font-bold text-slate-800 font-mono truncate mt-1">
                  {report.apk?.package_name || "N/A"}
                </div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200">
                <div className="text-xs uppercase font-semibold text-slate-400">SDK Target</div>
                <div className="text-sm font-bold text-slate-800 mt-1">
                  Min: {report.apk?.min_sdk} | Target: {report.apk?.target_sdk}
                </div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200">
                <div className="text-xs uppercase font-semibold text-slate-400">Payment Providers</div>
                <div className="text-sm font-bold text-blue-600 truncate mt-1">
                  {report.billing?.providers_detected?.join(", ") || "None"}
                </div>
              </div>
              <div className="bg-white p-4 rounded-xl border border-slate-200">
                <div className="text-xs uppercase font-semibold text-slate-400">Multi-DEX Breakdown</div>
                <div className="text-sm font-bold text-slate-800 mt-1">
                  {report.dex_files?.length} DEX files analyzed
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="border-b border-slate-200 flex flex-wrap gap-2 text-sm font-medium">
              <button
                onClick={() => setActiveTab("boolean")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "boolean"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <Code2 className="w-4 h-4" />
                Boolean Methods ({report.purchase_boolean_methods?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab("constructors")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "constructors"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <Layers className="w-4 h-4" />
                Constructor Analysis ({report.constructors?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab("callgraph")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "callgraph"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <ArrowRight className="w-4 h-4" />
                Call Graph
              </button>
              <button
                onClick={() => setActiveTab("network")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "network"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <Network className="w-4 h-4" />
                Network Endpoints ({report.network?.endpoints?.length || 0})
              </button>
              {report.gemini_interpretation && (
                <button
                  onClick={() => setActiveTab("gemini")}
                  className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                    activeTab === "gemini"
                      ? "border-purple-600 text-purple-600"
                      : "border-transparent text-purple-500 hover:text-purple-700"
                  }`}
                >
                  <Sparkles className="w-4 h-4" />
                  Gemini AI Synthesis
                </button>
              )}
              <button
                onClick={() => setActiveTab("raw")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "raw"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <Terminal className="w-4 h-4" />
                Raw JSON Schema
              </button>
              <button
                onClick={() => setActiveTab("github")}
                className={`pb-3 px-3 border-b-2 font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeTab === "github"
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <FileCode className="w-4 h-4" />
                GitHub Workflow Guide
              </button>
            </div>

            {/* TAB CONTENT: Boolean Methods */}
            {activeTab === "boolean" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <div className="relative flex-1 max-w-md">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search class, method, or DEX..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-9 pr-3 py-1.5 text-xs bg-white border border-slate-300 rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <span className="text-xs text-slate-500">
                    Showing {filteredBooleans.length} candidate(s)
                  </span>
                </div>

                <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold">
                          <th className="p-3">DEX File</th>
                          <th className="p-3">Enclosing Class</th>
                          <th className="p-3">Method Name & Signature</th>
                          <th className="p-3">Return Type</th>
                          <th className="p-3">Confidence</th>
                          <th className="p-3">Evidence & Callers</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {filteredBooleans.map((m, idx) => (
                          <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                            <td className="p-3 font-mono font-medium text-slate-700">
                              <span className="px-2 py-0.5 bg-slate-100 rounded-md border border-slate-200">
                                {m.dex_file}
                              </span>
                            </td>
                            <td className="p-3 font-mono font-semibold text-slate-900 max-w-[220px] truncate">
                              {m.class_name}
                            </td>
                            <td className="p-3 font-mono">
                              <div className="font-bold text-blue-600">{m.method_name}()</div>
                              <div className="text-[11px] text-slate-400">{m.signature}</div>
                            </td>
                            <td className="p-3">
                              <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-md font-mono text-[11px]">
                                boolean (Z)
                              </span>
                            </td>
                            <td className="p-3">
                              <span
                                className={`px-2 py-0.5 rounded-full font-bold text-[11px] ${
                                  m.confidence === "High"
                                    ? "bg-emerald-100 text-emerald-800"
                                    : m.confidence === "Medium"
                                    ? "bg-amber-100 text-amber-800"
                                    : "bg-slate-100 text-slate-700"
                                }`}
                              >
                                {m.confidence}
                              </span>
                            </td>
                            <td className="p-3 max-w-sm">
                              <div className="space-y-1">
                                {m.purchase_relevance_evidence.slice(0, 2).map((ev, i) => (
                                  <div key={i} className="text-[11px] text-slate-600 flex items-start gap-1">
                                    <span className="text-blue-500">•</span>
                                    <span>{ev}</span>
                                  </div>
                                ))}
                                {m.callers.length > 0 && (
                                  <div className="text-[10px] text-slate-400 font-mono truncate">
                                    Callers: {m.callers.join(", ")}
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Constructor Analysis */}
            {activeTab === "constructors" && (
              <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
                <div className="p-4 border-b border-slate-200 bg-slate-50">
                  <h3 className="text-sm font-bold text-slate-800">Constructor &lt;init&gt; Verification Evaluation</h3>
                  <p className="text-xs text-slate-500">
                    Distinguishes between genuine purchase verification vs merely initializing BillingClient.
                  </p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold">
                        <th className="p-3">DEX</th>
                        <th className="p-3">Class</th>
                        <th className="p-3">Verification</th>
                        <th className="p-3">Network Interaction</th>
                        <th className="p-3">Evidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {report.constructors?.map((c, i) => (
                        <tr key={i} className="hover:bg-slate-50/80">
                          <td className="p-3 font-mono font-medium">{c.dex_file}</td>
                          <td className="p-3 font-mono font-semibold text-slate-900">{c.class_name}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded-full font-bold text-[11px] ${
                                c.verification === "YES"
                                  ? "bg-emerald-100 text-emerald-800"
                                  : "bg-slate-100 text-slate-700"
                              }`}
                            >
                              {c.verification}
                            </span>
                          </td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded-full font-bold text-[11px] ${
                                c.network_interaction === "YES"
                                  ? "bg-blue-100 text-blue-800"
                                  : "bg-slate-100 text-slate-700"
                              }`}
                            >
                              {c.network_interaction}
                            </span>
                          </td>
                          <td className="p-3 text-slate-600 text-xs">{c.evidence.join("; ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Call Graph */}
            {activeTab === "callgraph" && (
              <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-xs space-y-4">
                <div>
                  <h3 className="text-sm font-bold text-slate-800">Targeted Payment & Entitlement Call Graph</h3>
                  <p className="text-xs text-slate-500">
                    Direct path from UI entrypoints down to boolean entitlement methods and backend verification endpoints.
                  </p>
                </div>

                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
                  <div className="text-xs font-semibold text-slate-500 uppercase mb-3">Sample Flow Execution Path</div>
                  <div className="flex flex-wrap items-center gap-2">
                    {report.call_graph?.sample_flow_path?.map((step, idx) => (
                      <React.Fragment key={idx}>
                        <div className="px-3 py-2 bg-white border border-slate-200 rounded-lg shadow-xs font-mono text-xs font-medium text-slate-800">
                          {step}
                        </div>
                        {idx < (report.call_graph?.sample_flow_path?.length || 0) - 1 && (
                          <ArrowRight className="w-4 h-4 text-blue-500 shrink-0" />
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="p-4 bg-white border border-slate-200 rounded-xl">
                    <h4 className="text-xs font-bold text-slate-700 uppercase mb-2">Graph Nodes</h4>
                    <div className="space-y-1.5 max-h-60 overflow-y-auto">
                      {report.call_graph?.nodes?.map((n, i) => (
                        <div key={i} className="text-xs font-mono p-2 bg-slate-50 rounded-md flex items-center justify-between">
                          <span className="font-semibold text-slate-800">{n.label}</span>
                          <span className="text-[10px] px-1.5 py-0.5 bg-slate-200 rounded-sm uppercase text-slate-600">
                            {n.type}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-white border border-slate-200 rounded-xl">
                    <h4 className="text-xs font-bold text-slate-700 uppercase mb-2">Graph Edges (Invocations)</h4>
                    <div className="space-y-1.5 max-h-60 overflow-y-auto">
                      {report.call_graph?.edges?.map((e, i) => (
                        <div key={i} className="text-xs font-mono p-2 bg-slate-50 rounded-md">
                          <span className="text-slate-600 truncate">{e.source.split("->")[0]}</span>
                          <span className="text-blue-500 font-bold mx-1">&rarr;</span>
                          <span className="text-slate-900 font-semibold">{e.target.split("->")[0]}</span>
                          <span className="text-[10px] text-slate-400 ml-2">({e.label})</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Network */}
            {activeTab === "network" && (
              <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
                <div className="p-4 border-b border-slate-200 bg-slate-50">
                  <h3 className="text-sm font-bold text-slate-800">Discovered Network Endpoints & Purchase APIs</h3>
                  <p className="text-xs text-slate-500">
                    URLs, Retrofit interfaces, and OkHttp requests correlated to billing methods.
                  </p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold">
                        <th className="p-3">Type</th>
                        <th className="p-3">URL / Endpoint</th>
                        <th className="p-3">Domain</th>
                        <th className="p-3">HTTP Method</th>
                        <th className="p-3">Referenced In</th>
                        <th className="p-3">DEX</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {report.network?.endpoints?.map((ep, i) => (
                        <tr key={i} className={`hover:bg-slate-50/80 ${ep.is_purchase_related ? "bg-red-50/30" : ""}`}>
                          <td className="p-3">
                            {ep.is_purchase_related ? (
                              <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-md font-bold text-[10px]">
                                Purchase API
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded-md text-[10px]">
                                Generic
                              </span>
                            )}
                          </td>
                          <td className="p-3 font-mono font-medium text-slate-900 max-w-xs break-all">{ep.url}</td>
                          <td className="p-3 font-mono text-slate-600">{ep.domain}</td>
                          <td className="p-3 font-mono font-bold text-slate-700">{ep.http_method || "POST"}</td>
                          <td className="p-3 font-mono text-xs text-blue-600">
                            {ep.referenced_from_class} &rarr; {ep.referenced_from_method}
                          </td>
                          <td className="p-3 font-mono text-slate-500">{ep.dex_file}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Gemini AI Interpretation */}
            {activeTab === "gemini" && report.gemini_interpretation && (
              <div className="bg-white p-6 rounded-2xl border border-purple-200 shadow-xs space-y-4">
                <div className="flex items-center gap-2 text-purple-700">
                  <Sparkles className="w-5 h-5" />
                  <h3 className="text-base font-bold">Grounded Gemini AI Interpretation (Stage 2)</h3>
                </div>

                <div className="p-4 bg-purple-50 rounded-xl border border-purple-100 text-xs text-purple-900 leading-relaxed">
                  <div className="font-bold mb-1">Executive Summary:</div>
                  {report.gemini_interpretation.summary}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
                    <h4 className="text-xs font-bold text-slate-700 uppercase mb-2">Payment Architecture Breakdown</h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {report.gemini_interpretation.payment_architecture}
                    </p>
                  </div>

                  <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
                    <h4 className="text-xs font-bold text-slate-700 uppercase mb-2">Classification Rationale</h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {report.gemini_interpretation.classification_explanation}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Raw JSON */}
            {activeTab === "raw" && (
              <div className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs overflow-x-auto max-h-[600px]">
                <pre>{JSON.stringify(report, null, 2)}</pre>
              </div>
            )}

            {/* TAB CONTENT: GitHub Workflow Guide */}
            {activeTab === "github" && (
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-xs space-y-6">
                <div>
                  <h3 className="text-base font-bold text-slate-900">GitHub Actions Workflow Configuration</h3>
                  <p className="text-xs text-slate-500 mt-1">
                    The workflow is strictly configured for <strong>workflow_dispatch</strong> (manual trigger only, never on push/PR).
                  </p>
                </div>

                <div className="relative">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(githubWorkflowYaml);
                      setCopiedYaml(true);
                      setTimeout(() => setCopiedYaml(false), 2000);
                    }}
                    className="absolute right-3 top-3 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedYaml ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedYaml ? "Copied!" : "Copy YAML"}
                  </button>
                  <pre className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs overflow-x-auto">
                    {githubWorkflowYaml}
                  </pre>
                </div>

                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                  <h4 className="text-xs font-bold text-slate-800 uppercase">How to Run on GitHub:</h4>
                  <ol className="list-decimal list-inside text-xs text-slate-600 space-y-1">
                    <li>Push this repository to GitHub.</li>
                    <li>(Optional) Add your <code className="bg-slate-200 px-1 py-0.5 rounded">GEMINI_API_KEY</code> to <strong>Repository Settings &gt; Secrets and variables &gt; Actions</strong>.</li>
                    <li>Go to the <strong>Actions</strong> tab and select <strong>APK In-App Billing Static Analysis</strong>.</li>
                    <li>Click <strong>Run workflow</strong> and provide an APK path or download URL.</li>
                    <li>Download the generated <strong>apk-purchase-analysis-report</strong> artifact containing <code className="bg-slate-200 px-1 py-0.5 rounded">analysis.json</code> and <code className="bg-slate-200 px-1 py-0.5 rounded">report.html</code>.</li>
                  </ol>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
