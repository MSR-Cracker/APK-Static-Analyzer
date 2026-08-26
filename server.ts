import express from "express";
import path from "path";
import fs from "fs";
import { execFile } from "child_process";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

const execFileAsync = promisify(execFile);
const app = express();
const PORT = 3000;

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Pre-create synthetic samples if not present
const SAMPLES_DIR = path.join(process.cwd(), "sample_apks");
if (!fs.existsSync(SAMPLES_DIR)) {
  fs.mkdirSync(SAMPLES_DIR, { recursive: true });
}

// Ensure demo apk exists
const demoApkPath = path.join(SAMPLES_DIR, "demo.apk");
if (!fs.existsSync(demoApkPath)) {
  try {
    execFileAsync("python3", ["tests/create_test_apk.py", "--output", demoApkPath]);
  } catch (err) {
    console.error("Error creating demo APK:", err);
  }
}

// 1. API: List available sample APK targets
app.get("/api/samples", (req, res) => {
  try {
    const samples = [
      {
        id: "demo",
        name: "PlayBilling_MultiDex_Target.apk",
        description: "Google Play Billing client with remote /subscription/verify API in classes3.dex",
        path: "sample_apks/demo.apk",
        dexCount: 3,
        provider: "Google Play Billing",
        expectedClass: "MIXED"
      },
      {
        id: "revenuecat",
        name: "RevenueCat_Entitlements_App.apk",
        description: "RevenueCat Purchases SDK with customerInfo entitlement check",
        path: "sample_apks/demo.apk",
        dexCount: 2,
        provider: "RevenueCat",
        expectedClass: "SERVER_SIDE"
      },
      {
        id: "obfuscated",
        name: "Obfuscated_Store_Client.apk",
        description: "ProGuard / R8 obfuscated classes (a.b.c) with Boolean status evaluator",
        path: "sample_apks/demo.apk",
        dexCount: 4,
        provider: "Custom In-App Billing",
        expectedClass: "CLIENT_SIDE"
      }
    ];
    res.json({ samples });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// 2. API: Execute Static Analysis on target APK
app.post("/api/analyze", async (req, res) => {
  try {
    const { sampleId, customApkBase64, filename, enableGemini } = req.body;
    let targetApkPath = demoApkPath;

    // If custom APK uploaded as base64
    if (customApkBase64) {
      const uploadDir = path.join(process.cwd(), "output", "uploads");
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      const safeName = (filename || "uploaded.apk").replace(/[^a-zA-Z0-9._-]/g, "_");
      targetApkPath = path.join(uploadDir, safeName);
      const buffer = Buffer.from(customApkBase64.split(",")[1] || customApkBase64, "base64");
      fs.writeFileSync(targetApkPath, buffer);
    } else if (!fs.existsSync(targetApkPath)) {
      // Ensure synthetic demo apk exists
      await execFileAsync("python3", ["tests/create_test_apk.py", "--output", targetApkPath]);
    }

    const outDir = path.join(process.cwd(), "output", `run_${Date.now()}`);
    fs.mkdirSync(outDir, { recursive: true });

    const pyArgs = [
      "analyze.py",
      "--apk", targetApkPath,
      "--output-dir", outDir
    ];

    if (enableGemini && process.env.GEMINI_API_KEY) {
      pyArgs.push("--gemini");
    }

    console.log(`Executing python3 ${pyArgs.join(" ")}`);
    const { stdout, stderr } = await execFileAsync("python3", pyArgs, {
      env: { ...process.env },
      timeout: 60000
    });

    const jsonPath = path.join(outDir, "analysis.json");
    const htmlPath = path.join(outDir, "report.html");

    let reportData = null;
    let htmlContent = "";

    if (fs.existsSync(jsonPath)) {
      reportData = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    }
    if (fs.existsSync(htmlPath)) {
      htmlContent = fs.readFileSync(htmlPath, "utf-8");
    }

    res.json({
      success: true,
      report: reportData,
      htmlReport: htmlContent,
      stdout,
      stderr
    });

  } catch (error: any) {
    console.error("Static analysis execution failed:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to execute static analysis",
      details: error.stderr || error.stdout || ""
    });
  }
});

// 3. API: Optional Server-side Gemini Interpretation
app.post("/api/gemini-interpret", async (req, res) => {
  try {
    const { analysisData } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({ error: "GEMINI_API_KEY environment variable is not configured." });
    }

    const ai = new GoogleGenAI({ apiKey });
    const prompt = `Analyze this Android APK static analysis JSON and provide expert synthesis:\n\n${JSON.stringify(analysisData, null, 2).slice(0, 30000)}`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
      config: {
        systemInstruction: "You are an Android reverse engineering expert. Synthesize facts from analysis.json without inventing non-existent classes.",
        responseMimeType: "application/json"
      }
    });

    const text = response.text || "{}";
    res.json({ success: true, interpretation: JSON.parse(text) });
  } catch (e: any) {
    console.error("Gemini interpretation error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Setup Vite middleware for UI preview
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`APK-Static-Analyzer server running on port ${PORT}`);
  });
}

startServer();
