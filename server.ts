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
const INPUT_DIR = path.join(process.cwd(), "input");
if (!fs.existsSync(SAMPLES_DIR)) {
  fs.mkdirSync(SAMPLES_DIR, { recursive: true });
}
if (!fs.existsSync(INPUT_DIR)) {
  fs.mkdirSync(INPUT_DIR, { recursive: true });
}

// Ensure demo apk and apks exist
const demoApkPath = path.join(SAMPLES_DIR, "demo.apk");
const demoApksPath = path.join(SAMPLES_DIR, "demo.apks");
const inputApksPath = path.join(INPUT_DIR, "app.apks");

if (!fs.existsSync(demoApkPath)) {
  try {
    execFileAsync("python3", ["tests/create_test_apk.py", "--output", demoApkPath]);
  } catch (err) {
    console.error("Error creating demo APK:", err);
  }
}

if (!fs.existsSync(demoApksPath)) {
  try {
    execFileAsync("python3", ["-c", `from tests.create_test_apk import create_synthetic_apks; create_synthetic_apks('${demoApksPath}')`]);
  } catch (err) {
    console.error("Error creating demo APKS:", err);
  }
}

if (!fs.existsSync(inputApksPath)) {
  try {
    execFileAsync("python3", ["-c", `from tests.create_test_apk import create_synthetic_apks; create_synthetic_apks('${inputApksPath}')`]);
  } catch (err) {
    console.error("Error creating input APKS:", err);
  }
}

// 1. API: List available sample targets (.apk and .apks)
app.get("/api/samples", (req, res) => {
  try {
    const samples = [
      {
        id: "apks_bundle",
        name: "Android_App_Bundle_Export.apks",
        description: "Android App Bundle (.apks) containing base.apk and split config APKs with classes*.dex",
        path: "input/app.apks",
        type: "APKS",
        splitsCount: 3,
        dexCount: 4,
        provider: "Google Play Billing",
        expectedClass: "SERVER_SIDE"
      },
      {
        id: "demo",
        name: "PlayBilling_MultiDex_Target.apk",
        description: "Google Play Billing client with remote /subscription/verify API in classes3.dex",
        path: "sample_apks/demo.apk",
        type: "APK",
        splitsCount: 1,
        dexCount: 3,
        provider: "Google Play Billing",
        expectedClass: "SERVER_SIDE"
      },
      {
        id: "revenuecat",
        name: "RevenueCat_Entitlements_App.apk",
        description: "RevenueCat Purchases SDK with customerInfo entitlement check",
        path: "sample_apks/demo.apk",
        type: "APK",
        splitsCount: 1,
        dexCount: 3,
        provider: "RevenueCat",
        expectedClass: "SERVER_SIDE"
      }
    ];
    res.json({ samples });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// 2. API: Execute Static Analysis on target APK or APKS
app.post("/api/analyze", async (req, res) => {
  try {
    const { sampleId, customApkBase64, filename, enableGemini } = req.body;
    let targetPath = demoApksPath;

    if (sampleId === "demo") {
      targetPath = demoApkPath;
    } else if (sampleId === "apks_bundle") {
      targetPath = fs.existsSync(inputApksPath) ? inputApksPath : demoApksPath;
    }

    // If custom APK or APKS uploaded as base64
    if (customApkBase64) {
      const uploadDir = path.join(process.cwd(), "output", "uploads");
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      const safeName = (filename || "uploaded.apk").replace(/[^a-zA-Z0-9._-]/g, "_");
      targetPath = path.join(uploadDir, safeName);
      const buffer = Buffer.from(customApkBase64.split(",")[1] || customApkBase64, "base64");
      fs.writeFileSync(targetPath, buffer);
    } else if (!fs.existsSync(targetPath)) {
      if (targetPath.endsWith(".apks")) {
        await execFileAsync("python3", ["-c", `from tests.create_test_apk import create_synthetic_apks; create_synthetic_apks('${targetPath}')`]);
      } else {
        await execFileAsync("python3", ["tests/create_test_apk.py", "--output", targetPath]);
      }
    }

    const outDir = path.join(process.cwd(), "output", `run_${Date.now()}`);
    fs.mkdirSync(outDir, { recursive: true });

    const pyArgs = [
      "analyze.py",
      "--apk", targetPath,
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
