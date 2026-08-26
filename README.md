# 🛡️ APK-Static-Analyzer

**أداة التحليل الساكن المتقدمة لتطبيقات أندرويد واكتشاف منظومة التحقق من الشراء داخل التطبيق (In-App Purchases & Billing Verification Detection)**

An advanced, deterministic, multi-DEX Android Static Analysis engine designed for GitHub Actions (`workflow_dispatch`) and standalone CLI usage. It deeply inspects APK binaries to dissect payment flows, identify exact Boolean entitlement verification methods, examine constructors, analyze network endpoints, and produce structured `analysis.json` and interactive `report.html` reports.

---

## 🌟 المميزات الرئيسية (Key Capabilities)

1. **دعم كامل لجميع ملفات الـ DEX المتعددة (Multi-DEX Engine)**:
   - يفكك ويحلل جميع ملفات `classes.dex`, `classes2.dex`, `classes3.dex`, `classes4.dex`... إلخ ولا يفترض وجود الكود في DEX الأول.
   - يستخرج الفئات (Classes)، الدوال (Methods)، التواقيع (Signatures)، المعاملات (Parameters)، ومعدلات الوصول (Access Modifiers).
2. **محرك اكتشاف منطق الدفع (Payment & Billing Engine)**:
   - يدعم Google Play Billing (بما يشمل `BillingClient`, `ProductDetails`, `PurchasesUpdatedListener`, `acknowledgePurchase`, `consumePurchase`, `queryPurchases`).
   - يدعم مكتبات الدفع مثل RevenueCat, Stripe, PayPal, WebViews ومسارات التحقق المخصصة (Custom Purchase APIs).
3. **مكتشف دوال الـ Boolean لحالة الشراء (`PurchaseBooleanDetector`)**:
   - يبحث عن دوال ترجع `boolean` (`Z` في Dalvik) ويقيمها عبر تحليل السياق، الـ Call Graph، استدعاءات `SharedPreferences`، والمؤشرات النصية.
   - يعطي الإجابة الدقيقة على سؤال: **"دالة الـ Boolean الخاصة بحالة الشراء موجودة فين؟"** مع تحديد ملف الـ DEX، الفئة، التوقيع، ومستوى الثقة (`High` / `Medium` / `Low`).
4. **تحليل دوال البناء (`ConstructorAnalyzer` - `<init>`)**:
   - يحلل هل دالة البناء تقوم بتهيئة حالة الشراء، قراءة التخزين المحلي، استدعاء دوال التحقق، أو استدعاء شبكي.
   - يفرّق بدقة بين مجرد تهيئة `BillingClient` وبين التحقق الفعلي من الشراء.
5. **تصنيف المعمارية (Architecture Classification)**:
   - يصنف التطبيق بناءً على الأدلة الصارمة إلى:
     - `SERVER_SIDE`: التحقق مركزي عبر السيرفر والـ API.
     - `CLIENT_SIDE`: التحقق محلي داخل التطبيق (Flags / Preferences / Local checks).
     - `MIXED`: نظام هجين يجمع بين التخزين المحلي والتحقق الشبكي.
     - `UNKNOWN`: عدم وجود أدلة كافية.
6. **تحليل الشبكة ورسم الـ Call Graph**:
   - يستخرج جميع الروابط، النطاقات (Domains)، ونقاط النهاية (Endpoints) ويربطها بدوال الدفع المستدعية لها.
   - يرسم مسار تدفق مبسط من واجهات المستخدم (Activities) وصولاً لدوال التحقق والروابط الخارجية.
7. **تكامل منضبط مع Gemini AI**:
   - الذكاء الاصطناعي يعمل في مرحلة التفسير والربط فقط (Interpretation Stage) اعتمادًا على حقائق `analysis.json`.
   - محظور تمامًا من اختراع أو افتراض أي Class أو Method أو DEX غير موجود في التحليل الساكن.
8. **تشغيل يدوي صارم عبر GitHub Actions**:
   - يعمل فقط عبر `workflow_dispatch` بدون تشغيل تلقائي عند الـ push أو pull request.

---

## 📁 هيكلية المشروع (Project Tree)

```text
APK-Static-Analyzer/
├── .github/
│   └── workflows/
│       └── apk-analysis.yml          # GitHub Actions Workflow (Manual dispatch only)
├── analyzer/
│   ├── __init__.py
│   ├── models.py                     # Dataclass schemas (ApkInfo, DexMethod, etc.)
│   ├── core/
│   │   ├── apk_parser.py             # Binary AndroidManifest, SDK, and components extractor
│   │   ├── dex_parser.py             # Multi-DEX binary bytecode parser & cross-referencer
│   │   ├── decompiler.py             # JADX integration & Dalvik fallback
│   │   └── callgraph.py              # Targeted payment call graph builder
│   ├── detectors/
│   │   ├── base.py                   # Base detector interface
│   │   ├── billing_detector.py       # Google Play, RevenueCat, Stripe, PayPal detector
│   │   ├── boolean_detector.py       # PurchaseBooleanDetector (Contextual locator)
│   │   ├── constructor_analyzer.py   # <init> constructor analyzer
│   │   ├── network_analyzer.py       # URL, domain, and API endpoint extractor
│   │   └── classifier.py             # Server-side vs Client-side classifier
│   ├── ai/
│   │   └── gemini_interpreter.py     # Grounded Gemini AI interpretation
│   └── reporters/
│       ├── json_reporter.py          # Compliant analysis.json generator
│       └── html_reporter.py          # Standalone responsive report.html generator
├── tests/
│   ├── create_test_apk.py            # Generates synthetic multi-DEX test APK fixtures
│   └── test_pipeline.py              # Automated test suite
├── sample_apks/                      # Directory for sample target APKs
├── analyze.py                        # CLI entry point
├── requirements.txt                  # Python dependencies
├── pyproject.toml                    # Package configuration
└── README.md                         # Documentation
```

---

## 🚀 طريقة التشغيل (How to Run)

### 1. التشغيل المحلي عبر Command Line (CLI)

```bash
# 1. تثبيت المتطلبات
pip install -r requirements.txt

# 2. إنشاء APK تجريبي متعدد ملفات DEX (اختياري للاختبار السريع)
python tests/create_test_apk.py --output sample_apks/demo.apk

# 3. تشغيل التحليل الساكن
python analyze.py --apk sample_apks/demo.apk --output-dir output

# 4. تشغيل التحليل مع تفعيل تفسير Gemini AI (اختياري)
export GEMINI_API_KEY="your_api_key_here"
python analyze.py --apk sample_apks/demo.apk --output-dir output --gemini
```

### 2. التشغيل عبر GitHub Actions (Manual Workflow)

1. ارفع المشروع إلى مستودعك على GitHub.
2. إذا رغبت بتفعيل تفسير الذكاء الاصطناعي، أضف مفتاح `GEMINI_API_KEY` داخل:
   `Repository Settings` ➡️ `Secrets and variables` ➡️ `Actions` ➡️ `New repository secret`.
3. اذهب إلى تبويب **Actions** في المستودع.
4. اختر **"APK In-App Billing Static Analysis"**.
5. اضغط على **"Run workflow"**:
   - أدخل مسار الـ APK داخل المستودع (مثل `sample_apks/app.apk`) **أو** رابط تحميل مباشر للـ APK.
   - اختر ما إذا كنت تريد تفعيل JADX أو Gemini AI.
6. بعد انتهاء الـ Workflow، قم بتحميل الـ Artifact باسم **`apk-purchase-analysis-report`** والذي يحتوي على:
   - `analysis.json`
   - `report.html`

---

## 📊 بنية النتائج والتقارير (Output Artifacts)

### 1. `analysis.json` (Structured JSON Schema)

```json
{
  "apk": {
    "package_name": "com.example.targetapp",
    "version_name": "1.0",
    "version_code": "1",
    "min_sdk": "21",
    "target_sdk": "33",
    "total_dex_count": 3,
    "permissions": ["android.permission.INTERNET", "com.android.vending.BILLING"]
  },
  "dex_files": [
    {"name": "classes.dex"},
    {"name": "classes2.dex"},
    {"name": "classes3.dex"}
  ],
  "billing": {
    "providers_detected": ["Google Play Billing"],
    "has_play_billing": true,
    "has_revenuecat": false
  },
  "purchase_boolean_methods": [
    {
      "dex_file": "classes3.dex",
      "class_name": "com.example.billing.PurchaseManager",
      "method_name": "isPurchased",
      "signature": "()Z",
      "return_type": "boolean",
      "confidence": "High",
      "status": "Confirmed",
      "purchase_relevance_evidence": [
        "Method name 'isPurchased' explicitly matches purchase keyword",
        "References purchase/entitlement strings: ['is_purchased', 'sku_pro_access']"
      ]
    }
  ],
  "constructors": [
    {
      "dex_file": "classes3.dex",
      "class_name": "com.example.billing.PurchaseManager",
      "verification": "NO",
      "network_interaction": "NO",
      "evidence": ["Initializes BillingClient instance via builder"]
    }
  ],
  "network": {
    "endpoints": [
      {
        "url": "https://api.example.com/subscription/verify",
        "domain": "api.example.com",
        "is_purchase_related": true,
        "dex_file": "classes3.dex"
      }
    ]
  },
  "classification": {
    "classification": "SERVER_SIDE",
    "confidence": "High",
    "reasons": ["Entitlement verification is delegated to remote backend API servers."]
  },
  "evidence": [...]
}
```

### 2. `report.html` (Standalone Interactive Report)
تقرير HTML تفاعلي متجاوب وخفيف يعمل دون الحاجة لإنترنت أو خوادم خارجية، يقدم جداول قابلة للبحث، شارات الثقة، وتحديد الموقع الأبرز لدالة التحقق.

---

## 🔒 الأمان والسرية (Security Guidelines)

- لا يتم تضمين أي مفاتيح API داخل الكود المصدري.
- يتم استقبال `GEMINI_API_KEY` حصرياً عبر متغيرات البيئة أو GitHub Secrets.
- الـ Workflow لا يطبع أي أسرار في سجلات التشغيل (Logs).
- الأداة **لا تعدل** الـ APK الأصلي، **لا تعيد بناءه**، و**لا تقوم بتوقيعه**.

---

## ⚠️ حدود التحليل الساكن (Known Limitations)

1. **المكتبات الأصلية (Native Code / C / C++ `.so`)**: إذا كان منطق التحقق مبرمجًا بالكامل داخل مكتبة C/C++ أصلية عبر JNI (`System.loadLibrary`) دون دوال Java/Kotlin وسيطة، يتم الإشارة إلى وجود مكتبة Native ولكن لا يتم تفكيك كود الـ ARM الثنائي بالكامل.
2. **الحزم المشفرة والـ Packers القوية**: التطبيقات المحمية بحلول Enterprise Packers (مثل Bangcle أو DexGuard المتقدم) قد تخفي كود DEX الأصلي أثناء التحليل الساكن قبل تشغيل الـ Runtime.
3. **التحقق السحابي الصارم (Pure Server-Side Entitlement)**: في التطبيقات التي لا تحوي أي كود محلي وتعتمد 100% على توكن الـ JWT القادم من السيرفر، يتم تصنيفها كـ `SERVER_SIDE` مع توضيح نقطة التحقق الشبكية.
