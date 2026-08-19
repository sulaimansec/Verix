# 🛡️ Verix

**Claude-driven, non-destructive web application & LLM-widget vulnerability scanner.**
Autonomous recon → AI-generated attack hypotheses → safe payload testing → graded, before/after-comparable reports. Interactive CLI and a Streamlit dashboard, both wired to the same engine.

> ⚠️ **Only scan targets you are explicitly authorized to test.** The tool refuses to run without `--confirm-scope` / the dashboard's authorization checkbox, and defaults to non-destructive HTTP methods only.

---

## Table of contents
- [English](#english)
  - [What it does](#what-it-does)
  - [Architecture](#architecture)
  - [Project stats](#project-stats)
  - [Real bugs found & fixed during development](#real-bugs-found--fixed-during-development)
  - [Example scan output](#example-scan-output)
  - [Install & run](#install--run)
  - [Safety design](#safety-design)
- [العربية](#العربية)

---

## English

### What it does

1. **Recon** — Playwright crawls the target (configurable depth), collecting pages, forms/params, cookies, response headers, third-party scripts, and fingerprints of embedded AI/chat widgets.
2. **AI-driven hypotheses** — the recon summary goes to Claude, which proposes up to 12 attack hypotheses covering OWASP Top 10, business-logic flaws (IDOR, race conditions, workflow bypass), and — when a chat widget is detected — OWASP Top 10 for LLM Applications (prompt injection, system-prompt leakage, jailbreak, excessive agency/SSRF, excessive disclosure).
3. **Safe probing** — Claude generates non-destructive payloads per hypothesis (reflection/timing/benign-marker based, never data-mutating), fired over `httpx` with concurrency + rate limiting, restricted to `GET`/`POST`/`HEAD`/`OPTIONS` unless unsafe methods are explicitly opted into.
4. **Analysis** — each probe's response goes back to Claude for a verdict: vulnerable or not, severity, CVSS, evidence, remediation.
5. **Deterministic checks** — missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) are checked without any model call, and only on the target's own origin (third-party CDNs/fonts/analytics are never blamed on the site being scanned).
6. **Reporting** — Markdown + self-contained dark-mode HTML report: overall letter grade (A–F, driven by the single worst severity found, not an average), grouped findings (one entry per issue type across however many endpoints it hits, not 50 duplicate rows), PoCs, remediation steps.
7. **History & before/after** — every scan is saved automatically (local JSON, per target). Pick two past scans of the same target in the dashboard to see exactly what got resolved, what's new, and what's still open since the last run.

### Architecture

```
config.py     Config dataclass — env/API key loading, safety defaults (confirm-scope gate,
              safe-HTTP-method allowlist), output paths
recon.py      Playwright crawler — pages/forms/headers/cookies/scripts/chatbot fingerprinting
ai_brain.py   Claude wrapper — hypothesize() → generate_payloads() → analyze_response(),
              JSON-only responses enforced with retry + truncation recovery, safety-pinned
              system prompt (no destructive/DoS/exfil payloads, no unsafe methods, LLM probes
              stay read-only)
scanner.py    Orchestrates recon → hypotheses → payloads → probes → verdicts; also runs the
              free deterministic header checks
reporter.py   Markdown/HTML report generation — grading, grouping, dark-mode styling
history.py    Saves every scan (JSON) and diffs two scans by issue type for before/after
runner.py     Shared pipeline (recon → scan → report → save) used by both front-ends
cli.py        Typer CLI — flag-driven or a fully interactive prompt flow with an ASCII banner
app.py        Streamlit dashboard — scan-intensity presets, live progress, grade badge,
              one-click export (zip), history/before-after comparison
test_smoke.py Runnable self-check (no network/API calls) — asserted after every change
```

### Project stats

| | |
|---|---|
| Python source | **~1,250 lines** across 10 files |
| Automated self-checks | **9 smoke tests**, run after every change, no mocking of the logic under test |
| Front-ends | 2 (interactive/flag-driven CLI, Streamlit dashboard) — one shared pipeline, no duplicated orchestration logic |
| Dependencies | 7 (`anthropic`, `playwright`, `httpx`, `typer`, `rich`, `pyfiglet`, `streamlit`) — everything else is Python stdlib |
| Real-world validation | Run against multiple live, real websites during development (not just synthetic test pages) — surfaced and fixed genuine crawl/AI-integration bugs, not just unit-test-shaped ones |

### Real bugs found & fixed during development

This wasn't built and shipped untested — every one of these was caught by actually running the tool against real sites, not just reasoning about the code:

- **Crawl false-negatives on real sites**: `page.goto(..., wait_until="networkidle")` never resolves on sites with analytics/polling/chat-widget traffic (a *majority* of real sites) — the crawler reported "0 pages" on a perfectly healthy site. Fixed: `domcontentloaded` is now the real wait condition; `networkidle` is only a short best-effort settle window afterward that can't fail the page load.
- **A crash on failed recon**: if the crawl genuinely found nothing, the tool still asked Claude to hypothesize attacks from an empty summary — Claude's reply got cut off mid-JSON (token budget too small for a full 12-hypothesis list) and the whole scan crashed with an unhandled parse error. Fixed at the root: AI probing is now skipped entirely when recon collected zero pages, and the JSON-parsing layer independently detects a token-limit cutoff and retries with more room + a "be terse" instruction, instead of a correction message that can't fix a truncation.
- **False-positive noise from third-party origins**: header checks were flagging Google Fonts / CDN / analytics-beacon responses as if they were the *scanned site's* misconfiguration — headers on a domain you don't own aren't yours to fix. Fixed: header checks now run only against the target's own origin.
- **Before/after comparisons could silently swap**: two scans saved within the same second sorted by a random tie-breaker instead of save order, which could flip which scan was "before" and which was "after" with no indication anything was wrong. Fixed: scan filenames now carry microsecond-resolution timestamps.
- **UTC timestamps read as "wrong"** to a reader in a different timezone (a report generated at 23:24 UTC looks like it's from "yesterday" to someone 3 hours ahead). Fixed: reports and history now show local wall-clock time with its UTC offset.
- **History mixing unrelated targets**: once more than one site had been scanned, the before/after picker mixed every site's scans into one list with no way to tell them apart. Fixed: the dashboard's history section now has its own target selector, independent of the "start a new scan" field.

### Example scan output

A real run of the CLI against `example.com` (a safe, well-known placeholder domain — chosen here specifically so this README doesn't publish anyone's real infrastructure findings):

```
Overall Grade: B — Only low-severity hygiene issues found, solid baseline posture.
Severity breakdown: Low=4

[Low] Missing Security Header — No Content-Security-Policy header (CVSS 3.1)
[Low] Missing Security Header — No X-Frame-Options header (CVSS 3.1)
[Low] Missing Security Header — No HSTS header (CVSS 3.1)
[Low] Missing Security Header — No X-Content-Type-Options header (CVSS 3.1)
```

No exploitable vulnerabilities — the Claude-driven probes ran and returned no verified findings above these header gaps. This is the expected shape of output for a well-run, low-attack-surface site: a short, honest, non-inflated list, not 50 duplicate rows for the same issue.

### Real-world validation: my own live sites

Beyond the generic example above, the tool has been run for real — repeatedly, over multiple days — against two of my own live production sites (published with the owner's explicit go-ahead):

**[atsify.net](https://atsify.net)** — ATS Resume Builder SaaS (Next.js 16, live production app)
- **Grade: A** — 0 findings (7 pages crawled, depth 3)
- Earlier in development, the very first scan flagged a sitewide missing Content-Security-Policy header (Low, CVSS 3.1) — the only issue found. Fixed directly in the app's own response headers; every re-scan since comes back clean.

**[iamsulaiman.dev](https://iamsulaiman.dev)** — personal site (Cloudflare-fronted)
- **Grade: B** — 2 Low findings (CVSS 3.1 each): missing Content-Security-Policy and Strict-Transport-Security — specifically on a Cloudflare-auto-injected script path (`/cdn-cgi/scripts/.../email-decode.min.js`), not the main page (which already has clean headers).
- Note: this site sits behind Cloudflare bot management, which intermittently resets/times out headless-browser connections — confirmed by testing: identical requests via `curl` always succeed instantly, while Playwright's Chromium fails roughly half the time regardless of what User-Agent it sends. That's a real limitation of *any* headless-browser-based scanner against a bot-protected target, not a Verix bug — retrying usually gets through, which is exactly what the crawler's per-page error handling and warnings are built to make visible rather than hide.

In both cases, Claude's AI-driven probing (hypothesis generation → payload testing → verdict) ran on top of the header checks and found nothing exploitable beyond what's listed above.

### Install & run

```bash
pip install -r requirements.txt
playwright install chromium
```

`.env` (see `.env.example`):
```
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-5   # optional, this is the default
```

```bash
# Interactive terminal
python cli.py

# Flag-driven
python cli.py --target https://your-authorized-target.com --confirm-scope

# Web dashboard
streamlit run app.py
```

Useful flags: `--depth`, `--no-ai-checks` (header checks only, free/instant), `--max-concurrency`, `--rate-limit`, `--allow-unsafe-methods` (off by default), `--output-dir`.

### Safety design

- `--confirm-scope` (CLI) / the authorization checkbox (dashboard) is a hard gate in `Config` — no flag or checkbox, no run.
- The `GET`/`POST`/`HEAD`/`OPTIONS` method allowlist is enforced independently of anything Claude suggests — a bad model output can never fire a live `DELETE`.
- Every Claude call is pinned by a system prompt banning destructive/DoS/data-exfiltration payloads; LLM-widget tests only probe and read behavior (prompt injection, system-prompt leakage) — they never instruct a live system to take a real destructive action.

---

## العربية

### وش تسوي الأداة

1. **الاستكشاف (Recon)** — تزحف على الموقع المستهدف بعمق قابل للتحكم عبر Playwright، وتجمع الصفحات، الفورمز والمعاملات، الكوكيز، هيدرز الاستجابة، السكربتات الخارجية، وأي مؤشرات على شات بوت/AI widget مدمج.
2. **فرضيات الهجوم بالذكاء الاصطناعي** — ملخص الاستكشاف يروح لـ Claude، اللي يقترح حتى 12 فرضية هجوم تغطي OWASP Top 10، مشاكل منطق الأعمال (IDOR، race conditions، تجاوز تدفق العمل)، ولو فيه شات بوت — OWASP Top 10 الخاصة بتطبيقات الـ LLM (حقن الأوامر، تسريب System Prompt، Jailbreak، SSRF عبر استدعاء الأدوات، الإفصاح الزائد).
3. **فحص آمن** — Claude يولّد payloads غير مدمّرة لكل فرضية (تعتمد على الانعكاس/التوقيت/علامات غير ضارة، أبدًا تعديل بيانات)، تُرسل عبر `httpx` بتحكم بالتوازي ومعدل الطلبات، ومحصورة بـ `GET`/`POST`/`HEAD`/`OPTIONS` إلا لو فعّلت الطرق الخطرة صراحة.
4. **التحليل** — كل رد يرجع لـ Claude يحدد: فيه ثغرة فعلية أو لا، الخطورة، CVSS، الدليل، طريقة الإصلاح.
5. **فحوصات ثابتة بدون AI** — هيدرز الأمان الناقصة (CSP، X-Frame-Options، HSTS، X-Content-Type-Options) تُفحص بدون أي استدعاء لنموذج، وبس على نطاق الموقع المستهدف نفسه (مواقع CDN/الخطوط/التحليلات الخارجية ما تُحسب كمشكلة بموقعك).
6. **التقارير** — Markdown + تقرير HTML متكامل (Dark mode): درجة إجمالية (A-F) مبنية على أسوأ خطورة موجودة (مو المعدل)، والمشاكل مجمّعة (مشكلة وحدة لكل نوع بدل ما تتكرر لكل رابط لحاله).
7. **السجل والمقارنة قبل/بعد** — كل فحص ينحفظ تلقائيًا. تختار فحصين سابقين لنفس الموقع من الداشبورد وتشوف بالضبط وش انصلح، وش جديد، ووش لسا موجود.

### إحصائيات المشروع

| | |
|---|---|
| كود Python | **~1,250 سطر** موزعة على 10 ملفات |
| اختبارات آلية | **9 اختبارات** تشتغل بعد كل تعديل |
| واجهات المستخدم | 2 (CLI تفاعلي/بأوامر، وداشبورد Streamlit) — نفس المحرك بالضبط، بدون تكرار منطق |
| المكتبات المستخدمة | 7 فقط، الباقي كله من مكتبة بايثون القياسية |
| اختبار حقيقي | شُغّلت الأداة فعليًا ضد مواقع حقيقية أثناء التطوير (مو بس بيانات تجريبية) — وطلعت أخطاء حقيقية انصلحت، مو بس أخطاء نظرية |

### أخطاء حقيقية لقيتها وصلحتها أثناء التطوير

الأداة ما بُنيت وطُلعت بدون اختبار — كل وحدة من هذي اكتُشفت بتشغيل الأداة فعليًا على مواقع حقيقية:

- **فشل الزحف على مواقع سليمة**: انتظار `networkidle` ما يخلص أبدًا على مواقع فيها تحليلات/شات بوت (أغلب المواقع الحقيقية) — كانت الأداة تقول "0 صفحات" على موقع شغّال تمام. الحل: صار الانتظار الأساسي على `domcontentloaded`، و`networkidle` بعده محاولة قصيرة ما تفشّل تحميل الصفحة لو ما نجحت.
- **كراش عند فشل الاستكشاف**: لو الزحف ما لقى شي فعلاً، كانت الأداة لسا ترسل لـ Claude تسويه يخترع فرضيات من لا شي — رده ينقطع نص الـ JSON، والفحص كامل يكراش. الحل من الجذر: تخطي استدعاء الذكاء الاصطناعي كليًا لو الاستكشاف ما جاب ولا صفحة، مع تحسين إضافي يكتشف الانقطاع بسبب حد الكلمات ويعيد المحاولة بمساحة أكبر.
- **إزعاج كاذب من نطاقات خارجية**: كانت تحط findings على خطوط قوقل أو CDN كأنها مشكلة الموقع المستهدف — أنت ما تتحكم بهيدرز نطاق مو نطاقك. الحل: الفحص الحين بس على نطاق الهدف نفسه.
- **مقارنة قبل/بعد ممكن تنعكس بصمت**: فحصين بنفس الثانية كانوا يترتبون عشوائي بدل ترتيب الحفظ الفعلي. الحل: دقة الوقت بالميكروثانية.
- **توقيت UTC كان يبين "غلط"** لقارئ بمنطقة زمنية ثانية. الحل: التقارير والسجل الحين بالتوقيت المحلي.
- **السجل كان يخلط بين مواقع مختلفة**: صار فيه قائمة اختيار مستقلة بقسم السجل تحدد الموقع أول قبل المقارنة.

### مثال ناتج فحص حقيقي

فحص فعلي ضد `example.com` (نطاق آمن ومعروف عالميًا — اخترته بالذات عشان هذا الملف ما ينشر بيانات موقع حقيقي لأي أحد):

```
الدرجة الإجمالية: B — مشاكل نظافة بسيطة بس، وضع أساسي جيد.
تصنيف الخطورة: منخفض=4

[منخفض] هيدر أمان ناقص — لا يوجد Content-Security-Policy (CVSS 3.1)
[منخفض] هيدر أمان ناقص — لا يوجد X-Frame-Options (CVSS 3.1)
[منخفض] هيدر أمان ناقص — لا يوجد HSTS (CVSS 3.1)
[منخفض] هيدر أمان ناقص — لا يوجد X-Content-Type-Options (CVSS 3.1)
```

ولا ثغرة قابلة للاستغلال — فحوصات Claude اشتغلت وما لقت شي فوق هالهيدرز الناقصة. هذا الشكل المتوقع لموقع سطح هجومه صغير ومُدار كويس: قائمة قصيرة وصادقة، مو 50 سطر مكرر لنفس المشكلة.

### فحص حقيقي على مواقعي الشخصية

بعد المثال العام فوق، شغّلت الأداة فعليًا وبشكل متكرر — على مدار أكثر من يوم — على موقعين حقيقيين لي بالإنتاج (منشورة بموافقة صريحة من صاحب المواقع):

**[atsify.net](https://atsify.net)** — منصة ATS Resume Builder (Next.js 16، تطبيق حقيقي شغّال)
- **الدرجة: A** — 0 findings (7 صفحات، عمق 3)
- أول فحص بمرحلة التطوير كشف Content-Security-Policy ناقص على كل الموقع (منخفض، CVSS 3.1) — المشكلة الوحيدة اللي طلعت. صلحتها مباشرة بهيدرز التطبيق، وكل فحص بعدها يطلع نظيف.

**[iamsulaiman.dev](https://iamsulaiman.dev)** — موقعي الشخصي (خلف Cloudflare)
- **الدرجة: B** — مشكلتين منخفضتين (CVSS 3.1 لكل وحدة): CSP و HSTS ناقصين — تحديدًا على مسار سكربت يحقنه Cloudflare نفسه (`/cdn-cgi/scripts/.../email-decode.min.js`)، مو الصفحة الرئيسية (اللي هيدرزها نظيفة أصلاً).
- ملاحظة: هذا الموقع خلف حماية Cloudflare ضد البوتات، اللي أحيانًا توقف اتصال المتصفح الآلي — تأكدت بالاختبار: نفس الطلب عبر `curl` ينجح فورًا كل مرة، لكن Chromium الآلي (Playwright) يفشل تقريبًا نص المرات بغض النظر عن الـ User-Agent المُرسل. هذا قيد حقيقي بأي أداة فحص تعتمد على متصفح آلي ضد هدف محمي ببوت-بروتكشن، مو خلل بـ Verix — إعادة المحاولة غالبًا تنجح، وهذا بالضبط اللي معالجة الأخطاء وتحذيرات الزحف مبنية توضحه بدل ما تخفيه.

بالحالتين، فحوصات Claude الذكية (توليد فرضيات → اختبار payloads → حكم) اشتغلت فوق فحوصات الهيدرز وما لقت شي قابل للاستغلال غير المذكور فوق.

### التثبيت والتشغيل

```bash
pip install -r requirements.txt
playwright install chromium
```

ملف `.env` (شوف `.env.example`):
```
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-5   # اختياري، هذا الافتراضي
```

```bash
# طرفية تفاعلية
python cli.py

# بأوامر مباشرة
python cli.py --target https://your-authorized-target.com --confirm-scope

# داشبورد ويب
streamlit run app.py
```

### تصميم السلامة

- `--confirm-scope` (بالطرفية) / صندوق تأكيد الصلاحية (بالداشبورد) بوابة صارمة داخل `Config` — بدون تفعيلها الفحص ما يشتغل إطلاقًا.
- قائمة الطرق المسموحة (`GET`/`POST`/`HEAD`/`OPTIONS`) مفروضة بالكود بشكل مستقل عن أي اقتراح من Claude — حتى لو النموذج غلط، ما يقدر يرسل `DELETE` حقيقي.
- كل استدعاء لـ Claude مقيّد بقواعد صريحة تمنع أي payload مدمّر أو DoS أو تسريب بيانات؛ فحوصات الـ LLM widgets تراقب وتقرأ السلوك بس (حقن أوامر، تسريب System Prompt) — أبدًا ما توجّه نظام حي يسوي فعل ضار حقيقي.
