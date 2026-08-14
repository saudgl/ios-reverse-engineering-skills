<div align="center">

**[English](README.md)** · **[العربية](README.ar.md)**

</div>

<div dir="rtl">

# مجموعة أدوات الهندسة العكسية لتطبيقات iOS

مجموعة أدوات ومهارة متكاملة لاستخراج وتحليل وتدقيق تطبيقات iOS — ملفات IPA، وحِزم `.app`، وثنائيات Mach-O، والمكتبات الديناميكية، وأطر العمل (Frameworks). تقوم بأتمتة استخراج تعريفات الأصناف (class dump)، واستخراج نقاط نهاية الـ API، وتتبّع مسار الاستدعاءات، وفحص الأسرار وبيانات الاعتماد، والهندسة العكسية للثنائيات بمساعدة نماذج اللغة (Ghidra headless)، وبصمة حزم التطوير (SDK) مع مطابقة الثغرات المعروفة (CVE)، واكتشاف آليات مقاومة العبث، والتدقيق الأمني الساكن. تعمل مع تطبيقات Swift و Objective-C على أنظمة macOS و Linux.

## المميزات

- **استخراج IPA / .app** — يفكّ ضغط الأرشيفات، ويحدّد ملف Mach-O الرئيسي، وينفّذ استخراج الأصناف، ويستخرج `Info.plist` والصلاحيات (entitlements) وأطر العمل المضمّنة وبيانات الخصوصية ورايات ترويسة Mach-O ‏(PIE / hardened runtime).
- **استخراج نقاط نهاية الـ API** — يكتشف واجهات HTTP عبر URLSession و Alamofire و AFNetworking و Moya و GraphQL و WebSocket، مع إزالة التكرار وتوليد تقارير Markdown.
- **تتبّع مسار الاستدعاءات** — يوجّه التحليل من `AppDelegate` ونقاط الدخول وصولًا إلى طبقة الشبكة مرورًا بـ ViewControllers و ViewModels والمستودعات وعملاء الـ API.
- **فحص عميق للأسرار وبيانات الاعتماد** — يتحقق من بيانات اعتماد الخدمات السحابية (Firebase و AWS و GCP و Azure و Stripe و GitHub و GitLab و web3 وغيرها) مع تصفية النتائج الخاطئة، وفحوص العشوائية (entropy)، وقوائم سماح للقيم النائبة، ووسم المفاتيح الآمنة للعميل (`client-safe`).
- **هندسة عكسية للثنائيات بمساعدة نماذج اللغة** — تحليل عبر radare2/rizin و Ghidra headless يشمل فك الترجمة (decompilation) والمراجع المتقاطعة ومخططات الاستدعاء واستخدام التشفير وتتبّع الأسرار ومراجع النصوص.
- **بصمة حزم التطوير (SDK)** — يتعرّف على حزم الطرف الثالث، ويكتشف إصداراتها، ويطابقها مع الثغرات المعروفة (CVE).
- **اكتشاف مقاومة العبث** — التشويش (obfuscation)، ومقاومة التنقيح (anti-debugging)، ومنع حقن المكتبات، وفحوص السلامة، واكتشاف كسر الحماية (jailbreak)، وحماية FairPlay DRM، مع درجة حماية من 0 إلى 20.
- **تدقيق أمني ساكن** — التخزين، و WebView وجسور JavaScript، واختطاف الروابط العميقة، والتشفير والتوليد العشوائي الضعيف، وفك التسلسل غير الآمن، و XXE / Zip Slip، وسوء إعداد ATS وتثبيت الشهادات، والخصوصية، وفحوص تحصين Mach-O.
- **متعدد المنصات** — يعمل بكامل وظائفه على macOS و Linux (يعتمد على `ipsw` و `plistutil` و Python حين لا تتوفر أدوات Apple التطويرية).

## المتطلبات المسبقة

| الأداة | الغرض | إلزامية |
|------|---------|----------|
| [ipsw](https://github.com/blacktop/ipsw) | استخراج الأصناف، تحليل Mach-O، الصلاحيات، الترقيق (thinning) | نعم |
| أدوات سطر أوامر Xcode (`otool`, `strings`, `plutil`, `codesign`, `lipo`) | التحليل الأصلي على macOS | على macOS فقط |
| [radare2](https://github.com/radareorg/radare2) / [rizin](https://github.com/rizinorg/rizin) | تحليل عميق للثنائيات | مُستحسنة |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | فك ترجمة بدون واجهة (سكربتات Java مرفقة) | اختيارية |
| [jtool2](https://github.com/blacktop/ipsw) / frida | تحليل ديناميكي أعمق | اختيارية |

## التثبيت

استنسخ المستودع ثم شغّل مدقّق الاعتماديات:

</div>

```bash
git clone https://github.com/saudgl/ios-reverse-engineering-skills.git
cd ios-reverse-engineering-skills

bash scripts/check-deps.sh
```

<div dir="rtl">

في حال نقص أي من الاعتماديات الإلزامية، يمكن تثبيتها تلقائيًا:

</div>

```bash
bash scripts/install-dep.sh ipsw
# أو يدويًا، مثلًا عبر Homebrew:
# brew install blacktop/tap/ipsw
```

<div dir="rtl">

## البدء السريع

</div>

```bash
# ١. استخراج وتحليل ملف IPA
bash scripts/extract-ipa.sh App.ipa -o App-analysis

# ٢. العثور على نقاط نهاية الـ API وتوليد تقرير
bash scripts/find-api-calls.sh App-analysis/ --context 3 --dedup --report api-report.md

# ٣. فحص عميق لبيانات الاعتماد السحابية
bash scripts/deep-secret-scan.sh App-analysis/ --report secrets-report.md

# ٤. بصمة حزم التطوير المضمّنة مع فحص الثغرات
bash scripts/detect-sdks.sh App-analysis/ --check-cves --report sdks-report.md

# ٥. اكتشاف آليات مقاومة العبث
bash scripts/detect-protections.sh App-analysis/ --report protections-report.md

# ٦. تدقيق أصناف الثغرات في iOS
bash scripts/audit-vulnerabilities.sh App-analysis/ --all --report vuln-report.md

# ٧. هندسة عكسية عميقة عبر Ghidra headless (اختياري)
bash scripts/reversing-analyze.sh --tool ghidra App-analysis/Payload/App.app/App -o App-analysis/reversing
```

<div dir="rtl">

## نظرة عامة على السكربتات

| السكربت | الوصف |
|--------|-------------|
| `check-deps.sh` | يتحقق من الأدوات الإلزامية والاختيارية، ويطبع تعليمات تثبيت قابلة للقراءة آليًا |
| `install-dep.sh` | يثبّت اعتمادية عبر Homebrew أو إصدارات GitHub |
| `extract-ipa.sh` | يستخرج ملفات IPA / `.app` / Mach-O / `.dylib` / `.framework` إلى مجلد تحليل |
| `find-api-calls.sh` | يبحث عن أنماط URLSession و Alamofire و AFNetworking و GraphQL و WebSocket والمصادقة والأمان |
| `deep-secret-scan.sh` | يتحقق من بيانات اعتماد مزوّدي السحابة مع تصفية النتائج الخاطئة وتصنيف الخطورة |
| `reversing-analyze.sh` | ينفّذ تحليل radare2/rizin أو Ghidra headless (الأسرار، الشبكة، التشفير، المصادقة، العشوائية، مخططات الاستدعاء) |
| `detect-sdks.sh` | يبصم حزم الطرف الثالث مع اكتشاف الإصدارات ومطابقة الثغرات |
| `detect-protections.sh` | يكتشف التشويش ومقاومة التنقيح ومنع الحقن وفحوص السلامة واكتشاف كسر الحماية |
| `audit-vulnerabilities.sh` | تدقيق ساكن لأصناف ثغرات iOS مع الخطورة ودرجة الثقة واحتمالية النتائج الخاطئة |
| `scripts/ghidra/*.java` | سكربتات Ghidra headless لفك الترجمة والأسرار واستدعاءات الـ API واستخدام التشفير ومراجع النصوص |

## سير العمل

1. **التحقق من الاعتماديات** — `check-deps.sh`، وتثبيت ما ينقص.
2. **الاستخراج واستخراج الأصناف** — ينتج `extract-ipa.sh` تعريفات الأصناف وملفات plist والصلاحيات وأطر العمل وبيانات Mach-O الوصفية.
3. **تحليل البنية** — مراجعة `Info.plist` والصلاحيات ومخرجات class-dump وأطر العمل المضمّنة لرسم معمارية التطبيق ‏(MVC / MVVM / VIPER / Coordinator).
4. **تتبّع مسارات الاستدعاء** — من نقاط الدخول ← ViewModels ← المستودعات ← عملاء الـ API.
5. **استخراج وتوثيق الـ APIs** — عبر `find-api-calls.sh` مع توثيق كل نقطة نهاية: الطريقة والمسار والمعاملات والترويسات وسلسلة الاستدعاء.
6. **التحليل الأمني** — استثناءات ATS، وتثبيت الشهادات، والأسرار المكشوفة، واكتشاف كسر الحماية، والتشفير الضعيف، وسوء استخدام الـ Keychain، وبقايا التنقيح.
7. **تحليل عميق للأسرار وبيانات الاعتماد** — `deep-secret-scan.sh` مع فرز بمساعدة نماذج اللغة (تصنيف، تقدير نطاق الضرر، تحقق، معالجة).
8. **هندسة عكسية عميقة للثنائيات** — radare2/rizin أو Ghidra headless مع مراجعة الدوال المفكوكة والمراجع المتقاطعة واستخدام التشفير.
9. **بصمة حزم التطوير** — اكتشاف الإصدارات ومطابقة الثغرات، وتقييم سطح الهجوم وتدفّق البيانات.
10. **اكتشاف مقاومة العبث** — التشويش ومقاومة التنقيح ومنع الحقن والسلامة وكسر الحماية، مع حساب درجة الحماية.
11. **التدقيق الأمني الساكن** — `audit-vulnerabilities.sh` عبر التخزين و WebView والروابط العميقة والتشفير وفك التسلسل والتحليل النصي و ATS والخصوصية والتحصين.

## التقارير

تولّد السكربتات تقارير Markdown منظّمة تلقائيًا عبر الخيار `--report`:

- `api-report.md` — نقاط النهاية المكتشفة مع مسارات الاستدعاء
- `secrets-report.md` — بيانات الاعتماد المتحقق منها مع احتمالية النتائج الخاطئة ووسوم `client-safe`
- `sdks-report.md` — جرد حزم التطوير مع الإصدارات ومطابقات الثغرات
- `protections-report.md` — آليات الحماية ودرجة الحماية
- `vuln-report.md` — نتائج الثغرات مع الخطورة ودرجة الثقة والأدلة

## هيكل المشروع

</div>

```
ios-reverse-engineering/
├── SKILL.md                    # تعريف المهارة الكامل وسير العمل
├── scripts/                    # سكربتات التحليل (shell)
│   ├── check-deps.sh
│   ├── install-dep.sh
│   ├── extract-ipa.sh
│   ├── find-api-calls.sh
│   ├── deep-secret-scan.sh
│   ├── reversing-analyze.sh
│   ├── detect-sdks.sh
│   ├── detect-protections.sh
│   ├── audit-vulnerabilities.sh
│   └── ghidra/                 # سكربتات Ghidra headless بلغة Java
└── references/                 # أدلة مرجعية تفصيلية
```

<div dir="rtl">

## التوافق مع المساعدات والنماذج

صُمّم هذا المشروع ليُحمَّل كـ **مهارة (skill)** داخل مساعدات البرمجة المعتمدة على الذكاء الاصطناعي. المهارة نفسها **غير مرتبطة بنموذج بعينه** — فهي مجموعة تعليمات مع سكربتات shell و Ghidra، وبالتالي تعمل تحت أي نموذج لغوي قادر على تنفيذ الأوامر وقراءة الملفات. جرى التحقق منها مع:

| المساعد | النموذج | مجلد المهارات |
|-----------|-------|-----------------|
| **opencode** | **DeepSeek** (أو أي نموذج مُهيّأ) | `~/.config/opencode/skills/` |
| **Claude Code** | **Claude** ‏(Anthropic) | `~/.claude/skills/` |
| أي أداة وكيل أخرى | أي نموذج لغوي | `~/.agents/skills/` أو مسار المهارات الخاص بأداتك |

وجّه مجلد المهارات في مساعدك إلى هذا المستودع (أو أنشئ رابطًا رمزيًا إليه) لتتوفر لك التعليمات المرحلية والسكربتات المساعدة أثناء جلسات تحليل تطبيقات iOS. تُفعّل ترويسة `SKILL.md` ‏(`compatibility: opencode`) التحميل التلقائي في opencode، أما مع Claude Code فضع المجلد داخل `~/.claude/skills/`.

## الأمان والأخلاقيات

هذه المجموعة مخصّصة لـ **التقييمات الأمنية المصرّح بها** — أي تحليل التطبيقات التي تملكها أو التي لديك إذن صريح باختبارها. التزم دائمًا بالقوانين المعمول بها وبشروط استخدام التطبيق المستهدف. استخدمها بمسؤولية.

## المراجع

توجد الأدلة المرجعية التفصيلية داخل مجلد `references/`:

- `setup-guide.md` — تثبيت ipsw و jtool2 و frida والأدوات الاختيارية
- `class-dump-usage.md` — خيارات أمر `ipsw class-dump` وتحليل Mach-O
- `api-extraction-patterns.md` — أنماط البحث الخاصة بكل مكتبة وقالب التوثيق
- `call-flow-analysis.md` — تقنيات تتبّع مسارات الاستدعاء
- `cloud-secrets-patterns.md` — أنماط بيانات الاعتماد السحابية وتقليل النتائج الخاطئة
- `reversing-tools-guide.md` — مرجع radare2 و rizin و Ghidra headless
- `sdk-fingerprinting.md` — قاعدة بصمات حزم التطوير ومرجع الثغرات
- `anti-tampering-patterns.md` — أنماط التشويش ومقاومة التنقيح ومنع الحقن
- `vulnerability-patterns.md` — أصناف ثغرات iOS مع ملاحظات النتائج الخاطئة وطرق المعالجة

## المؤلف والشكر

يُشرف على المشروع **SaudGL** — [https://github.com/saudgl](https://github.com/saudgl)

اشتُقّت هذه المهارة في الأصل من **iOS Reverse Engineering Claude Skill** من إعداد **incogbyte**، ونتقدّم بالشكر للمؤلف الأصلي على عمله:

- **incogbyte/iOS-reverse-engineering-claude-skill** — [https://github.com/incogbyte/iOS-reverse-engineering-claude-skill](https://github.com/incogbyte/iOS-reverse-engineering-claude-skill)

ينقل هذا التفريع (fork) المهارة الأصلية من Claude Code إلى opencode/DeepSeek مع الحفاظ على توافقها الكامل مع Claude Code وأي مساعد آخر مدعوم بنموذج لغوي.

## الرخصة

هذا المشروع مرخّص بموجب **رخصة MIT** — راجع ملف [LICENSE](LICENSE) للتفاصيل.

</div>

```
MIT License

Copyright (c) 2026 SaudGL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
