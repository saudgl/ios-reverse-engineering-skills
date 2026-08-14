# Cloud Secrets & Credential Patterns

Comprehensive patterns for detecting cloud provider credentials, API keys, and service configurations leaked in iOS application binaries. These patterns are used by the LLM analysis phase to classify, validate, and assess the risk of exposed secrets.

## Firebase

Firebase is extremely common in iOS apps. Look for configuration embedded via `GoogleService-Info.plist`.

### Patterns

```bash
# Firebase config (GoogleService-Info.plist values)
grep -rni 'GOOGLE_APP_ID\|GCM_SENDER_ID\|FIREBASE_URL\|DATABASE_URL.*firebaseio\.com\|STORAGE_BUCKET\|PROJECT_ID\|BUNDLE_ID\|API_KEY\|CLIENT_ID.*apps\.googleusercontent\.com' output/

# Firebase SDK classes
grep -rn 'FIRApp\|FirebaseApp\|FIRAuth\|FIRDatabase\|FIRFirestore\|FIRStorage\|FIRMessaging\|FIRAnalytics\|FIRCrashlytics\|FIRRemoteConfig' output/

# Firebase URLs
grep -rn 'firebaseio\.com\|firebaseapp\.com\|firebase\.google\.com\|fcm\.googleapis\.com\|firebasestorage\.googleapis\.com' output/

# Firebase Dynamic Links
grep -rn 'page\.link\|app\.goo\.gl\|FIRDynamicLink' output/

# Realtime Database / Firestore rules (sometimes hardcoded)
grep -rni 'databaseURL\|firestoreSettings\|persistenceEnabled\|cacheSizeBytes' output/
```

### What to look for

| Field | Risk | Notes |
|-------|------|-------|
| `API_KEY` | Medium | Restricted by API key restrictions, but can be abused if unrestricted |
| `DATABASE_URL` | High | Direct database access if security rules are misconfigured |
| `STORAGE_BUCKET` | High | May allow unauthenticated file read/write |
| `GCM_SENDER_ID` | Low | Can be used to send push notifications if abused |
| `PROJECT_ID` | Low-Medium | Identifies the project, useful for enumeration |
| `CLIENT_ID` | Medium | OAuth client ID, can be used for authentication flows |

### LLM Analysis Prompts

When analyzing Firebase credentials, the LLM should:
1. Check if `API_KEY` has domain/app restrictions (cannot be determined from binary alone — flag for manual testing)
2. Verify if `DATABASE_URL` is accessible without authentication (`curl <url>/.json`)
3. Check if `STORAGE_BUCKET` allows public listing
4. Identify if Firebase Auth is configured (presence of `FIRAuth` classes)
5. Flag any hardcoded Firebase Admin SDK credentials (service account keys)

## Google Cloud Platform (GCP)

### Patterns

```bash
# GCP API keys
grep -rni 'AIza[0-9A-Za-z_-]\{35\}' output/

# GCP Service Account
grep -rni 'service_account\|client_email.*gserviceaccount\.com\|private_key_id\|"type":\s*"service_account"' output/

# GCP OAuth Client IDs
grep -rn '[0-9]\{12\}-[a-z0-9]\{32\}\.apps\.googleusercontent\.com' output/

# GCP project references
grep -rni 'googleapis\.com\|storage\.cloud\.google\.com\|compute\.googleapis\.com\|bigquery\.googleapis\.com' output/

# Google Maps
grep -rni 'maps\.googleapis\.com\|places\.googleapis\.com\|GMSServices\|GMSMapView\|GoogleMaps\|GooglePlaces' output/

# Google Sign-In
grep -rn 'GIDSignIn\|GIDConfiguration\|GIDGoogleUser\|clientID.*googleusercontent' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| API Key | `AIza[0-9A-Za-z_-]{35}` | Medium-High (depends on restrictions) |
| OAuth Client ID | `{12-digits}-{32-chars}.apps.googleusercontent.com` | Medium |
| Service Account JSON | `"type": "service_account"` with `private_key` | **Critical** |
| Project Number | `[0-9]{12}` (in context of GCP) | Low |

## Amazon Web Services (AWS)

### Patterns

```bash
# AWS Access Key ID
grep -rn 'AKIA[0-9A-Z]\{16\}' output/

# AWS Secret Access Key (40 char base64)
grep -rni 'aws[_-]?secret[_-]?access[_-]?key\|aws[_-]?secret\|secret[_-]?key.*[A-Za-z0-9/+=]\{40\}' output/

# AWS session/temp credentials
grep -rni 'aws[_-]?session[_-]?token\|x-amz-security-token' output/

# AWS SDK and service references
grep -rn 'AWSMobileClient\|AWSCognitoIdentityProvider\|AWSCognito\|AWSS3\|AWSDynamoDB\|AWSLambda\|AWSAppSync\|AWSIoT' output/

# AWS Cognito
grep -rni 'cognito[_-]?identity[_-]?pool\|user[_-]?pool[_-]?id\|CognitoIdentityUserPoolId\|CognitoIdentityPoolId\|us-east-1:[a-f0-9-]\{36\}' output/

# AWS endpoints/regions
grep -rni '\.amazonaws\.com\|\.aws\.amazon\.com\|s3\..*\.amazonaws\|execute-api\..*\.amazonaws\|lambda\..*\.amazonaws' output/

# AWS Amplify
grep -rni 'amplifyconfiguration\|awsconfiguration\|aws-exports' output/

# S3 bucket names
grep -rn 's3://[a-z0-9][a-z0-9.-]*\|[a-z0-9][a-z0-9.-]*\.s3\.amazonaws\.com\|s3\.[a-z0-9-]*\.amazonaws\.com/[a-z0-9]' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| Access Key ID | `AKIA[0-9A-Z]{16}` | **Critical** |
| Secret Access Key | 40-char base64 string | **Critical** |
| Cognito Identity Pool ID | `{region}:{uuid}` | Medium |
| Cognito User Pool ID | `{region}_{alphanumeric}` | Medium |
| S3 Bucket Name | URL or `s3://` reference | Medium (enumeration) |

## Microsoft Azure

### Patterns

```bash
# Azure connection strings
grep -rni 'DefaultEndpointsProtocol=https;AccountName=\|SharedAccessSignature=\|AccountKey=' output/

# Azure AD / MSAL
grep -rn 'MSALPublicClientApplication\|MSALConfiguration\|MSALAuthority\|MSALAccount\|ADALContext\|ADAL' output/

# Azure tenant/client IDs
grep -rni 'tenant[_-]?id\|client[_-]?id.*[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}' output/

# Azure endpoints
grep -rni '\.azure\.com\|\.azurewebsites\.net\|\.blob\.core\.windows\.net\|\.table\.core\.windows\.net\|\.queue\.core\.windows\.net\|\.vault\.azure\.net\|\.database\.windows\.net\|\.servicebus\.windows\.net' output/

# Azure Notification Hubs
grep -rni 'SBNotificationHub\|notificationhubname\|DefaultFullSharedAccessSignature\|\.servicebus\.windows\.net' output/

# Azure App Configuration
grep -rni 'Endpoint=https://.*\.azconfig\.io' output/

# Azure Key Vault
grep -rni 'keyvault\|\.vault\.azure\.net' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| Storage Account Key | Base64, 88 chars | **Critical** |
| SAS Token | `sv=...&sig=...` | High |
| Connection String | `DefaultEndpointsProtocol=...` | **Critical** |
| Client Secret | GUID-like string in auth context | **Critical** |
| Tenant ID | UUID format | Low |

## Other Common Services

### Stripe

```bash
grep -rni 'sk_live_[0-9a-zA-Z]\{24,\}\|pk_live_[0-9a-zA-Z]\{24,\}\|sk_test_[0-9a-zA-Z]\{24,\}\|pk_test_[0-9a-zA-Z]\{24,\}\|rk_live_\|rk_test_' output/
```

| Key | Pattern | Risk |
|-----|---------|------|
| Secret Key | `sk_live_*` | **Critical** (full API access) |
| Publishable Key | `pk_live_*` | Low (intended for client) |
| Test Secret | `sk_test_*` | Medium |
| Restricted Key | `rk_live_*` | High |

### Twilio

```bash
grep -rni 'AC[0-9a-f]\{32\}\|SK[0-9a-f]\{32\}\|twilio\|\.twilio\.com' output/
```

### SendGrid

```bash
grep -rni 'SG\.[a-zA-Z0-9_-]\{22\}\.[a-zA-Z0-9_-]\{43\}\|sendgrid\|\.sendgrid\.com' output/
```

### Slack

```bash
grep -rni 'xoxb-[0-9]\{11\}-[0-9]\{11\}-[a-zA-Z0-9]\{24\}\|xoxp-\|xoxa-\|hooks\.slack\.com/services/' output/
```

### OneSignal

```bash
grep -rni 'onesignal\|OneSignal\|setAppId\|[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}.*onesignal' output/
```

### Mixpanel / Amplitude / Segment

```bash
grep -rni 'mixpanel\|Mixpanel\.initialize\|amplitude\|Amplitude\.instance\|segment\|Analytics\.setup\|writeKey' output/
```

### Sentry

```bash
grep -rni 'sentry\.io\|SentrySDK\|dsn.*sentry\|https://[a-f0-9]\{32\}@[a-z0-9]*\.ingest\.sentry\.io' output/
```

### Algolia

```bash
grep -rni 'algolia\|ALGOLIA_API_KEY\|applicationID.*algolia\|algolianet\.com' output/
```

### Pusher / PubNub

```bash
grep -rni 'pusher\|PusherSwift\|Pusher(\|pubnub\|PubNub\|subscribeKey\|publishKey' output/
```

## Developer-platform & SaaS keys (new)

These provider keys are validated by `deep-secret-scan.sh` (format + entropy + allowlist)
and reported with an FP-likelihood tag.

| Provider | Pattern | Risk | Client-safe? |
|----------|---------|------|--------------|
| **GitHub** | `(ghp\|gho\|ghs\|ghr\|ghu)_[A-Za-z0-9]{36}` | Critical (repo/org access) | No |
| **GitLab** | `glpat-[A-Za-z0-9_-]{20}` | Critical | No |
| **Mailgun** | `key-[a-f0-9]{32}` | High (send mail as domain) | No |
| **Mailchimp** | `[a-f0-9]{32}-us[0-9]{1,2}` | High (audience access) | No |
| **Telegram** (bot) | `[0-9]{8,10}:[A-Za-z0-9_-]{34,40}` | High | No |
| **Square** | `sq0[a-z][a-z0-9_-]{20,}` | High | No |
| **Cloudflare** | API key: 37 hex; token: `cf_`-prefixed | High | No |
| **Mapbox** | public `pk.*\.`, secret `sk.*\.` | Public=Low, Secret=Critical | Public yes |
| **Infura** | `https://<key>.infura.io/v3/[A-Za-z0-9]{32}` | High (RPC access) | Mostly |
| **Alchemy** | `https://<network>.g.alchemy.com/<api>/<key>` | High | Mostly |
| **Ethereum** private key | `(0x)?[0-9a-fA-F]{64}` | Critical (drain wallet) | No |
| **Private key blocks** | `BEGIN (RSA\|OPENSSH\|EC\|PGP )?PRIVATE KEY` | Critical | No |

```bash
# Developer-platform
grep -rnE '(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|key-[a-f0-9]{32}|[a-f0-9]{32}-us[0-9]{1,2}|[0-9]{8,10}:[A-Za-z0-9_-]{34,40}|sq0[a-z][a-z0-9_-]{20,}' output/

# Web3
grep -rniE 'https://[a-z0-9]*\.infura\.io/v3/[A-Za-z0-9]{32}|https://[a-z-]*\.g\.alchemy\.com/[a-z0-9]+/[A-Za-z0-9_-]{30,}|BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY|(0x)?[0-9a-fA-F]{64}' output/
```

> **Caution — Ethereum private keys:** the `[0-9a-fA-F]{64}` pattern is broad and matches
> transaction hashes, file hashes, and random hex. The scan validates entropy and flags
> FP-likelihood HIGH for low-entropy hex. Treat any 64-hex hit as a *candidate* and confirm
> against context (e.g. named `privateKey`, `mnemonic`-derived) before escalating.

## False-positive minimization

The `deep-secret-scan.sh` scan applies these filters (disable with `--raw`). Each finding
keeps an **FP-likelihood** tag (Low/Medium/High) so the LLM can triage.

### 1. Placeholder / example allowlist

Values matching these are downgraded to INFO (unless `--raw`):

| Placeholder | Example |
|------------|---------|
| `AKIAIOSFODNN7EXAMPLE` | AWS documented example access key |
| `wJalrXUtnFEMI...EXAMPLEKEY` | AWS documented example secret |
| `example.com`, `your_key`, `YOUR_API_KEY`, `<token>` | docs strings |
| `^x{3,}$`, `^abc123$`, `^test$`, `placeholder`, `dummy`, `redacted` | obvious dummies |
| `firebase_example`, `sentry_example` | provider example configs |

> Note: bare numeric runs like `123456789` are **not** allowlisted — real secrets legitimately
> contain digit runs, so substring-matching them would drop real keys.

### 2. Format / charset validation

| Provider | Validated format |
|----------|------------------|
| AWS Access Key | `(AKIA\|ASIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASCA)[0-9A-Z]{16}` |
| GCP API Key | `AIza[0-9A-Za-z_-]{35}` |
| Stripe | `(sk\|pk\|rk)_(live\|test)_[0-9a-zA-Z]{24,}` |
| Twilio | `AC[0-9a-f]{32}` / `SK[0-9a-f]{32}` |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` |
| Slack | `xox[abprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}` |
| GitHub | `(ghp\|gho\|ghs\|ghr\|ghu)_[A-Za-z0-9]{36}` |
| GitLab | `glpat-[A-Za-z0-9_-]{20}` |
| JWT | 3 base64url segments; header decodes to JSON with `alg`/`typ` |

A value that *looks* like a key (matches a prefix) but fails the strict format gets
FP-likelihood raised (e.g. `AKIA1234567890ABCDEF` valid; `AKIA1234` → format mismatch → HIGH FP).

### 3. Shannon entropy

Bits/char across the candidate value. Strings ≥20 chars below ~3.0 bits/char are usually
binary artifacts/hashes, not secrets → FP-likelihood raised. Real keys (40+ chars of mixed
case + digits) are typically 4.0–6.0 bits/char.

### 4. Client-safe vs server-side

Some keys are **designed** to ship in client binaries — they don't grant server-side access
on their own. The scan flags these `client-safe=yes` and downgrades critical→medium:

| Client-safe (low/medium impact) | Server-side (critical) |
|----------------------------------|------------------------|
| Firebase API Key (`AIza...`, restricted) | Stripe `sk_live_*` |
| Stripe publishable `pk_live_*` | AWS secret access key |
| GCP OAuth client ID | Slack `xoxb-*` / `xoxp-*` |
| Mapbox public key | GitHub `ghp_*` / GitLab `glpat-*` |
| Infura/Alchemy (rate-limited RPC) | Ethereum private key |

> A client-safe key still has impact (quota abuse, enumeration, unrestricted API key abuse) —
> "client-safe" means *intended for client use*, not "harmless". Apply API key restrictions
> (referrer/Bundle ID) and least-privilege scopes.

### 5. Dedup by value

Candidates are extracted with `grep -oE` and deduplicated **by value** (a secret in 3 files
counts once), not by grep line. The previous behavior triple-counted any secret present in
`strings-raw.txt`, `strings-urls-and-keys.txt`, and `symbols.txt`.

## Regex Summary for Binary Scanning

These high-confidence regexes can be run directly against `strings-raw.txt`:

```bash
# All high-confidence patterns in one scan
grep -E \
  'AIza[0-9A-Za-z_-]{35}|'\
  '(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}|'\
  'sk_live_[0-9a-zA-Z]{24,}|'\
  'sk_test_[0-9a-zA-Z]{24,}|'\
  'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|'\
  'xox[abprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}|'\
  'AC[0-9a-f]{32}|'\
  'DefaultEndpointsProtocol=https|'\
  'AccountKey=[A-Za-z0-9+/=]{86,}|'\
  '(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}|'\
  'glpat-[A-Za-z0-9_-]{20}|'\
  'key-[a-f0-9]{32}|'\
  '[0-9]{8,10}:[A-Za-z0-9_-]{34,40}|'\
  'BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY|'\
  'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
  output/strings-raw.txt
```

> These are raw high-confidence formats. The `deep-secret-scan.sh` script applies the
> allowlist + format + entropy + dedup filters on top of them and tags each with
> FP-likelihood; prefer the script over a raw `grep` for reporting.

## JWT Token Detection

```bash
# JWT tokens (base64.base64.base64)
grep -rn 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' output/
```

JWTs found in the binary may contain:
- Hardcoded test/dev tokens
- Default/example tokens with real claims
- Token structure revealing API expectations

## LLM Analysis Guidelines

When the LLM analyzes extracted secrets, it should:

### Classification
1. **Identify the service** — match the key format to known providers
2. **Assess the risk level** — Critical / High / Medium / Low / Info
3. **Determine if client-safe** — some keys (e.g., `pk_live_*`, Firebase `API_KEY`) are intended for client use
4. **Check for test vs production** — test keys (`sk_test_*`, staging URLs) are lower risk

### Validation suggestions
For each found credential, suggest validation steps:
- Firebase API Key → test with Firebase REST API
- AWS Access Key → `aws sts get-caller-identity`
- GCP API Key → test with Maps/Geocoding API
- Azure Connection String → test blob storage access
- Stripe Secret Key → `curl https://api.stripe.com/v1/charges -u sk_live_xxx:`

### Report format
```markdown
### 🔑 [SERVICE] — [RISK LEVEL]

- **Type**: [credential type]
- **Value**: `[redacted first/last 4 chars]`
- **Location**: [file:line]
- **Client-safe**: Yes/No
- **Impact**: [what an attacker could do]
- **Recommendation**: [specific remediation]
```
