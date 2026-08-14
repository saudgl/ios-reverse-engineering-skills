#!/usr/bin/env bash
# by SaudGL — https://github.com/saudgl
# deep-secret-scan.sh — Deep scan for cloud credentials, API keys, and secrets in extracted iOS app
#
# FP-minimized: candidates are extracted by VALUE (grep -oE), deduplicated, then validated
# against an allowlist of placeholders, format/charset checks, and Shannon entropy. Each
# finding carries an FP-likelihood (Low/Medium/High) and a client-safe flag. Use --raw to
# disable all filtering (research / brute-force mode) — matches still get FP-likelihood tags.
set -euo pipefail

usage() {
  cat <<EOF
Usage: deep-secret-scan.sh <analysis-dir> [OPTIONS]

Deep scan extracted iOS app output for cloud provider credentials, API keys,
and other secrets. Produces structured output suitable for LLM analysis.

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --firebase        Search only for Firebase/Google credentials
  --aws             Search only for AWS credentials
  --azure           Search only for Azure credentials
  --gcp             Search only for GCP credentials
  --payments        Search only for payment provider keys (Stripe, etc.)
  --messaging       Search only for messaging/push keys (Twilio, OneSignal, etc.)
  --analytics       Search only for analytics keys (Mixpanel, Amplitude, Sentry, etc.)
  --jwt             Search only for JWT tokens
  --devtools        Search only for developer-platform keys (GitHub, GitLab, etc.)
  --web3            Search only for web3 keys (Infura, Alchemy, private keys)
  --all             Search all patterns (default)
  --report FILE     Export results as structured Markdown report
  --json            Output results in JSON format for programmatic use
  --severity LEVEL  Minimum severity to report: critical, high, medium, low, info (default: low)
  --raw             Disable FP filtering (allowlist/entropy/format). Keep all matches,
                    still tagged with FP-likelihood. Use for research/brute-force triage.
  -h, --help        Show this help message

Output:
  Validated secret findings with service, credential type, severity, FP-likelihood,
  client-safe flag, and location. Config indicators (Firebase SDK class refs, etc.)
  are reported as INFO and excluded from critical/high totals.
EOF
  exit 0
}

ANALYSIS_DIR=""
SEARCH_FIREBASE=false
SEARCH_AWS=false
SEARCH_AZURE=false
SEARCH_GCP=false
SEARCH_PAYMENTS=false
SEARCH_MESSAGING=false
SEARCH_ANALYTICS=false
SEARCH_JWT=false
SEARCH_DEVTOOLS=false
SEARCH_WEB3=false
SEARCH_ALL=true
REPORT_FILE=""
JSON_OUTPUT=false
MIN_SEVERITY="low"
RAW_MODE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --firebase)    SEARCH_FIREBASE=true;    SEARCH_ALL=false; shift ;;
    --aws)         SEARCH_AWS=true;         SEARCH_ALL=false; shift ;;
    --azure)       SEARCH_AZURE=true;       SEARCH_ALL=false; shift ;;
    --gcp)         SEARCH_GCP=true;         SEARCH_ALL=false; shift ;;
    --payments)    SEARCH_PAYMENTS=true;    SEARCH_ALL=false; shift ;;
    --messaging)   SEARCH_MESSAGING=true;   SEARCH_ALL=false; shift ;;
    --analytics)   SEARCH_ANALYTICS=true;   SEARCH_ALL=false; shift ;;
    --jwt)         SEARCH_JWT=true;         SEARCH_ALL=false; shift ;;
    --devtools)    SEARCH_DEVTOOLS=true;    SEARCH_ALL=false; shift ;;
    --web3)        SEARCH_WEB3=true;        SEARCH_ALL=false; shift ;;
    --all)         SEARCH_ALL=true; shift ;;
    --report)      REPORT_FILE="$2"; shift 2 ;;
    --json)        JSON_OUTPUT=true; shift ;;
    --severity)    MIN_SEVERITY="$2"; shift 2 ;;
    --raw)         RAW_MODE=true; shift ;;
    -h|--help)     usage ;;
    -*)            echo "Error: Unknown option $1" >&2; usage ;;
    *)             ANALYSIS_DIR="$1"; shift ;;
  esac
done

if [[ -z "$ANALYSIS_DIR" ]]; then
  echo "Error: No analysis directory specified." >&2
  usage
fi

if [[ ! -d "$ANALYSIS_DIR" ]]; then
  echo "Error: Directory not found: $ANALYSIS_DIR" >&2
  exit 1
fi

# Force C locale so awk printf uses a decimal point (entropy/JSON stay valid) and
# regex character classes are byte-stable.
export LC_ALL=C

# Files to scan (extract-ipa.sh output). .h/.m/.swift are class-dump; .txt are strings/symbols.
INCLUDES=(--include='*.h' --include='*.m' --include='*.swift' --include='*.txt' --include='*.plist' --include='*.json' --include='*.c')

# --- Severity filter ---
severity_rank() {
  case "$1" in
    critical) echo 5 ;; high) echo 4 ;; medium) echo 3 ;; low) echo 2 ;; info) echo 1 ;; *) echo 0 ;;
  esac
}
MIN_RANK=$(severity_rank "$MIN_SEVERITY")
severity_passes() { [[ $(severity_rank "$1") -ge "$MIN_RANK" ]]; }

# =====================================================================
# FP-minimization helpers
# =====================================================================

# Placeholders / example / documentation values that are NOT real secrets.
# Anchored alternatives (^...$) match the whole value; the rest are strong placeholder
# markers unlikely to appear inside a real credential. Note: bare numeric runs like
# "123456789" are intentionally NOT here — real secrets legitimately contain digit runs.
ALLOWLIST_RE='AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI.*EXAMPLE|EXAMPLEKEY|example\.com|your[_-][A-Za-z0-9]+|YOUR[_-][A-Z0-9]+|<[^>]+>|^x{3,}$|^abc123$|^test$|^sample$|^dummy$|^placeholder$|^redacted$|^foobar$|^123$|REPLACE|TODO|my[_-](api[_-]?key|secret|token)|test[_-]key|demo[_-]key|firebase[_-]?(example|demo)|sentry[_-]?(example|demo)|maps\.googleapis\.com.*YOUR'

is_allowlisted() {
  # $1 = value. Returns 0 (true) if it matches a known placeholder.
  local val="$1"
  [[ "$val" =~ $ALLOWLIST_RE ]]
}

# Shannon entropy in bits/char (via awk). Empty → 0.
entropy() {
  awk -v s="$1" 'BEGIN{
    n=length(s); if(n==0){print 0; exit}
    for(i=1;i<=n;i++){c=substr(s,i,1); freq[c]++}
    e=0
    for(c in freq){p=freq[c]/n; e -= p*(log(p)/log(2))}
    printf "%.2f", e
  }'
}

# Format validators: return 0 if value matches the provider's strict format.
valid_aws()    { [[ "$1" =~ ^(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}$ ]]; }
valid_gcp()    { [[ "$1" =~ ^AIza[0-9A-Za-z_-]{35}$ ]]; }
valid_stripe() { [[ "$1" =~ ^(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,}$ ]]; }
valid_twilio_sid() { [[ "$1" =~ ^AC[0-9a-f]{32}$ ]]; }
valid_twilio_sk()  { [[ "$1" =~ ^SK[0-9a-f]{32}$ ]]; }
valid_sendgrid() { [[ "$1" =~ ^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$ ]]; }
valid_slack()  { [[ "$1" =~ ^xox[abprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}$ ]]; }
valid_github() { [[ "$1" =~ ^(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}$ ]]; }
valid_gitlab() { [[ "$1" =~ ^glpat-[A-Za-z0-9_-]{20}$ ]]; }
valid_mailgun() { [[ "$1" =~ ^key-[a-f0-9]{32}$ ]]; }
valid_mailchimp() { [[ "$1" =~ ^[a-f0-9]{32}-us[0-9]{1,2}$ ]]; }
valid_telegram() { [[ "$1" =~ ^[0-9]{8,10}:[A-Za-z0-9_-]{34,40}$ ]]; }
valid_square() { [[ "$1" =~ ^sq0[a-z][a-z0-9_-]{20,}$ ]]; }
valid_jwt() {
  # 3 base64url segments; header decodes to JSON containing "alg" or "typ".
  local v="$1"
  [[ "$v" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] || return 1
  local hdr="${v%%.*}"
  # base64url → base64
  hdr="${hdr//-/+}"; hdr="${hdr//_/\/}"
  local pad=$(( (4 - ${#hdr} % 4) % 4 )); hdr="${hdr}$(printf '=%.0s' $(seq 1 $pad) 2>/dev/null)"
  local decoded
  decoded=$(echo -n "$hdr" | base64 -d 2>/dev/null || true)
  [[ "$decoded" =~ (alg|typ) ]]
}

# Map a finding to FP-likelihood. Inputs: allowlisted?, format-valid?, entropy.
# High FP  → likely placeholder / low-entropy / format mismatch
# Medium FP → couldn't validate format (unknown provider) or borderline entropy
# Low FP    → format-valid AND high entropy AND not allowlisted
assess_fp() {
  local allowlisted="$1" format_valid="$2" ent="$3"
  if [[ "$allowlisted" == "yes" ]]; then
    echo "High"
  elif [[ "$format_valid" == "bad" ]]; then
    echo "High"
  elif [[ "$format_valid" == "unknown" ]]; then
    if awk -v e="$ent" 'BEGIN{exit !(e < 3.0)}'; then echo "High"; else echo "Medium"; fi
  else
    # format valid
    if awk -v e="$ent" 'BEGIN{exit !(e < 3.0)}'; then echo "Medium"; else echo "Low"; fi
  fi
}

# =====================================================================
# Counters
# =====================================================================
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
FP_HIGH_COUNT=0
CLIENT_SAFE_COUNT=0
INDICATOR_COUNT=0

REPORT_CONTENT=""
JSON_OBJS=""

# =====================================================================
# scan_secret: value-format secret with validation + dedup + FP-likelihood
#   $1 service $2 cred_type $3 severity $4 client_safe(yes/no) $5 value_regex
#   $6 validator_fn (or "" for unknown) [$7 -i for case-insensitive]
# =====================================================================
SEEN_FILE=$(mktemp)
trap 'rm -f "$SEEN_FILE"' EXIT
scan_secret() {
  local service="$1" cred_type="$2" severity="$3" client_safe="$4"
  local value_regex="$5" validator="${6:-}"
  local case_flag="${7:-}"
  shift 7 2>/dev/null || true

  if ! severity_passes "$severity"; then
    return
  fi

  # Extract candidate VALUES (dedup naturally with sort -u). -o prints only the match.
  local values=""
  if [[ -n "$case_flag" ]]; then
    # shellcheck disable=SC2086,SC2068
    values=$(grep -rohEi $case_flag ${INCLUDES[@]} "$value_regex" "$ANALYSIS_DIR" 2>/dev/null | sort -u || true)
  else
    # shellcheck disable=SC2086,SC2068
    values=$(grep -rohE ${INCLUDES[@]} "$value_regex" "$ANALYSIS_DIR" 2>/dev/null | sort -u || true)
  fi
  [[ -z "$values" ]] && return

  local sev_icon
  sev_icon=$(echo "$severity" | tr '[:lower:]' '[:upper:]')

  local first=1
  while IFS= read -r val; do
    [[ -z "$val" ]] && continue

    # Global dedup across providers so the same string isn't reported twice under
    # different pattern names.
    local key="${service}::${val}"
    if grep -Fxq -- "$key" "$SEEN_FILE" 2>/dev/null; then continue; fi
    printf '%s\n' "$key" >> "$SEEN_FILE"

    local allowlisted=no
    is_allowlisted "$val" && allowlisted=yes

    local format_valid=unknown
    if [[ -n "$validator" ]] && declare -f "$validator" >/dev/null 2>&1; then
      if "$validator" "$val"; then format_valid=good; else format_valid=bad; fi
    fi

    local ent
    ent=$(entropy "$val")

    local fp
    fp=$(assess_fp "$allowlisted" "$format_valid" "$ent")

    # FP filtering (unless --raw): drop High-FP allowlisted/mismatched from the
    # severity totals, but still note them as INFO so the user sees what was filtered.
    local report_severity="$severity"
    local filtered=0
    if [[ "$RAW_MODE" == false ]] && [[ "$fp" == "High" ]]; then
      report_severity="info"
      filtered=1
    fi

    # Client-safe downgrade: never critical even if format-valid (still report, lower impact)
    if [[ "$client_safe" == "yes" ]] && [[ "$report_severity" == "critical" ]]; then
      report_severity="medium"
    fi

    if ! severity_passes "$report_severity"; then
      continue
    fi

    TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
    case "$report_severity" in
      critical) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
      high)      HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
      medium)    MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
      low)       LOW_COUNT=$((LOW_COUNT + 1)) ;;
      info)      INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac
    [[ "$fp" == "High" ]] && FP_HIGH_COUNT=$((FP_HIGH_COUNT + 1))
    [[ "$client_safe" == "yes" ]] && CLIENT_SAFE_COUNT=$((CLIENT_SAFE_COUNT + 1))

    local sev_icon_r
    sev_icon_r=$(echo "$report_severity" | tr '[:lower:]' '[:upper:]')

    if [[ "$first" == 1 ]]; then
      echo
      echo "[$sev_icon] $service — $cred_type"
      first=0
    fi
    local val_preview
    if [[ ${#val} -gt 60 ]]; then
      val_preview="${val:0:4}...${val: -4} (redacted, ${#val} chars)"
    else
      val_preview="$val"
    fi
    printf "  → %-50s [FP:%-6s] [client-safe:%-3s] [entropy:%s]\n" "$val_preview" "$fp" "$client_safe" "$ent"
    [[ "$filtered" == 1 ]] && echo "    (filtered from $severity → info: likely placeholder/invalid format; rerun with --raw to keep)"

    if [[ -n "$REPORT_FILE" ]]; then
      REPORT_CONTENT+=$'\n'"#### [$sev_icon_r] $service — $cred_type"$'\n\n'
      REPORT_CONTENT+="- **Value**: \`$val_preview\`"$'\n'
      REPORT_CONTENT+="- **Severity**: $report_severity (original: $severity)"$'\n'
      REPORT_CONTENT+="- **FP-likelihood**: $fp"$'\n'
      REPORT_CONTENT+="- **Client-safe**: $client_safe"$'\n'
      REPORT_CONTENT+="- **Entropy**: $ent bits/char"$'\n'
      REPORT_CONTENT+="- **Format-valid**: $format_valid"$'\n'
      [[ "$filtered" == 1 ]] && REPORT_CONTENT+="- **Filtered**: yes (placeholder/invalid; use \`--raw\` to keep)"$'\n'
      REPORT_CONTENT+=$'\n'
    fi

    if [[ "$JSON_OUTPUT" == true ]]; then
      local jval
      jval=$(printf '%s' "$val" | sed 's/\\/\\\\/g; s/"/\\"/g')
      [[ -n "$JSON_OBJS" ]] && JSON_OBJS+=","
      JSON_OBJS+="{\"service\":\"$service\",\"type\":\"$cred_type\",\"severity\":\"$report_severity\",\"fp\":\"$fp\",\"client_safe\":\"$client_safe\",\"entropy\":$ent,\"value\":\"$jval\"}"
    fi
  done <<< "$values"
}

# =====================================================================
# indicator: keyword/config reference. INFO only, never counted in
# critical/high totals, no value validation. Used for SDK/config presence.
#   $1 service $2 desc $3 regex [$4 -i]
# =====================================================================
indicator() {
  local service="$1" desc="$2" regex="$3" case_flag="${4:-}"
  if ! severity_passes "info"; then return; fi

  local results=""
  if [[ -n "$case_flag" ]]; then
    # shellcheck disable=SC2086,SC2068
    results=$(grep -rlEi $case_flag ${INCLUDES[@]} "$regex" "$ANALYSIS_DIR" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
  else
    # shellcheck disable=SC2086,SC2068
    results=$(grep -rlE ${INCLUDES[@]} "$regex" "$ANALYSIS_DIR" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
  fi
  [[ "$results" == 0 ]] && return

  INDICATOR_COUNT=$((INDICATOR_COUNT + 1))
  echo
  echo "[INFO] $service — $desc (indicator, not a secret)"
  echo "  Found in $results file(s)"
  if [[ -n "$REPORT_FILE" ]]; then
    REPORT_CONTENT+=$'\n'"#### [INFO] $service — $desc (indicator)"$'\n\n'
    REPORT_CONTENT+="- **Files**: $results"$'\n\n'
  fi
}

echo "=== Deep Secret Scan: $ANALYSIS_DIR ==="
echo "Minimum severity: $MIN_SEVERITY (rank $MIN_RANK)"
echo "Raw mode: $RAW_MODE (FP filtering: $([[ "$RAW_MODE" == true ]] && echo OFF || echo ON))"
echo

# =====================================================================
# Firebase / Google  (config indicators + real keys)
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_FIREBASE" == true ]]; then
  echo "--- Scanning for Firebase / Google credentials ---"

  # Real Firebase API key (GCP-style AIza) — validated
  scan_secret "Firebase" "API Key" "medium" "yes" 'AIza[0-9A-Za-z_-]{35}' valid_gcp

  # Firebase service account (critical) — JSON key block indicator
  scan_secret "Firebase" "Service Account JSON" "critical" "no" '"type"[[:space:]]*:[[:space:]]*"service_account"'

  # Config indicators (NOT secrets) — INFO only
  indicator "Firebase" "GoogleService-Info config references" 'GOOGLE_APP_ID|GCM_SENDER_ID|FIREBASE_URL|REVERSED_CLIENT_ID|PLIST_VERSION|STORAGE_BUCKET|PROJECT_ID' "-i"
  indicator "Firebase" "Database/Storage URLs" 'firebaseio\.com|firebaseapp\.com|firebasestorage\.googleapis\.com'
  indicator "Firebase" "SDK class usage" 'FIRApp|FirebaseApp|FIRAuth|FIRDatabase|FIRFirestore|FIRStorage|FIRCrashlytics|FIRRemoteConfig|FIRAnalytics'
  indicator "Firebase" "Dynamic Links" 'page\.link|app\.goo\.gl|FIRDynamicLink'
fi

# =====================================================================
# Google Cloud Platform
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_GCP" == true ]]; then
  echo "--- Scanning for GCP credentials ---"

  scan_secret "GCP" "API Key" "high" "yes" 'AIza[0-9A-Za-z_-]{35}' valid_gcp
  scan_secret "GCP" "Service Account" "critical" "no" '"type"[[:space:]]*:[[:space:]]*"service_account"'
  indicator "GCP" "OAuth Client ID" '[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com'
  indicator "GCP" "API endpoints" 'googleapis\.com|storage\.cloud\.google\.com'
  indicator "Google" "Maps/Places SDK" 'maps\.googleapis\.com|places\.googleapis\.com|GMSServices|GMSMapView|GoogleMaps|GooglePlaces' "-i"
  indicator "Google" "Sign-In" 'GIDSignIn|GIDConfiguration|clientID.*googleusercontent'
fi

# =====================================================================
# AWS
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_AWS" == true ]]; then
  echo "--- Scanning for AWS credentials ---"

  scan_secret "AWS" "Access Key ID" "critical" "no" '(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}' valid_aws
  # Secret access keys rarely appear standalone as a recognizable token; flag the labeled
  # assignment only when an actual 40-char base64-ish value follows.
  scan_secret "AWS" "Secret Access Key" "critical" "no" 'aws[_-]?secret[_-]?(access[_-]?)?key[_=:][[:space:]]*[A-Za-z0-9/+=]{40}' "" "-i"
  scan_secret "AWS" "Session Token" "high" "no" 'aws[_-]?session[_-]?token[_=:][[:space:]]*[A-Za-z0-9/+=]{50,}' "" "-i"

  indicator "AWS" "Cognito Pool/Identity refs" 'cognito[_-]?identity[_-]?pool|user[_-]?pool[_-]?id|CognitoIdentityUserPoolId|CognitoIdentityPoolId' "-i"
  indicator "AWS" "SDK usage" 'AWSMobileClient|AWSCognitoIdentityProvider|AWSS3|AWSDynamoDB|AWSLambda|AWSAppSync|AWSIoT'
  indicator "AWS" "S3 bucket refs" 's3://[a-z0-9][a-z0-9.-]*|[a-z0-9.-]*\.s3\.amazonaws\.com|s3\.[a-z0-9-]*\.amazonaws\.com'
  indicator "AWS" "Endpoints" '\.amazonaws\.com|execute-api\..*\.amazonaws|lambda\..*\.amazonaws'
  indicator "AWS" "Amplify config" 'amplifyconfiguration|awsconfiguration|aws-exports' "-i"
fi

# =====================================================================
# Azure
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_AZURE" == true ]]; then
  echo "--- Scanning for Azure credentials ---"

  scan_secret "Azure" "Connection String" "critical" "no" 'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}'
  scan_secret "Azure" "SAS Token" "high" "no" 'SharedAccessSignature=[^[:space:]"'\'']+|sv=[0-9]{4}-[0-9]{2}-[0-9]{2}[^[:space:]"'\'']*sig=[A-Za-z0-9%+/=]+'

  indicator "Azure" "MSAL/ADAL" 'MSALPublicClientApplication|MSALConfiguration|MSALAuthority|ADALContext|ADAL'
  indicator "Azure" "Tenant/Client ID" 'tenant[_-]?id|client[_-]?id' "-i"
  indicator "Azure" "Endpoints" '\.azurewebsites\.net|\.blob\.core\.windows\.net|\.table\.core\.windows\.net|\.vault\.azure\.net|\.database\.windows\.net|\.servicebus\.windows\.net'
  indicator "Azure" "Notification Hubs" 'SBNotificationHub|notificationhubname|DefaultFullSharedAccessSignature' "-i"
  indicator "Azure" "App Configuration" 'Endpoint=https://.*\.azconfig\.io'
  indicator "Azure" "Key Vault" 'keyvault|\.vault\.azure\.net' "-i"
fi

# =====================================================================
# Payment Providers
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_PAYMENTS" == true ]]; then
  echo "--- Scanning for payment provider credentials ---"

  scan_secret "Stripe" "Secret Key" "critical" "no" 'sk_live_[0-9a-zA-Z]{24,}' valid_stripe
  scan_secret "Stripe" "Test Secret Key" "medium" "no" 'sk_test_[0-9a-zA-Z]{24,}' valid_stripe
  scan_secret "Stripe" "Publishable Key" "low" "yes" 'pk_(live|test)_[0-9a-zA-Z]{24,}' valid_stripe
  scan_secret "Stripe" "Restricted Key" "high" "no" 'rk_(live|test)_[0-9a-zA-Z]{24,}' valid_stripe

  indicator "PayPal/Braintree" "SDK" 'paypal|braintree|BTPayPalDriver|BTDropInController' "-i"
  indicator "RevenueCat" "API key / usage" 'revenuecat|Purchases\.configure|appl_[a-zA-Z0-9]' "-i"
fi

# =====================================================================
# Messaging / Push
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_MESSAGING" == true ]]; then
  echo "--- Scanning for messaging/push credentials ---"

  scan_secret "Twilio" "Account SID" "high" "no" 'AC[0-9a-f]{32}' valid_twilio_sid
  scan_secret "Twilio" "API Key" "high" "no" 'SK[0-9a-f]{32}' valid_twilio_sk
  scan_secret "SendGrid" "API Key" "critical" "no" 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}' valid_sendgrid
  scan_secret "Slack" "Bot/User Token" "critical" "no" 'xox[abprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}' valid_slack

  indicator "Slack" "Webhook" 'hooks\.slack\.com/services/'
  indicator "OneSignal" "App ID / usage" 'onesignal|setAppId' "-i"
  indicator "Pusher" "usage" 'pusher|PusherSwift|Pusher\(' "-i"
  indicator "PubNub" "keys/usage" 'pubnub|subscribeKey|publishKey' "-i"
fi

# =====================================================================
# Analytics
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_ANALYTICS" == true ]]; then
  echo "--- Scanning for analytics credentials ---"

  scan_secret "Sentry" "DSN (with secret)" "high" "no" 'https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+'
  indicator "Sentry" "DSN/SDK (no embedded secret)" 'sentry\.io|SentrySDK|https://[a-f0-9]*@.*\.ingest\.sentry\.io'
  indicator "Mixpanel" "token/usage" 'mixpanel|Mixpanel\.initialize|Mixpanel\.mainInstance' "-i"
  indicator "Amplitude" "API key/usage" 'amplitude|Amplitude\.instance|amplitude[_-]?api[_-]?key' "-i"
  indicator "Segment" "write key/usage" 'segment|Analytics\.setup|writeKey' "-i"
  indicator "Algolia" "API key/usage" 'algolia|ALGOLIA_API_KEY|algolianet\.com' "-i"
  indicator "Datadog" "client token/usage" 'datadog|Datadog\.initialize|clientToken|dd-api-key' "-i"
  indicator "Crashlytics" "usage" 'Crashlytics|FIRCrashlytics|fabric\.io'
  indicator "AppsFlyer" "dev key/usage" 'appsflyer|AppsFlyerLib|appsFlyerDevKey' "-i"
fi

# =====================================================================
# Developer-platform keys (GitHub, GitLab, ...)
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_DEVTOOLS" == true ]]; then
  echo "--- Scanning for developer-platform credentials ---"

  scan_secret "GitHub" "Token" "critical" "no" '(ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9]{36}' valid_github
  scan_secret "GitLab" "Token" "critical" "no" 'glpat-[A-Za-z0-9_-]{20}' valid_gitlab
  scan_secret "Mailgun" "API Key" "high" "no" 'key-[a-f0-9]{32}' valid_mailgun
  scan_secret "Mailchimp" "API Key" "high" "no" '[a-f0-9]{32}-us[0-9]{1,2}' valid_mailchimp
  scan_secret "Telegram" "Bot Token" "high" "no" '[0-9]{8,10}:[A-Za-z0-9_-]{34,40}' valid_telegram
  scan_secret "Square" "App Secret" "high" "no" 'sq0[a-z][a-z0-9_-]{20,}' valid_square
fi

# =====================================================================
# Web3 (Infura, Alchemy, private keys)
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_WEB3" == true ]]; then
  echo "--- Scanning for web3 credentials ---"

  scan_secret "Infura" "API Key (in URL)" "high" "yes" 'https://[a-z0-9]*\.infura\.io/v3/[A-Za-z0-9]{32}'
  scan_secret "Alchemy" "API Key (in URL)" "high" "yes" 'https://[a-z-]*\.g\.alchemy\.com/[a-z0-9]+/[A-Za-z0-9_-]{30,}'
  scan_secret "Ethereum" "Private Key (64 hex)" "critical" "no" '(0x)?[0-9a-fA-F]{64}' "" "-i"
  scan_secret "Generic" "Private Key Block" "critical" "no" 'BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY'
fi

# =====================================================================
# JWT Tokens
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_JWT" == true ]]; then
  echo "--- Scanning for JWT tokens ---"
  scan_secret "JWT" "Token" "high" "no" 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' valid_jwt
fi

# =====================================================================
# Generic high-confidence patterns (always run)
# =====================================================================
echo "--- Scanning for generic secret patterns ---"

scan_secret "Generic" "Private Key Block" "critical" "no" 'BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY'
scan_secret "Generic" "Hardcoded Password" "high" "no" '(password|passwd|pass)\s*[:=]\s*"[^"]{8,}"' "" "-i"
scan_secret "Generic" "Encryption Key" "high" "no" '(encryption[_-]?key|aes[_-]?key|secret[_-]?key)\s*[:=]\s*"[^"]{8,}"' "" "-i"
scan_secret "Generic" "Hardcoded IV" "high" "no" '(iv[_-]?vector|initialization[_-]?vector)\s*[:=]\s*"[^"]{8,}"' "" "-i"

# =====================================================================
# Summary
# =====================================================================
echo
echo "============================================"
echo "=== Deep Secret Scan Complete ==="
echo "============================================"
echo
echo "Validated findings: $TOTAL_FINDINGS"
echo "  Critical: $CRITICAL_COUNT"
echo "  High:     $HIGH_COUNT"
echo "  Medium:   $MEDIUM_COUNT"
echo "  Low:      $LOW_COUNT"
echo "  Info:     $INFO_COUNT (includes filtered placeholders)"
echo "Client-safe (downgraded): $CLIENT_SAFE_COUNT"
echo "High-FP-likelihood: $FP_HIGH_COUNT (placeholders / low-entropy / format-mismatch)"
echo "Config indicators (INFO, not secrets): $INDICATOR_COUNT"
echo
echo "LLM_ANALYSIS_SUMMARY:TOTAL=$TOTAL_FINDINGS,CRITICAL=$CRITICAL_COUNT,HIGH=$HIGH_COUNT,MEDIUM=$MEDIUM_COUNT,LOW=$LOW_COUNT,INFO=$INFO_COUNT,FP_HIGH=$FP_HIGH_COUNT,CLIENT_SAFE=$CLIENT_SAFE_COUNT,INDICATORS=$INDICATOR_COUNT"

# --- Generate report ---
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Deep Secret Scan Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Minimum severity**: $MIN_SEVERITY"
    echo "**Raw mode**: $RAW_MODE (FP filtering: $([[ "$RAW_MODE" == true ]] && echo OFF || echo ON))"
    echo
    echo "## Summary"
    echo
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| Critical | $CRITICAL_COUNT |"
    echo "| High | $HIGH_COUNT |"
    echo "| Medium | $MEDIUM_COUNT |"
    echo "| Low | $LOW_COUNT |"
    echo "| Info (incl. filtered) | $INFO_COUNT |"
    echo "| **Validated total** | **$TOTAL_FINDINGS** |"
    echo
    echo "| FP tag | Count |"
    echo "|--------|-------|"
    echo "| High FP-likelihood (placeholders/invalid) | $FP_HIGH_COUNT |"
    echo "| Client-safe (downgraded) | $CLIENT_SAFE_COUNT |"
    echo "| Config indicators (not secrets) | $INDICATOR_COUNT |"
    echo
    echo "## Findings"
    echo
    echo "$REPORT_CONTENT"
    echo
    echo "---"
    echo
    echo "## LLM Analysis Instructions"
    echo
    echo "For each finding above, analyze:"
    echo "1. **Is this a real credential or a false positive?** — Check FP-likelihood; High means placeholder/low-entropy/format-mismatch (re-examine with \`--raw\` if unsure)."
    echo "2. **Is this credential client-safe?** — client-safe=yes means intended for client use (Firebase API Key, Stripe publishable, Mapbox public); impact is limited. server-side keys (sk_live, AWS secret, Slack bot) are critical."
    echo "3. **What is the blast radius?** — What can an attacker do with this credential?"
    echo "4. **What is the remediation?** — Rotate, restrict via referrer/IP allowlists, move to server-side, use environment config."
    echo "5. **Can this be validated?** — Suggest safe validation commands (e.g. \`aws sts get-caller-identity\`, Firebase REST, Stripe API)."
    echo
    echo "### FP-minimization notes"
    echo
    echo "- Candidates are deduplicated by **value**, not by grep line (a secret in 3 files = 1 finding)."
    echo "- Values matching the allowlist (EXAMPLE, your_key, AKIAIOSFODNN7EXAMPLE, sk_test via separate pattern, etc.) are downgraded to INFO unless \`--raw\`."
    echo "- Provider formats are validated (AWS AKIA alphabet, GCP AIza length, Stripe prefix, JWT 3-segment header) — mismatches raise FP-likelihood."
    echo "- Shannon entropy < 3.0 bits/char raises FP-likelihood (long low-randomness strings are usually binary artifacts, not secrets)."
    echo "- Config indicators (SDK class names, endpoint URLs) are reported as INFO and excluded from critical/high totals."
    echo
    echo "---"
    echo "_Report generated by ios-reverse-engineering-skill deep-secret-scan_"
  } > "$REPORT_FILE"
  echo "Report saved to: $REPORT_FILE"
fi

if [[ "$JSON_OUTPUT" == true ]]; then
  echo "JSON_FINDINGS:[${JSON_OBJS}]"
fi

# Exit code based on severity (validated findings only)
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
  exit 2
elif [[ "$HIGH_COUNT" -gt 0 ]]; then
  exit 1
else
  exit 0
fi