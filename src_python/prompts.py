"""
LAMD Prompt Templates — Tier-Wise Code Reasoning
==================================================
Structured prompt templates for the 3-tier LAMD malware detection pipeline.

Tier 1: Function-level analysis of each sliced CFG
Tier 2: API-level aggregation of function summaries
Tier 3: APK-level malware/benign prediction

Also includes factual consistency verification (DRC) prompts.

Reference: LAMD paper, Section 3.3 (Tier-wise Code Reasoning)
"""

# =============================================================================
#  Tier 1 — Function-Level CFG Analysis
# =============================================================================

TIER1_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "You analyze control flow graphs (CFGs) extracted from Android applications "
    "via backward program slicing. Your task is to summarize the behavior of "
    "each function, focusing on how it uses the identified suspicious API."
)

TIER1_USER_TEMPLATE = """\
Analyze the following sliced control flow graph from an Android application.
The CFG shows Jimple IR statements that are data-flow or control-dependence
relevant to a suspicious API call.

Provide a concise behavioral summary that covers:
1. What data is being accessed or manipulated
2. How the suspicious API is being used
3. Whether the usage pattern appears malicious or benign
4. Any obfuscation or evasion techniques visible

Control Flow Graph:
{cfg_content}

Respond with a structured summary in this format:
FUNCTION: <function name>
SUSPICIOUS_API: <API name>
BEHAVIOR: <1-2 sentence description of what this function does>
DATA_FLOW: <what data flows into/out of the suspicious API>
RISK_ASSESSMENT: <LOW/MEDIUM/HIGH with brief justification>
"""

# =============================================================================
#  Factual Consistency Verification — Data Relationship Coverage (DRC)
# =============================================================================

DRC_SYSTEM = (
    "You are a program analysis expert. You identify variable relationships "
    "within control flow graphs. Be precise and only report relationships "
    "that are explicitly present in the code."
)

DRC_USER_TEMPLATE = """\
The provided control flow graph represents a slice of a function, identifying
variable relationships for each statement leading to the final invocation
statement that invokes {function_name}.

Identify all data dependencies among variables in the CFG. Classify each
dependency into one of the following FIVE types:

1. **Direct**: Variables used directly as function parameters.
   Example: invoker1.method(r2) → r1, r2

2. **Transitive**: Variables whose values flow through assignments but are
   not directly used in the invocation.
   Example: r2 = r3.getValue(); invoker1.method(r2) → r3

3. **Conditional**: Variables in branch statements whose value affects
   whether the API invocation is reached.
   Example: if r4 != null goto label → r4

4. **Parallel**: Variables that are computed together or share a common source.
   Example: r2 = r1.getA(); r3 = r1.getB() → r2, r3 are parallel

5. **Derived**: Variables whose value is computed from another tracked variable.
   Example: r3 = r2 + 1 → r3 is derived from r2

Control Flow Graph:
{cfg_content}

Output your analysis in this exact format (one dependency per line):
<dependency_type>: <variable_names>
"""

# =============================================================================
#  Factual Consistency Verification — Tier 1 Hallucination Check
# =============================================================================
# NOTE: this is distinct from DRC_SYSTEM/DRC_USER_TEMPLATE above (which
# classifies variable-dependency types). This checks whether a Tier 1
# behavioral summary's claims are actually supported by the CFG it was
# generated from — i.e. whether the summary hallucinated behavior the code
# doesn't show.

DRC_VERIFY_SYSTEM = (
    "You are a strict fact-checker for static-analysis reports. You compare "
    "a behavioral summary against the exact code it claims to describe, and "
    "flag any claim that is not directly supported by the code shown. You "
    "do not evaluate whether the summary's conclusions are reasonable — only "
    "whether every factual claim in it is actually present in the code."
)

DRC_VERIFY_USER_TEMPLATE = """\
Below is a sliced Control Flow Graph (Jimple IR) and a behavioral summary
that was generated from it. Check whether the summary's factual claims
(what data is accessed, what values flow where, what the code does) are
actually supported by the code — not whether the summary's risk judgment
is reasonable.

Control Flow Graph:
{cfg_content}

Behavioral Summary To Verify:
{tier1_summary}

Look specifically for:
- Claims about data (e.g. "hardcoded number", "user's contacts") that
  don't appear in the code shown.
- Claims about an action (e.g. "sends data", "without consent") that isn't
  actually present in this slice.
- Invented details not derivable from the NODE/EDGE statements above.

Respond in EXACTLY this format:
VERDICT: <CONSISTENT or INCONSISTENT>
REASON: <one sentence — if INCONSISTENT, name the specific unsupported claim>
"""

# =============================================================================
#  Tier 2 — API-Level Summary
# =============================================================================

TIER2_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "You aggregate function-level analysis results to determine the overall "
    "intent behind how an application uses a specific sensitive API."
)

TIER2_USER_TEMPLATE = """\
The following are behavioral summaries of all functions in an Android application
that invoke the suspicious API: {api_name} ({api_type}).

For each function, a backward-sliced control flow graph was analyzed to produce
these summaries.

Function Summaries:
{function_summaries}

Based on these summaries, provide an API-level intent analysis:

API_NAME: {api_name}
API_TYPE: {api_type}
USAGE_COUNT: {usage_count} function(s)
OVERALL_INTENT: <2-3 sentence description of why the app uses this API>
SUSPICIOUS_PATTERNS: <any concerning patterns across functions, or "None detected">
RISK_LEVEL: <LOW/MEDIUM/HIGH/CRITICAL with justification>
"""

# =============================================================================
#  Tier 3 — APK-Level Malware Judgement
# =============================================================================

TIER3_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "Determine whether the application is MALWARE or BENIGN, citing indicators "
    "of compromise, evidence, and malicious patterns if present. Give a final "
    "prediction and key findings of your analysis. "
    "IMPORTANT: Be balanced in your assessment. Many legitimate apps use "
    "reflection, network checks, and storage access. Only classify as MALWARE "
    "if there are CLEAR malicious indicators."
)

TIER3_USER_TEMPLATE = """\
You are analyzing an Android application for potential malware behavior.
Below are the API-level intent summaries for all suspicious APIs found
in this application.

CALIBRATION — Common BENIGN patterns (do NOT flag these alone as malware):
- Reflection (forName, newInstance, getDeclaredMethod): Used by nearly all
  apps for plugin systems, dependency injection, and compatibility layers.
- Network checks (getActiveNetworkInfo): Standard Android behavior for
  any app that uses the internet.
- Storage access (getExternalStorageDirectory): Normal for apps that
  save files, photos, or cache data.
- Class loading (DexClassLoader): Commonly used by app frameworks like
  React Native, Flutter, and game engines to load bundled code.

Only classify as MALWARE if you find CLEAR indicators such as:
- Sending premium SMS without user consent
- Covert data exfiltration to remote servers
- Dynamic loading of remote/encrypted payloads from unknown URLs
- Accessing sensitive data (contacts, SMS, calls) without clear user purpose
- Hiding functionality through heavy obfuscation + suspicious network activity

{api_summaries}

Based on ALL the above API analysis results, provide your final assessment:

=== FINAL APPLICATION ANALYSIS ===

**Final Prediction:**
<MALWARE or BENIGN>

**Application Purpose:**
<1-2 sentence description of what the app appears to do>

**Indicators of Compromise:**
<numbered list of specific suspicious behaviors found, or "None detected">

**Final Conclusion:**
<2-3 sentence overall assessment with confidence level>
"""

# =============================================================================
#  Direct Analysis (for pre-computed logs / single-shot analysis)
# =============================================================================

DIRECT_ANALYSIS_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "You analyze sliced control flow graphs extracted from Android applications "
    "and determine whether they indicate malicious behavior."
)

DIRECT_ANALYSIS_TEMPLATE = """\
Analyze the following sliced control flow graph(s) extracted from an Android
application. These CFGs were produced by backward program slicing from
suspicious API call sites.

Determine if this application is MALWARE or BENIGN.

{cfg_content}

Provide your analysis in this exact format:

=== FINAL APPLICATION ANALYSIS ===

**Final Prediction:**
<MALWARE or BENIGN>

**Application Purpose:**
<1-2 sentence description of what the app appears to do>

**Indicators of Compromise:**
<numbered list of specific suspicious behaviors, or "None detected">

**Final Conclusion:**
<2-3 sentence overall assessment>
"""


# =============================================================================
#  Helper: Format API summaries for Tier 3
# =============================================================================

def format_api_summaries_for_tier3(api_summaries: list[dict]) -> str:
    """
    Formats a list of API summary dicts into the Tier 3 prompt input.

    Each dict should have keys: api_name, api_type, summary
    """
    parts = []
    for i, api in enumerate(api_summaries, 1):
        parts.append(
            f"--- API {i} ---\n"
            f"API name: {api['api_name']}\n"
            f"API type: {api.get('api_type', 'access')}\n"
            f"API intent: {api['summary']}\n"
        )
    return "\n".join(parts)


def classify_api_type(api_name: str) -> str:
    """
    Classifies a suspicious API as 'access' (data source) or
    'transfer' (data sink) based on the LAMD paper's taxonomy.
    """
    TRANSFER_APIS = {
        "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage",
        "openFileOutput", "exec", "loadLibrary", "load",
        "doFinal", "update", "invoke", "startRecording",
        # Network exfiltration — literal data sinks, added alongside the
        # Java slicer's new network-exfil seed APIs.
        "openConnection", "connect", "getOutputStream",
    }
    if api_name in TRANSFER_APIS:
        return "transfer"
    return "access"


# =============================================================================
#  Single-Call Analysis (Full APK in one LLM call)
# =============================================================================

SINGLE_CALL_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware detection. "
    "You analyze backward-sliced Control Flow Graphs (CFGs) extracted from "
    "Android APKs. You will receive ALL the CFG slices from a single application "
    "and must determine if the application is MALWARE or BENIGN.\n\n"
    "IMPORTANT: Err on the side of caution. If the evidence is ambiguous but "
    "leans toward malicious behavior, classify as MALWARE with MEDIUM confidence. "
    "Only classify as BENIGN if you are confident the app has a clear, legitimate purpose "
    "and the suspicious APIs are used in standard, expected ways."
)

SINGLE_CALL_TEMPLATE = """\
Analyze ALL of the following backward-sliced Control Flow Graphs (CFGs) extracted
from a single Android application. Each CFG slice shows Jimple IR statements
that are data-flow relevant to a suspicious API call site.

CALIBRATION — These patterns are COMMON in benign apps (do NOT flag alone):
- Reflection in well-known standard libraries (android.support, com.google.android.gms).
- Network checks (getActiveNetworkInfo) for standard connectivity monitoring.
- Storage access (getExternalStorageDirectory) for standard app file caching.
- Device ID access (getDeviceId) by well-known, named analytics SDKs (e.g., com.flurry, com.crashlytics).

KNOWN MALWARE FAMILY PATTERNS:

1. **Dowgin & Airpush** (Adware/Spyware): Masquerade as ad networks but harvest
   device identifiers (IMEI, MAC) using reflection. Look for obfuscated packages
   (e.g., `a.b.c`, `com.bu.a`) using `Class.forName`/`getMethod` to dynamically
   load sensitive APIs in the background.

2. **Dnotua & Anydown** (Silent Downloaders): Background services collecting
   location or network data, coupled with dynamic code loading from untrusted
   sources. Often have minimal UI but heavy background activity.

3. **TencentProtect / Commercial Packers**: Packers like `com.tencent.StubShell`
   or `com.secneo` combined with heavy data harvesting and no clear benign purpose.

4. **Revmob & Domob** (Aggressive Ad Networks): Excessive ad injection, silent
   ad loading in background, tracking beacons. Look for packages like
   `com.revmob`, `cn.domob` accessing device IDs, installing shortcuts, or
   displaying ads without user interaction.

5. **SMSReg** (SMS Fraud): Silent SMS sending or interception. Look for
   `sendTextMessage`, `SmsManager`, or `BroadcastReceiver` for SMS_RECEIVED
   without clear user consent flow.

6. **HiddenAd** (Stealth Adware): Hides the app icon after install, displays
   ads aggressively. Look for `setComponentEnabledSetting` to disable launcher
   activity, combined with ad SDK initialization.

7. **Ramnit** (File Infector): Unusual file I/O patterns combined with exec()
   calls, native library loading, or attempts to modify other app files.

8. **Kuguo & Feiwo** (Chinese Adware): Similar to Dowgin. Heavy use of Chinese
   ad SDKs with device fingerprinting. Look for packages like `com.kuguo`,
   `com.feiwo` harvesting IMEI/IMSI.

9. **Deng & Scamapp** (Data Harvesters): Silently collect contacts, SMS, call
   logs, and transmit them. Look for ContentResolver queries to `content://sms`,
   `content://contacts`, `content://call_log` combined with network operations.

10. **Gappusin** (Aggressive PUP): Installs additional apps without consent,
    modifies browser settings, pushes notifications aggressively.

FLAG AS MALWARE if you find ANY of these combinations:
- Reflection/Dynamic loading in OBFUSCATED or UNKNOWN packages accessing sensitive data.
- Collecting sensitive data (contacts, SMS, call logs, device IDs) without clear user-facing purpose.
- Heavy obfuscation + encrypted payloads + background execution.
- Silent SMS sending or interception.
- Hidden app icon + aggressive ad display.
- Unknown packages harvesting IMEI, IMSI, MAC address, or subscriber ID.
- Dynamic code loading (DexClassLoader, loadClass) from non-standard sources.

=== RAG KNOWLEDGE BASE MATCHES ===
Here are the 3 most structurally similar CFGs from our known malware/benign database:
{rag_context}
================================

=== BEGIN CFG SLICES ===
{all_cfgs}
=== END CFG SLICES ===

Total functions analyzed: {func_count}
Suspicious APIs found: {api_list}

Provide your analysis in EXACTLY this format:

PREDICTION: <MALWARE or BENIGN>
CONFIDENCE: <HIGH, MEDIUM, or LOW>
APP_PURPOSE: <1-2 sentence description of what this app appears to do>
KEY_FINDINGS:
- <finding 1>
- <finding 2>
- <finding 3>
EVIDENCE: <2-3 sentences explaining your reasoning, citing specific function names or APIs>
"""
