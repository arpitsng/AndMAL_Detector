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
#  Single-Call Analysis (Full APK in one LLM call with FCG API Intent Mapping)
# =============================================================================

SINGLE_CALL_SYSTEM = (
    "You are a principal cybersecurity researcher specializing in Android static binary analysis. "
    "You analyze backward-sliced Control Flow Graphs (Jimple IR CFGs) structured into Function Call Graphs (FCGs) "
    "extracted from an Android application. "
    "You will receive all CFG slices grouped by Suspicious API, along with caller -> callee call chains.\n\n"
    "DECISION METHODOLOGY:\n"
    "1. **Analyze API Intent via FCG Call Chains**: For each suspicious API group, examine its call chain "
    "(CALLS / CALLED_BY) and data-flow to determine WHY the application invokes the API:\n"
    "   - **MALWARE Intent**: The call chain connects sensitive data sources (IMEI/IMSI, SMS, location) to network sinks "
    "     or dynamic bytecode execution (e.g., payload downloading via openConnection/openFileOutput feeding into DexClassLoader/loadClass).\n"
    "   - **BENIGN Intent**: The call chain is confined to standard framework operations: UI fragment initialization, "
    "     view inflation, ContentProvider queries (CursorLoader -> query), activity navigation, local caching, or app protection without exfiltration.\n"
    "2. Determine whether the application is MALWARE or BENIGN based strictly on verifiable data-flow evidence."
)

SINGLE_CALL_TEMPLATE = """\
Analyze ALL of the following backward-sliced Control Flow Graphs (CFGs) grouped by
Suspicious API and structured with Function Call Graph (FCG) caller/callee relationships.
Each CFG slice shows Jimple IR statements that are data-flow relevant to a suspicious API call site.

=============================================================================
 CALIBRATION RULES (Distinguish Legitimate Frameworks from Real Malware)
=============================================================================

A. LEGITIMATE BENIGN INTENT PATTERNS (Do NOT flag as malware):
1. **Standard UI & Framework Reflection**:
   - `loadClass` or `newInstance` inside `android.support.*`, `androidx.*`, `com.google.android.gms.*`, or `com.alibaba.fastjson.*` for fragment instantiation, view inflation, or JSON serialization.
2. **Activity Routing & Commercial App Protectors**:
   - Modular navigation (e.g., `com.alibaba.android.arouter`) using reflection to find activities.
   - Commercial app protectors (e.g., `com.secneo`, `com.tencent.StubShell`, `com.qihoo.util`) that protect code integrity or load native libraries (`loadLibrary`) WITHOUT exfiltrating private user data.
3. **Local File & Network Operations**:
   - `openFileInput`, `openFileOutput`, `getExternalStorageDirectory` used for standard app caching or configuration.
   - `getActiveNetworkInfo`, `openConnection` for standard connectivity monitoring or REST API requests.
4. **Input Device ID**:
   - `getDeviceId` called on `android.view.InputDevice` or within `KeyEvent` handling (this is an input device identifier, NOT a telephony IMEI).

B. MALICIOUS INTENT PATTERNS (FLAG AS MALWARE):
1. **Dnotua & Anydown (Silent Downloaders / Droppers)**:
   - Network download (`openConnection` / `openFileOutput`) feeding directly into `DexClassLoader`, `loadClass`, or dynamic execution to run external payloads in the background. Often embedded within disguised or custom support classes.
2. **Dowgin, Airpush, Viser, Kuguo (Adware / Spyware / Harvesters)**:
   - Reading sensitive telephony hardware identifiers (`TelephonyManager.getDeviceId` [IMEI], `getSubscriberId` [IMSI], `getSimSerialNumber`, `getLine1Number`, `getMacAddress`) in background services and transmitting them via `openConnection` or `getOutputStream`.
3. **SMSReg & UMPay (SMS Fraud)**:
   - Calling `sendTextMessage`, `SmsManager`, or registering background SMS receivers without explicit user consent flow.
4. **Ewind, Geinimi, Mobby (Trojans / Botnets / Backdoors)**:
   - Shell command execution (`Runtime.getRuntime().exec`), C2 communication, or payload unpacking combined with device surveillance.
5. **HiddenAd & FakeApp (Stealth Adware / Phishing)**:
   - Programmatically hiding the launcher icon (`setComponentEnabledSetting`) right after launch, or impersonating system/banking dialogs.

=============================================================================
 DECISION SUMMARY:
 - FLAG MALWARE: If you find active payload delivery (dynamic dex downloading/loading), exfiltration of private telephony IDs, silent SMS, or backdoor execution.
 - FLAG BENIGN: If API calls are standard framework plumbing (UI reflection, activity routing, local caching, commercial packers without exfiltration).
=============================================================================

=== RAG KNOWLEDGE BASE MATCHES ===
Here are the most structurally similar CFGs from our known malware/benign database:
{rag_context}
================================

=== BEGIN API-GROUPED FUNCTION CALL GRAPHS (FCGs) & CFG SLICES ===
{all_cfgs}
=== END FUNCTION CALL GRAPHS & CFG SLICES ===

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
EVIDENCE: <2-3 sentences explaining your reasoning, citing specific API groups, call chains, or function names>
"""


# =============================================================================
#  Bulk-Chunked Code Reasoning (HBCR) — For Large APKs
# =============================================================================

BULK_CHUNK_SYSTEM = (
    "You are a cybersecurity expert specializing in Android static binary analysis. "
    "You are analyzing a partitioned chunk of backward-sliced Control Flow Graphs (CFGs) "
    "structured into Function Call Graphs (FCGs) for an Android application.\n\n"
    "YOUR TASK:\n"
    "Analyze the FCG call chains and Jimple IR statements in this chunk. Determine whether "
    "this chunk contains any malicious behavior patterns (dropper payload downloading/loading, "
    "telephony identifier exfiltration, silent SMS, backdoor execution) or consists entirely "
    "of benign framework plumbing (UI reflection, activity routing, local caching)."
)

BULK_CHUNK_TEMPLATE = """\
You are analyzing Chunk {chunk_id} of {total_chunks} for an Android application.
Below are the FCG-structured CFG slices assigned to this chunk.

=============================================================================
 CALIBRATION RULES
=============================================================================
- BENIGN INTENT: Standard UI reflection (androidx, support), activity routing (ARouter),
  commercial packers (com.secneo, com.tencent.StubShell) without data theft, local file caching.
- MALICIOUS INTENT: Network downloads feeding into DexClassLoader/loadClass (droppers like dnotua),
  telephony hardware ID harvesting (TelephonyManager.getDeviceId/getSubscriberId sent over network),
  silent SMS (sendTextMessage), command execution (Runtime.exec).

=== BEGIN CHUNK {chunk_id}/{total_chunks} FCG SLICES ===
{chunk_cfgs}
=== END CHUNK {chunk_id}/{total_chunks} FCG SLICES ===

Total functions in this chunk: {func_count}
Suspicious APIs in this chunk: {api_list}

Provide your chunk analysis in EXACTLY this format:

CHUNK_ID: {chunk_id}/{total_chunks}
SUSPICIOUS_BEHAVIOR_FOUND: <YES or NO>
SUSPICIOUS_CHAINS:
- <specific suspicious call chain or "None detected">
BENIGN_FRAMEWORKS_IDENTIFIED:
- <identified benign frameworks or "None">
CHUNK_SUMMARY: <2-3 sentences summarizing the functions analyzed in this chunk and their behavioral intent>
"""

BULK_AGGREGATION_SYSTEM = (
    "You are a principal cybersecurity architect specializing in Android malware detection. "
    "You synthesize chunk-by-chunk static analysis findings from an Android application "
    "to determine the final APK-level verdict: MALWARE or BENIGN."
)

BULK_AGGREGATION_TEMPLATE = """\
You have analyzed all {total_chunks} chunks of an Android application covering all {total_functions} functions.
Below is the synthesized evidence gathered from each chunk analysis:

=============================================================================
 CHUNK-BY-CHUNK ANALYSIS FINDINGS
=============================================================================
{all_chunk_reports}

=============================================================================
 RAG KNOWLEDGE BASE MATCHES
=============================================================================
{rag_context}

=============================================================================
 DECISION CRITERIA
=============================================================================
- Classify as MALWARE if any chunk demonstrated verifiable malicious payload delivery
  (dynamic dex loading from network), private telephony exfiltration (IMEI/IMSI to server),
  silent SMS fraud, or backdoor execution.
- Classify as BENIGN if all functions across all chunks represent standard framework plumbing,
  UI reflection, activity routing, local caching, or commercial packers without exfiltration.

Provide your final APK assessment in EXACTLY this format:

=== FINAL APPLICATION ANALYSIS ===

PREDICTION: <MALWARE or BENIGN>
CONFIDENCE: <HIGH, MEDIUM, or LOW>
APP_PURPOSE: <1-2 sentence description of what the application does>
KEY_FINDINGS:
- <finding 1>
- <finding 2>
- <finding 3>
EVIDENCE: <2-3 sentences synthesizing the verifiable evidence across all analyzed chunks>
"""

