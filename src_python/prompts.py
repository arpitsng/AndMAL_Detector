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
#  Tier 2 (batched) — several small API groups analyzed in ONE call
# =============================================================================
# Pure engineering optimization for the hybrid pipeline: many suspicious-API
# groups have very few functions (1-4), so a full separate LLM call for each
# is dominated by fixed per-call overhead rather than content volume.
# Batching several of these into one call cuts round-trip count without
# changing WHAT gets analyzed or losing per-API separation in the output —
# each API still gets analyzed on its own dedicated content, just packaged
# into a shared request/response. Never used for large groups (those still
# get their own call, same as before).

TIER2_BATCH_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "You will analyze SEVERAL independent suspicious APIs in this one request, "
    "each with its own function call graph content. Treat each API completely "
    "independently — do not let evidence from one API's functions influence "
    "your assessment of a different API. Produce exactly one result block per "
    "API listed, in the exact format shown, using the EXACT API name given as "
    "the block's identifier."
)

TIER2_BATCH_USER_TEMPLATE = """\
Below are {group_count} independent suspicious APIs found in an Android application. \
For EACH one, a backward-sliced control flow graph was analyzed for all functions \
that invoke it. Analyze each API's intent completely independently of the others.

{grouped_content}

Provide EXACTLY {group_count} result blocks, one per API listed above, in this \
EXACT format (repeat for each API, using its exact name from the list):

=== API_RESULT: <api_name> ===
API_NAME: <api_name>
API_TYPE: <access or transfer>
USAGE_COUNT: <N> function(s)
OVERALL_INTENT: <2-3 sentence description of why the app uses this API>
SUSPICIOUS_PATTERNS: <any concerning patterns across functions, or "None detected">
RISK_LEVEL: <LOW/MEDIUM/HIGH/CRITICAL with justification>
=== END API_RESULT ===
"""

# =============================================================================
#  Tier 3 — APK-Level Malware Judgement
# =============================================================================

TIER3_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "Determine whether the application is MALWARE or BENIGN, citing indicators "
    "of compromise, evidence, and malicious patterns if present. Give a final "
    "prediction and key findings of your analysis. "
    "IMPORTANT: Weigh the evidence proportionally in both directions — but "
    "'proportional' means weighing CONCRETE evidence, not adding up generic "
    "facts. Reflection, minified/short class names, dynamic class loading, "
    "and reading a sensitive API are baseline noise present in nearly every "
    "production Android app (ad SDKs, analytics, crash reporting, app "
    "frameworks); citing several of these together is still citing zero real "
    "evidence, no matter how the count looks. Only count something as an "
    "indicator if you can name the SPECIFIC value and where it concretely "
    "goes (e.g. 'the IMEI read in X is passed as an argument into the HTTP "
    "call in Y', not 'the app reads the IMEI and also uses reflection'). "
    "Don't require 100% certainty before calling something MALWARE — but "
    "don't manufacture certainty out of volume of unrelated, individually "
    "ordinary observations either."
)

TIER3_USER_TEMPLATE = """\
You are analyzing an Android application for potential malware behavior.
Below are the API-level intent summaries for all suspicious APIs found
in this application.

CALIBRATION — these are BASELINE NOISE, never indicators, regardless of how
many call sites there are or how "obfuscated"/minified the class names look
(ProGuard/R8 minification to single-letter names is normal in nearly every
production APK and is NOT evidence of malicious obfuscation on its own):
- Reflection (forName, newInstance, getDeclaredMethod, getDeclaredField,
  invoke): used by nearly all apps for plugin systems, dependency injection,
  serialization, and compatibility layers. Extensive/repeated use across
  many functions does NOT make this more suspicious — ad SDKs (AppLovin,
  Unity Ads, Google Ads/GMS), analytics, and crash reporters commonly have
  hundreds of reflection call sites and are still ordinary, benign SDKs.
- Dynamic class loading (DexClassLoader, loadClass) IS baseline noise ONLY
  when the loaded target is a hardcoded, readable literal you can point to
  that names a recognizable bundled/framework package (react native,
  flutter, unity, adobe air, a known ad/mediation SDK, or the app's own
  package). Frameworks and SDKs load their OWN bundled code this way — that
  specific, confirmable case is not suspicious, no matter how many times it
  happens.
- Network checks (getActiveNetworkInfo) and ordinary network requests
  (openConnection/connect/getOutputStream to fetch ads, configs, or content):
  standard behavior for any internet-connected app.
- Storage access (getExternalStorageDirectory, openFileOutput/Input): normal
  for apps that cache files, images, or config.
- Reading ONE sensitive value (device ID, location, etc.) in isolation, with
  no traced destination for that value: this is a fact about the code, not
  an indicator — nearly every analytics/ads SDK reads a device identifier
  for attribution. It only becomes relevant once you can point to where that
  specific value goes (see below).

Indicators that actually drive a MALWARE verdict — each one requires you to
name the SPECIFIC data/action and its concrete destination or effect, not a
category of API:
- HIGH confidence alone: sending premium-rate SMS without a visible user
  consent flow; a SPECIFIC sensitive value (IMEI, contacts, SMS content)
  demonstrably passed into a network-send call in the same or a connected
  function (name both the source and the sink function); dynamically
  loading a class from a value that is itself downloaded over the network
  or decoded/decrypted at runtime (not a bundled/local resource); disabling
  the launcher icon or hiding the app right after install.
- MEDIUM confidence alone, but can combine with another indicator on THIS
  list (not with baseline-noise items above): a runtime-decoded or
  runtime-constructed string (e.g. built from a byte array or XORed at
  runtime) used as a class name, URL, or command — i.e. the code is
  actively hiding a literal from static inspection, not merely minified;
  a content-provider query against contacts/SMS/call-log whose result is
  then written to a file or network call you can point to; shell command
  execution (Runtime.exec) with an argument that isn't a fixed, readable
  string; DexClassLoader/loadClass where the loaded target does NOT meet
  the baseline-noise bar above — i.e. you cannot point to a hardcoded,
  readable literal naming a recognizable bundled package for what's being
  loaded. Do not require proof it's malicious (a traced network download)
  before counting this one — an app dynamically loading code whose origin
  you cannot confirm as its own bundled resource is exactly the
  second-stage-payload-dropper pattern this system exists to catch, and
  demanding a fully traced download chain before flagging it is how real
  droppers get missed. This item alone, even without a second indicator,
  is legitimate grounds for MALWARE at MEDIUM confidence.

Two or more items from the MEDIUM list above, naming concrete values and
destinations, are legitimate grounds for MALWARE at MEDIUM confidence — the
unresolved-origin DexClassLoader item is the one exception explicitly noted
above that can stand alone. Items from the CALIBRATION list never count
toward this, individually or stacked — if the only things you can point to
are baseline-noise items, the correct verdict is BENIGN, even if there are
many of them.

"Privacy-invasive" is not the same question as "malware," and this system
answers only the malware question. Aggressive tracking, lack of an explicit
consent dialog, frequent location polling, or broad data collection are
normal (if sometimes distasteful) behavior for real ad and analytics SDKs —
that is a grayware/PUP judgment, not evidence of malware, and is OUT OF
SCOPE here. If your own Application Purpose assessment concludes this is a
recognized legitimate category (ad network, analytics, game engine, utility
app) and the only things you can cite beyond that are vague words like
"privacy concern," "without consent," "could be misused," or "aggressive
tracking" — with no concrete indicator from the MEDIUM/HIGH list above —
the correct verdict is BENIGN. Do not let your own conclusion that the app
is legitimate coexist with a MALWARE verdict; if you write that the app's
purpose looks legitimate, that should be reflected in the final prediction,
not overridden by a restatement of the same baseline-noise APIs in more
alarming language.

{api_summaries}

Based on ALL the above API analysis results, provide your final assessment:

=== FINAL APPLICATION ANALYSIS ===

**Final Prediction:**
<MALWARE or BENIGN>

**Confidence:**
<HIGH, MEDIUM, or LOW>

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
   - `loadClass` or `newInstance` inside `android.support.*`, `androidx.*`, or `com.alibaba.fastjson.*` for fragment instantiation, view inflation, or JSON serialization.
   - Genuine Google Play Services SDK operations interacting with official system framework services WITHOUT loading unverified external DEX/JAR payloads from app-private files.
2. **Activity Routing, Native NDK Libraries & Commercial App Protectors**:
   - `System.loadLibrary` / `System.load` loading bundled native C/C++ shared libraries (e.g., Unity, Unreal, React Native, media decoders) from the APK's `lib/` directory is standard Android NDK behavior, NOT a dropper.
   - Modular navigation (e.g., `com.alibaba.android.arouter`) using reflection to find activities.
   - Commercial app protectors (e.g., `com.secneo`, `com.tencent.StubShell`, `com.qihoo.util`) that protect code integrity or load native libraries (`loadLibrary`) WITHOUT exfiltrating private user data.
3. **Local File & Network Operations**:
   - `openFileInput`, `openFileOutput`, `getExternalStorageDirectory` used for standard app caching or configuration.
   - `getActiveNetworkInfo`, `openConnection` for standard connectivity monitoring or REST API requests.
4. **Input Device ID**:
   - `getDeviceId` called on `android.view.InputDevice` or within `KeyEvent` handling (this is an input device identifier, NOT a telephony IMEI).

B. MALICIOUS INTENT PATTERNS (FLAG AS MALWARE):
1. **Dnotua & Anydown (Silent Downloaders / Disguised Droppers)**:
   - Dynamic class loading (`DexClassLoader`, `PathClassLoader`, `loadClass`) or reflection loading executable code from local files (`/data/data/`, cache, assets) or network streams.
   - NOTE: Dnotua frequently disguises its droppers inside spoofed Google Play Services (`com.google.android.gms.internal...`) or helper namespaces to evade analysis. If dynamic code loading or hidden payload execution is present, FLAG AS MALWARE.
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
#  HBCR — Cluster-Level Sub-Graph Reasoning
# =============================================================================
# Used when an APK exceeds the single-call token budget and is partitioned
# into graph-connected clusters. Each cluster is analyzed independently
# with full caller->callee context preserved within it, plus boundary
# bridge stubs for cross-cluster edges so the LLM knows connections exist.

CLUSTER_SYSTEM = (
    "You are a principal cybersecurity researcher specializing in Android static binary analysis. "
    "You are analyzing ONE connected subsystem (cluster) of an Android application's backward-sliced "
    "Control Flow Graphs (Jimple IR). This cluster contains functions that are connected by caller -> callee "
    "relationships or shared data-flow resources (file paths, crypto outputs, dynamic class targets).\n\n"
    "Your job is to produce a concise, evidence-based behavioral summary of THIS cluster only. "
    "Do NOT issue a final MALWARE/BENIGN verdict — that is done later when all clusters are combined. "
    "Focus on:\n"
    "1. What this subsystem DOES (its functional purpose).\n"
    "2. Whether any data flows from sensitive sources to network/execution sinks WITHIN this cluster.\n"
    "3. Whether any cross-cluster boundary calls suggest payload handoff to another subsystem.\n\n"
    "CALIBRATION: Reflection (forName, newInstance, invoke, getDeclaredMethod) for standard UI or lifecycle "
    "operations is baseline noise. HOWEVER, dynamic class loading (DexClassLoader, PathClassLoader, loadClass) "
    "or reflection executing runtime methods — even if disguised within com.google.android.gms.* or helper packages "
    "(frequently spoofed by Dnotua/Anydown trojan droppers) — MUST be flagged as HIGH RISK if it loads dynamic DEX/JAR payloads "
    "or executes hidden binary components."
)

CLUSTER_USER_TEMPLATE = """\
Analyze the following connected cluster of backward-sliced Control Flow Graphs (CFGs) \
from an Android application. These functions are grouped because they share caller -> callee \
call edges or data-flow resources (shared file paths, crypto outputs, class loading targets).

Cluster ID: {cluster_id}
Functions in this cluster: {func_count}
Suspicious APIs in this cluster: {api_list}
{boundary_info}

=== RAG KNOWLEDGE BASE MATCHES ===
{rag_context}
===================================

=== CLUSTER CFG CONTENT ===
{cluster_content}
=== END CLUSTER ===

Provide your analysis in EXACTLY this format:

CLUSTER_PURPOSE: <1-2 sentences: what does this subsystem do?>
SENSITIVE_DATA_FLOWS: <List any concrete data flows from sensitive sources to sinks, or "None detected">
SUSPICIOUS_INDICATORS: <List any concrete suspicious patterns (payload delivery, exfiltration, SMS fraud), or "None detected">
BENIGN_INDICATORS: <List evidence this is standard framework/SDK behavior, or "None">
RISK_LEVEL: <LOW / MEDIUM / HIGH with brief justification>
"""

# =============================================================================
#  HBCR — Global Synthesis (Holistic APK Verdict from Cluster Summaries)
# =============================================================================
# Combines all cluster summaries into one final MALWARE/BENIGN verdict.
# Uses the same calibrated baseline-noise rules as TIER3 and SINGLE_CALL.

SYNTHESIS_SYSTEM = (
    "You are a principal cybersecurity researcher making the FINAL malware/benign verdict "
    "for an Android application. You are given behavioral summaries of ALL connected subsystems "
    "(clusters) of the app, each already analyzed for suspicious data flows and indicators.\n\n"
    "DECISION METHODOLOGY:\n"
    "1. Review each cluster's findings holistically — a benign cluster and a malicious cluster "
    "can coexist in the same app (e.g., a legitimate game with a hidden payload dropper).\n"
    "2. Cross-cluster connections (boundary bridges) are critical: a download in Cluster A feeding "
    "into dynamic execution in Cluster B is the classic dropper pattern.\n"
    "3. Apply the same calibration rules: reflection, minified names, standard SDK behavior, and "
    "reading one sensitive value with no traced destination are baseline noise, not indicators.\n"
    "4. Issue MALWARE only when you can name SPECIFIC concrete indicators (exfiltration chains, "
    "payload delivery, SMS fraud, backdoor execution) with evidence from the cluster summaries.\n"
    "5. Issue BENIGN when cluster summaries show only standard framework/SDK behavior."
)

SYNTHESIS_USER_TEMPLATE = """\
You are making the FINAL verdict for an Android application. Below are the behavioral \
summaries of ALL {cluster_count} connected subsystems (clusters) found in this app.

=== CLUSTER SUMMARIES ===
{cluster_summaries}
=== END CLUSTER SUMMARIES ===

{cross_cluster_connections}

Based on ALL cluster summaries and their cross-cluster connections, provide your final assessment:

=== FINAL APPLICATION ANALYSIS ===

PREDICTION: <MALWARE or BENIGN>
CONFIDENCE: <HIGH, MEDIUM, or LOW>
APP_PURPOSE: <1-2 sentence description of what this app appears to do>
KEY_FINDINGS:
- <finding 1>
- <finding 2>
- <finding 3>
EVIDENCE: <2-3 sentences explaining your reasoning, citing specific clusters, data flows, or cross-cluster connections>
"""
