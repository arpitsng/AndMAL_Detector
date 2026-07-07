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
    }
    if api_name in TRANSFER_APIS:
        return "transfer"
    return "access"
