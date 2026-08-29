import soot.SootMethod;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Catalogue of privacy-sensitive / dangerous Android APIs used as the
 * <b>seed set</b> (slicing criteria) for Algorithm 1.
 *
 * <h2>Matching strategy</h2>
 * <ol>
 *   <li>If the callee method name is in {@link #UNAMBIGUOUS_NAMES}, it is
 *       flagged regardless of the declaring class (these names are unique
 *       enough that false positives are very rare).</li>
 *   <li>If the method name is in {@link #CONTEXT_DEPENDENT_NAMES} <em>and</em>
 *       the declaring class name contains a known sensitive Android class
 *       fragment, it is flagged. This avoids, e.g., flagging every {@code query()}
 *       or {@code update()} call in the application.</li>
 * </ol>
 *
 * <p>Categories covered (per the LAMD paper's threat model):
 * <ul>
 *   <li>Device / subscriber identifiers</li>
 *   <li>Location tracking</li>
 *   <li>SMS / telephony exfiltration</li>
 *   <li>Network state enumeration</li>
 *   <li>File-system access</li>
 *   <li>Cryptographic operations (used for encoding exfiltrated data)</li>
 *   <li>Java reflection (code hiding / dynamic loading)</li>
 *   <li>Native process execution</li>
 *   <li>Camera / microphone recording</li>
 *   <li>Installed-package enumeration</li>
 *   <li>Network exfiltration (URL/URLConnection/Socket data sinks)</li>
 *   <li>Dynamic dex/class loading (DexClassLoader, PathClassLoader —
 *       second-stage payload droppers)</li>
 * </ul>
 */
public final class SuspiciousApiList {

    private SuspiciousApiList() { /* static utility class */ }

    // ── 1. Unambiguously suspicious method names ───────────────────────────────
    //    These are specific enough that we flag them regardless of declaring class.

    private static final Set<String> UNAMBIGUOUS_NAMES = new HashSet<>(Arrays.asList(
            // Device / subscriber identifiers
            "getDeviceId",
            "getSubscriberId",
            "getSimSerialNumber",
            "getLine1Number",
            "getImei",
            "getMeid",
            "getAndroidId",

            // SMS / telephony exfiltration
            "sendTextMessage",
            "sendMultipartTextMessage",
            "sendDataMessage",

            // Location (usually only called by location managers)
            "getLastKnownLocation",
            "requestLocationUpdates",

            // Java reflection (strongly associated with code hiding)
            "forName",
            "getDeclaredMethod",
            "getDeclaredField",
            "invoke",
            "newInstance",

            // Native / process execution
            "exec",
            "loadLibrary",
            "load",

            // Camera / microphone
            "startRecording",
            "takePicture",

            // Package enumeration
            "getInstalledPackages",
            "getInstalledApplications"
    ));

    // ── 2. Context-dependent names ─────────────────────────────────────────────
    //    These are common names flagged ONLY when the declaring class is sensitive.

    private static final Set<String> CONTEXT_DEPENDENT_NAMES = new HashSet<>(Arrays.asList(
            // Network (only from ConnectivityManager / WifiManager)
            "getNetworkInfo",
            "getActiveNetworkInfo",
            "getMacAddress",
            "getConnectionInfo",

            // Telephony (carrier/country fingerprinting — used to target attacks)
            "getSimOperator",

            // File-system (only from Context / Environment)
            "openFileOutput",
            "openFileInput",
            "getExternalStorageDirectory",
            "getExternalFilesDir",

            // Cryptographic operations (only from Cipher)
            "doFinal",
            "update",

            // Reflection — getMethod can appear in logging frameworks too
            "getMethod",

            // Content provider (contacts, call-log, SMS inbox, etc.)
            "query",

            // Clipboard access — the paper's own named example (Section 3.2.1)
            // of a sensitive API that bypasses permission enforcement.
            "getPrimaryClip"
    ));

    // ── 2b. Context-dependent names with a NARROW, dedicated fragment gate ─────
    //    IMPORTANT: these must NOT share SENSITIVE_CLASS_FRAGMENTS below. That
    //    set contains broad generic words ("Runtime", "Context", "Environment")
    //    that were tuned for rare method names — but "<init>" matches EVERY
    //    constructor call in the codebase, so gating it against a broad shared
    //    fragment set causes catastrophic over-matching (e.g. "Runtime" matches
    //    `RuntimeRemoteException`, `IllegalRuntimeException`, etc. — completely
    //    unrelated to Runtime.exec()). Verified against a real validation run:
    //    this exact bug flooded results with irrelevant constructor calls.
    //    Each entry here gets its OWN narrow fragment set instead.

    private static final Set<String> CLASS_LOADING_NAMES = new HashSet<>(Arrays.asList(
            "loadClass",
            "<init>"
    ));
    private static final Set<String> CLASS_LOADING_FRAGMENTS = new HashSet<>(Arrays.asList(
            "ClassLoader"  // DexClassLoader, PathClassLoader, InMemoryDexClassLoader, URLClassLoader
    ));

    private static final Set<String> NETWORK_EXFIL_NAMES = new HashSet<>(Arrays.asList(
            "openConnection",
            "connect",
            "getOutputStream"
    ));
    private static final Set<String> NETWORK_EXFIL_FRAGMENTS = new HashSet<>(Arrays.asList(
            "URL",     // URL, URLConnection, HttpURLConnection, HttpsURLConnection
            "Socket"   // Socket, SSLSocket, BluetoothSocket
    ));

    // ── 3. Declaring-class name fragments for context matching ─────────────────

    private static final Set<String> SENSITIVE_CLASS_FRAGMENTS = new HashSet<>(Arrays.asList(
            "Context",          // openFileOutput, openFileInput
            "ContextWrapper",   // openFileOutput, openFileInput
            "ClipboardManager"  // getPrimaryClip
    ));

    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Returns {@code true} if {@code method} represents a suspicious /
     * privacy-sensitive Android API call that should be used as a slicing seed.
     *
     * @param method the callee {@link SootMethod} extracted from an
     *               {@link soot.jimple.InvokeExpr}
     * @return {@code true} when the call should trigger backward slicing
     */
    public static boolean isSuspicious(SootMethod method) {
        String name = method.getName();

        // Fast-path: unambiguously suspicious regardless of class
        if (UNAMBIGUOUS_NAMES.contains(name)) {
            return true;
        }

        String className = null;  // computed lazily, at most once

        // Context-dependent: only suspicious when declared in a sensitive class
        if (CONTEXT_DEPENDENT_NAMES.contains(name)) {
            className = method.getDeclaringClass().getName();
            for (String fragment : SENSITIVE_CLASS_FRAGMENTS) {
                if (className.contains(fragment)) {
                    return true;
                }
            }
        }

        if (CLASS_LOADING_NAMES.contains(name)) {
            if (className == null) {
                className = method.getDeclaringClass().getName();
            }
            for (String fragment : CLASS_LOADING_FRAGMENTS) {
                if (className.contains(fragment)) {
                    return true;
                }
            }
        }

        if (NETWORK_EXFIL_NAMES.contains(name)) {
            if (className == null) {
                className = method.getDeclaringClass().getName();
            }
            for (String fragment : NETWORK_EXFIL_FRAGMENTS) {
                if (className.contains(fragment)) {
                    return true;
                }
            }
        }

        return false;
    }
}
