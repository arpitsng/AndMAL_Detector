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
            "query"
    ));

    // ── 3. Declaring-class name fragments for context matching ─────────────────

    private static final Set<String> SENSITIVE_CLASS_FRAGMENTS = new HashSet<>(Arrays.asList(
            "TelephonyManager",
            "LocationManager",
            "SmsManager",
            "NetworkInfo",
            "ConnectivityManager",
            "WifiManager",
            "WifiInfo",
            "Runtime",
            "Cipher",
            "ContentResolver",
            "PackageManager",
            "MediaRecorder",
            "Camera",
            "CameraManager",
            "Environment",
            "Context"          // openFileOutput, openFileInput
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

        // Context-dependent: only suspicious when declared in a sensitive class
        if (CONTEXT_DEPENDENT_NAMES.contains(name)) {
            String className = method.getDeclaringClass().getName();
            for (String fragment : SENSITIVE_CLASS_FRAGMENTS) {
                if (className.contains(fragment)) {
                    return true;
                }
            }
        }

        return false;
    }
}
