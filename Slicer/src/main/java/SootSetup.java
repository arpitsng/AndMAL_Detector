import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.options.Options;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Bootstraps the Soot framework for Android APK analysis.
 *
 * <h2>Configuration choices</h2>
 * <ul>
 *   <li><b>src_prec_apk</b> — tells Soot the input is an Android APK (DEX
 *       bytecode), not .class files or .java source.</li>
 *   <li><b>android_jars</b> — path to the Android SDK {@code platforms/}
 *       directory. Soot picks the correct {@code android.jar} stub based
 *       on the APK's {@code targetSdkVersion}.</li>
 *   <li><b>whole_program</b> — enables call-graph construction and
 *       points-to analysis. Required so that {@code Scene.v().getCallGraph()}
 *       is available for future inter-procedural extensions.</li>
 *   <li><b>allow_phantom_refs</b> — allows classes that are referenced but
 *       not resolvable (e.g. Android framework internals) to exist as
 *       "phantom" stubs. Essential for real APKs.</li>
 *   <li><b>no_bodies_for_excluded</b> — combined with {@link #FRAMEWORK_PACKAGES},
 *       prevents Soot from loading method bodies for Android/Java framework
 *       classes, keeping analysis fast.</li>
 *   <li><b>output_format_none</b> — we only need the in-memory IR;
 *       Soot should not write any .class / .dex files.</li>
 * </ul>
 */
public final class SootSetup {

    private SootSetup() { /* static utility class */ }

    /**
     * Android/Java framework packages whose method bodies we do NOT need.
     * Soot creates phantom stub entries for these (signatures only), which
     * is sufficient for recognising calls like {@code TelephonyManager.getDeviceId()}.
     */
    private static final List<String> FRAMEWORK_PACKAGES = Arrays.asList(
            "java.",
            "javax.",
            "sun.",
            "com.sun.",
            "android.",
            "androidx.",
            "dalvik.",
            "org.apache.",
            "org.w3c.",
            "org.xml.",
            "com.google.android."
    );

    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Configures Soot options and loads all necessary classes from the APK.
     *
     * <p>Must be called before {@link #run()} and before any Soot analysis
     * (e.g. {@link ApiScanner#scan()}).
     *
     * @param apkPath         path to the {@code .apk} file to analyse
     * @param androidJarsPath path to the Android SDK {@code platforms/} directory
     *                        (e.g. {@code C:\Users\me\AppData\Local\Android\Sdk\platforms})
     */
    public static void configure(String apkPath, String androidJarsPath) {
        G.reset(); // clear any previous Soot state

        Options opts = Options.v();

        // ── Source format ──────────────────────────────────────────────────────
        opts.set_src_prec(Options.src_prec_apk);
        opts.set_process_dir(Collections.singletonList(apkPath));
        opts.set_android_jars(androidJarsPath);

        // ── Analysis scope ─────────────────────────────────────────────────────
        opts.set_whole_program(true);           // build call graph
        opts.set_allow_phantom_refs(true);      // tolerate missing stubs
        opts.set_no_bodies_for_excluded(true);  // skip framework body loading
        opts.set_exclude(FRAMEWORK_PACKAGES);

        // ── Output ─────────────────────────────────────────────────────────────
        opts.set_output_format(Options.output_format_none); // no file output

        // ── Jimple IR options ──────────────────────────────────────────────────
        // Preserve original variable names where possible (aids LLM readability).
        opts.setPhaseOption("jb", "use-original-names:true");

        // ── Verbosity ──────────────────────────────────────────────────────────
        opts.set_verbose(false); // suppress Soot's internal progress messages

        Scene.v().loadNecessaryClasses();
        System.out.println("[*] Soot configured. Necessary classes loaded.");
    }

    /**
     * Executes Soot's analysis pack pipeline (body construction, call-graph
     * building, etc.).
     *
     * <p>After this returns, all application-class bodies are available via
     * {@code method.getActiveBody()} and the call graph is available via
     * {@code Scene.v().getCallGraph()}.
     */
    public static void run() {
        System.out.println("[*] Running Soot analysis packs...");
        PackManager.v().runPacks();
        System.out.println("[*] Soot packs complete. "
                + Scene.v().getApplicationClasses().size()
                + " application class(es) loaded.");
    }
}
