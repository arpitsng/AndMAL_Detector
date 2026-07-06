import soot.Unit;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Entry point for the LAMD backward-slicing pipeline.
 *
 * <p>Workflow:
 * <ol>
 *   <li>Configure Soot for APK analysis ({@link SootSetup}).</li>
 *   <li>Run Soot packs to build method bodies and call graph.</li>
 *   <li>Scan all application classes for suspicious API call sites ({@link ApiScanner}).</li>
 *   <li>Compute the backward slice for each call site ({@link BackwardSlicer}).</li>
 *   <li>Serialise all sliced CFGs to a text file ({@link CfgSerializer}).</li>
 * </ol>
 *
 * <p>Usage:
 * <pre>
 *   java -Xmx4g -jar slicer-1.0.jar &lt;apk_path&gt; &lt;output_txt_file&gt; [android_jars_path]
 * </pre>
 *
 * <p>If {@code android_jars_path} is omitted, the program checks the
 * {@code ANDROID_HOME} environment variable and falls back to a common
 * default Windows path.
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3) {
            System.err.println(
                "Usage: java Main <apk_path> <output_txt_file> [android_jars_path]\n\n"
              + "  apk_path           Path to the .apk file to analyse.\n"
              + "  output_txt_file    Destination for the serialised sliced CFGs.\n"
              + "  android_jars_path  (Optional) Android SDK platforms/ directory.\n"
              + "                     Defaults to ANDROID_HOME/platforms or\n"
              + "                     %LOCALAPPDATA%\\Android\\Sdk\\platforms."
            );
            System.exit(1);
        }

        String apkPath        = args[0];
        String outputTxtFile  = args[1];
        String androidJarsPath = resolveAndroidJars(args.length >= 3 ? args[2] : null);

        System.out.println("============================================================");
        System.out.println("  LAMD Slicer — Backward Slicing Pipeline");
        System.out.println("============================================================");
        System.out.println("  APK          : " + apkPath);
        System.out.println("  Output       : " + outputTxtFile);
        System.out.println("  Android JARs : " + androidJarsPath);
        System.out.println("============================================================");
        System.out.println();

        // ── Step 1: Configure and run Soot ────────────────────────────────────
        SootSetup.configure(apkPath, androidJarsPath);
        SootSetup.run();
        System.out.println();

        // ── Step 2: Scan for suspicious API call sites ────────────────────────
        System.out.println("[*] Scanning for suspicious API call sites...");
        List<SliceCriterion> criteria = ApiScanner.scan();
        System.out.println("[*] Found " + criteria.size() + " suspicious call site(s).");
        System.out.println();

        if (criteria.isEmpty()) {
            System.out.println("[*] No suspicious APIs found. Writing empty output.");
            try {
                Path outPath = Paths.get(outputTxtFile);
                java.nio.file.Files.createDirectories(outPath.getParent());
                java.nio.file.Files.write(outPath,
                    "NO_SUSPICIOUS_APIS_FOUND\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (IOException e) {
                System.err.println("[ERROR] Cannot write output: " + e.getMessage());
                System.exit(1);
            }
            return;
        }

        // ── Step 3: Backward-slice each call site ─────────────────────────────
        System.out.println("[*] Computing backward slices...");
        List<CfgSerializer.SliceResult> results = new ArrayList<>();
        int done = 0;

        for (SliceCriterion criterion : criteria) {
            done++;
            try {
                Set<Unit> slice = BackwardSlicer.slice(criterion);
                results.add(new CfgSerializer.SliceResult(criterion, slice));
                System.out.printf("  [%d/%d] Sliced: %s (%d units)%n",
                        done, criteria.size(), criterion, slice.size());
            } catch (Exception e) {
                System.err.printf("  [%d/%d] FAILED: %s — %s%n",
                        done, criteria.size(), criterion, e.getMessage());
            }
        }

        System.out.println("[*] Slicing complete. " + results.size()
                + " of " + criteria.size() + " succeeded.");
        System.out.println();

        // ── Step 4: Serialise to output file ──────────────────────────────────
        System.out.println("[*] Writing sliced CFGs to: " + outputTxtFile);
        try {
            CfgSerializer.write(results, Paths.get(outputTxtFile));
            System.out.println("[*] Done. " + results.size() + " sliced CFG(s) written.");
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to write output: " + e.getMessage());
            System.exit(1);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Android SDK resolution
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Resolves the Android SDK {@code platforms/} directory.
     * Priority: explicit CLI arg → ANDROID_HOME env → default Windows path.
     */
    private static String resolveAndroidJars(String explicit) {
        if (explicit != null && !explicit.isEmpty()) {
            return explicit;
        }

        // Try ANDROID_HOME environment variable
        String androidHome = System.getenv("ANDROID_HOME");
        if (androidHome == null || androidHome.isEmpty()) {
            androidHome = System.getenv("ANDROID_SDK_ROOT");
        }
        if (androidHome != null && !androidHome.isEmpty()) {
            return androidHome + java.io.File.separator + "platforms";
        }

        // Default Windows path
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData != null) {
            return localAppData + "\\Android\\Sdk\\platforms";
        }

        // Last resort
        return "platforms";
    }
}
