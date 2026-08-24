import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Serialises the result of {@link BackwardSlicer} into a structured text
 * format that the LLM can parse during tier-wise code reasoning.
 *
 * <h2>Output format (per sliced criterion)</h2>
 * <pre>
 * === FUNCTION: com.example.Foo.bar ===
 * SUSPICIOUS_API: getDeviceId
 * NODE 1: $r1 = virtualinvoke $r0.&lt;...TelephonyManager: ...&gt;()
 * NODE 2: $r3 = $r1
 * EDGE: 1 -> 2
 * === END FUNCTION ===
 * </pre>
 *
 * <p>Nodes are emitted in <em>program order</em> (the order they appear in
 * the method body), which preserves control-flow readability for the LLM.
 * Only units that are part of the slice are emitted as NODE lines.
 * Edges are derived from the intra-procedural CFG restricted to slice units.
 */
public final class CfgSerializer {

    private CfgSerializer() { /* static utility class */ }

    /**
     * Bump whenever a change to SuspiciousApiList.java, SootSetup.java, or
     * this serializer changes what ends up in the output for the SAME apk
     * (new seed APIs, multidex support, filtering fixes, etc.). This is how
     * find_stale_cfgs.py tells "extracted with the current logic" apart from
     * "extracted before a fix that matters" without needing a separate
     * manifest file to stay in sync with extracted_cfgs/ across machines —
     * the version travels with the CFG file itself, which matters given
     * these get merged across multiple laptops/servers via git.
     *
     * v3: BackwardSlicer now resolves undeclared (parameter-sourced)
     * variables inter-procedurally into callers (paper Appendix D). A slice
     * can now span multiple methods; see writeOneSlice()'s "--- METHOD ---"
     * sub-sections.
     * v4: SuspiciousApiList now also seeds on ClipboardManager.getPrimaryClip
     * — the paper's own named example (Section 3.2.1) of a sensitive API
     * that bypasses permission enforcement.
     */
    public static final int SLICER_VERSION = 4;

    /**
     * Writes all sliced CFGs for a single APK into {@code outputPath}.
     *
     * @param results    list of (criterion, slice) pairs produced by the
     *                   analysis pipeline
     * @param outputPath destination text file
     * @throws IOException if the file cannot be written
     */
    public static void write(List<SliceResult> results, Path outputPath)
            throws IOException {

        Path parent = outputPath.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter w = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            w.write("=== SLICER_VERSION: " + SLICER_VERSION + " ===");
            w.newLine();
            for (SliceResult sr : results) {
                writeOneSlice(w, sr);
                w.newLine();
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Internal
    // ─────────────────────────────────────────────────────────────────────────

    private static void writeOneSlice(BufferedWriter w, SliceResult sr)
            throws IOException {

        SliceCriterion criterion = sr.getCriterion();
        List<BackwardSlicer.MethodSlice> methodSlices = sr.getMethodSlices();
        SootMethod method        = criterion.getMethod();

        // ── Header ───────────────────────────────────────────────────────────
        String methodSig = method.getDeclaringClass().getName()
                + "." + method.getName();
        String apiName;
        try {
            apiName = criterion.getInvokeExpr().getMethod().getName();
        } catch (Exception e) {
            apiName = "UNKNOWN";
        }

        w.write("=== FUNCTION: " + methodSig + " ===");
        w.newLine();
        w.write("SUSPICIOUS_API: " + apiName);
        w.newLine();

        // Only emit "--- METHOD ---" sub-headers when the slice actually
        // spans more than one method (inter-procedural resolution kicked
        // in). The common single-method case stays byte-identical to the
        // pre-v3 output shape.
        boolean multiMethod = methodSlices.size() > 1;
        for (BackwardSlicer.MethodSlice ms : methodSlices) {
            if (multiMethod) {
                String subSig = ms.getMethod().getDeclaringClass().getName()
                        + "." + ms.getMethod().getName();
                w.write("--- METHOD: " + subSig + " (" + ms.getLabel() + ") ---");
                w.newLine();
            }
            writeMethodSlice(w, ms.getMethod(), ms.getUnits());
        }

        w.write("=== END FUNCTION ===");
        w.newLine();
    }

    /**
     * Emits NODE/EDGE lines for one method's contribution to a slice.
     * Node IDs restart at 1 for each method — safe because the Python
     * consumer only collects NODE/EDGE lines as text, it doesn't build a
     * cross-method graph object.
     */
    private static void writeMethodSlice(BufferedWriter w, SootMethod method, Set<Unit> slice)
            throws IOException {
        Body body = method.getActiveBody();

        // ── Build program-order node list ─────────────────────────────────────
        // Walk body units in their original order; assign sequential IDs only
        // to units that are part of the slice.
        List<Unit> orderedSliceUnits = new ArrayList<>();
        Map<Unit, Integer> unitToId  = new LinkedHashMap<>();
        int nodeId = 1;
        for (Unit u : body.getUnits()) {
            if (slice.contains(u)) {
                orderedSliceUnits.add(u);
                unitToId.put(u, nodeId++);
            }
        }

        // ── Emit NODE lines ──────────────────────────────────────────────────
        for (Unit u : orderedSliceUnits) {
            int id = unitToId.get(u);
            // Jimple's toString() gives a compact, readable representation.
            w.write("NODE " + id + ": " + u.toString());
            w.newLine();
        }

        // ── Emit EDGE lines ──────────────────────────────────────────────────
        // Build a mini-CFG restricted to slice units.
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        for (Unit u : orderedSliceUnits) {
            int fromId = unitToId.get(u);
            for (Unit succ : graph.getSuccsOf(u)) {
                Integer toId = unitToId.get(succ);
                if (toId != null) {
                    w.write("EDGE: " + fromId + " -> " + toId);
                    w.newLine();
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Result holder
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Pair of a slicing criterion and its computed (possibly inter-
     * procedural, multi-method) slice.
     */
    public static final class SliceResult {
        private final SliceCriterion criterion;
        private final List<BackwardSlicer.MethodSlice> methodSlices;

        public SliceResult(SliceCriterion criterion, List<BackwardSlicer.MethodSlice> methodSlices) {
            this.criterion = criterion;
            this.methodSlices = methodSlices;
        }

        public SliceCriterion getCriterion() { return criterion; }
        public List<BackwardSlicer.MethodSlice> getMethodSlices() { return methodSlices; }
    }
}
