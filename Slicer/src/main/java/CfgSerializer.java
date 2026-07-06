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
     * Writes all sliced CFGs for a single APK into {@code outputPath}.
     *
     * @param results    list of (criterion, slice) pairs produced by the
     *                   analysis pipeline
     * @param outputPath destination text file
     * @throws IOException if the file cannot be written
     */
    public static void write(List<SliceResult> results, Path outputPath)
            throws IOException {

        Files.createDirectories(outputPath.getParent());

        try (BufferedWriter w = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
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
        Set<Unit> slice          = sr.getSlice();
        SootMethod method        = criterion.getMethod();
        Body body                = method.getActiveBody();

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

        w.write("=== END FUNCTION ===");
        w.newLine();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Result holder
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Simple pair of a slicing criterion and its computed slice.
     */
    public static final class SliceResult {
        private final SliceCriterion criterion;
        private final Set<Unit> slice;

        public SliceResult(SliceCriterion criterion, Set<Unit> slice) {
            this.criterion = criterion;
            this.slice     = slice;
        }

        public SliceCriterion getCriterion() { return criterion; }
        public Set<Unit>      getSlice()     { return slice; }
    }
}
