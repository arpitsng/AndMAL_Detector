import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * <b>Algorithm 1 — Intra-procedural Backward Program Slicing</b>
 * (as described in the LAMD paper, Section 3.1).
 *
 * <h2>Goal</h2>
 * Given a suspicious API call site (the <em>slicing criterion</em>), compute
 * the minimal subset of Jimple statements inside the same method that are
 * <em>data-flow or control-dependence</em> relevant to that call.  This
 * produces the "Sliced CFG" that will be serialised and sent to the LLM.
 *
 * <h2>Algorithm (pseudo-code)</h2>
 * <pre>
 * Input:  criterion = (method, callSite, suspiciousCall)
 * Output: slice  — set of relevant {@link Unit}s
 *
 * slice    ← { callSite }
 * relevant ← args(suspiciousCall) ∪ { base object if instance invoke }
 * worklist ← { callSite }
 *
 * while worklist ≠ ∅:
 *   unit ← pop(worklist)
 *
 *   // ── Data-flow backward step ──────────────────────────────────────
 *   for each Value v used in unit  where  v ∈ relevant:
 *     for each defUnit that defines v and reaches unit (SimpleLocalDefs):
 *       if defUnit ∉ slice:
 *         slice.add(defUnit)
 *         worklist.add(defUnit)
 *         add all Local values used in defUnit to relevant
 *
 *   // ── Control-dependence step ──────────────────────────────────────
 *   for each predecessor pred of unit in the CFG:
 *     if pred is IfStmt or GotoStmt and pred ∉ slice:
 *       slice.add(pred)
 *       worklist.add(pred)
 * </pre>
 *
 * <h2>Soot classes used</h2>
 * <ul>
 *   <li>{@link ExceptionalUnitGraph} — intra-procedural CFG that models
 *       exceptional control flow (try/catch). Used for predecessor queries
 *       in the control-dependence step.</li>
 *   <li>{@link SimpleLocalDefs} — efficient, intra-procedural reaching-
 *       definition analysis.  {@code getDefsOfAt(local, unit)} answers
 *       "which statements could have last defined {@code local} when
 *       execution reaches {@code unit}?"</li>
 *   <li>{@link InstanceInvokeExpr} — allows extraction of the implicit
 *       {@code this} / base-object receiver so it is also tracked backward.</li>
 * </ul>
 *
 * <h2>Scope</h2>
 * Analysis is <em>intra-procedural</em>: the slicer does not follow call
 * edges into other methods.  This is sufficient for the majority of Android
 * privacy leaks and keeps analysis tractable on large APKs.
 */
public final class BackwardSlicer {

    private BackwardSlicer() { /* static utility class */ }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Computes the backward slice for a single suspicious API call site.
     *
     * <p>The returned set is ordered by insertion (a {@link LinkedHashSet}),
     * preserving roughly the BFS discovery order which approximates reverse
     * data-flow order.  {@link CfgSerializer} re-sorts by unit position when
     * emitting NODE lines.
     *
     * @param criterion the slicing seed produced by {@link ApiScanner}
     * @return set of all Jimple units that are data-flow or control-dependence
     *         relevant to the suspicious call
     */
    public static Set<Unit> slice(SliceCriterion criterion) {
        SootMethod method  = criterion.getMethod();
        Stmt       callSite = criterion.getCallSite();
        InvokeExpr ie       = criterion.getInvokeExpr();

        Body body = method.getActiveBody();

        // ── Build intra-procedural analysis structures ────────────────────────
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        SimpleLocalDefs      defs  = new SimpleLocalDefs(graph);

        // ── Initialise the worklist, slice, and relevant-variable set ─────────
        Set<Unit>   slice          = new LinkedHashSet<>();
        Set<Local>  relevantLocals = new HashSet<>();
        Deque<Unit> worklist       = new ArrayDeque<>();

        // Seed: the call site itself is always in the slice.
        slice.add(callSite);
        worklist.add(callSite);

        // Seed relevant locals: the arguments passed to the suspicious call.
        // These are the variables whose definitions we want to trace backward.
        for (Value arg : ie.getArgs()) {
            if (arg instanceof Local) {
                relevantLocals.add((Local) arg);
            }
        }

        // Also seed: the base ("receiver") object for instance method calls.
        // e.g. for  $mgr.getDeviceId()  we also track $mgr backward.
        if (ie instanceof InstanceInvokeExpr) {
            Value base = ((InstanceInvokeExpr) ie).getBase();
            if (base instanceof Local) {
                relevantLocals.add((Local) base);
            }
        }

        // ── Main backward traversal (BFS) ─────────────────────────────────────
        while (!worklist.isEmpty()) {
            Unit unit = worklist.poll();

            performDataFlowStep(unit, graph, defs, slice, relevantLocals, worklist);
            performControlDependenceStep(unit, graph, slice, worklist);
        }

        return slice;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Algorithm sub-steps
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Data-flow backward step.
     *
     * <p>For every {@link Local} variable <em>used</em> in {@code unit} that is
     * currently in {@code relevantLocals}, find all definitions of that variable
     * that reach {@code unit} (via {@link SimpleLocalDefs#getDefsOfAt}) and add
     * them to the slice.
     *
     * <p>Transitivity: every local variable used in a newly added definition
     * is itself added to {@code relevantLocals} so that the next BFS iteration
     * will trace those definitions backward too.
     */
    private static void performDataFlowStep(
            Unit             unit,
            ExceptionalUnitGraph graph,
            SimpleLocalDefs  defs,
            Set<Unit>        slice,
            Set<Local>       relevantLocals,
            Deque<Unit>      worklist) {

        // Collect all local variables used in this unit.
        // We work on a snapshot list to avoid issues with the underlying iterator.
        List<ValueBox> useBoxes = new ArrayList<>(unit.getUseBoxes());

        for (ValueBox vb : useBoxes) {
            Value v = vb.getValue();

            if (!(v instanceof Local)) {
                // Constants, fields, and expression sub-terms are not tracked
                // by SimpleLocalDefs, so skip them.
                continue;
            }

            Local local = (Local) v;
            if (!relevantLocals.contains(local)) {
                // This local is not currently relevant — ignore it.
                continue;
            }

            // Ask SimpleLocalDefs: which statements could have last defined
            // 'local' on a path leading to 'unit'?
            List<Unit> defUnits;
            try {
                defUnits = defs.getDefsOfAt(local, unit);
            } catch (Exception e) {
                // Defensive: some Soot versions throw on phi-node edge cases.
                continue;
            }

            for (Unit defUnit : defUnits) {
                if (slice.contains(defUnit)) {
                    continue; // already visited
                }

                slice.add(defUnit);
                worklist.add(defUnit);

                // Transitivity: add all locals used inside this definition
                // to the relevant set so we keep chasing the data chain.
                for (ValueBox defVb : defUnit.getUseBoxes()) {
                    Value defVal = defVb.getValue();
                    if (defVal instanceof Local) {
                        relevantLocals.add((Local) defVal);
                    }
                }
            }
        }
    }

    /**
     * Control-dependence step.
     *
     * <p>If a branch statement (if / goto) is an immediate predecessor of
     * {@code unit} in the CFG, that branch controls whether {@code unit} is
     * executed.  Including it in the slice preserves the conditional structure
     * of the CFG that the LLM needs to understand the program's logic.
     *
     * <p>Example: if an {@code if-eq} guards the block that calls
     * {@code getDeviceId()}, that {@code if-eq} statement is relevant.
     */
    private static void performControlDependenceStep(
            Unit             unit,
            ExceptionalUnitGraph graph,
            Set<Unit>        slice,
            Deque<Unit>      worklist) {

        for (Unit pred : graph.getPredsOf(unit)) {
            if (slice.contains(pred)) {
                continue;
            }
            // Include branch predecessors to preserve CFG structure.
            if (pred instanceof IfStmt || pred instanceof GotoStmt) {
                slice.add(pred);
                worklist.add(pred);
            }
        }
    }
}