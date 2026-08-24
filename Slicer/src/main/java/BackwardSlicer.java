import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.GotoStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.IfStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.ParameterRef;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>Algorithm 1 — Backward Program Slicing, with inter-procedural
 * resolution</b> (as described in the LAMD paper, Section 3.2.2 / Appendix D).
 *
 * <h2>Goal</h2>
 * Given a suspicious API call site (the <em>slicing criterion</em>), compute
 * the minimal subset of Jimple statements that are <em>data-flow or
 * control-dependence</em> relevant to that call. This produces the "Sliced
 * CFG" that will be serialised and sent to the LLM.
 *
 * <h2>Two stages</h2>
 * <ol>
 *   <li><b>Intra-procedural slice</b> ({@link #slice(SliceCriterion)}): the
 *       original single-method BFS over data-flow and control-dependence
 *       predecessors.</li>
 *   <li><b>Inter-procedural resolution</b> ({@link #sliceInterProcedural}):
 *       per the paper's Appendix D — "If undeclared variables remain in a
 *       sliced function, inter-procedural backward slicing is recursively
 *       applied to its callers until all variables are resolved." A local is
 *       "undeclared" here exactly when its only reaching definition inside
 *       the slice is an {@link IdentityStmt} binding a method parameter
 *       ({@link ParameterRef}) — i.e. its value comes from outside the
 *       method. For each such parameter, {@link CallerIndex} finds every
 *       app-scope call site invoking this method, and the same intra-
 *       procedural slicing procedure is re-run there, seeded from the actual
 *       argument expression — recursively, bounded by depth/fan-in/budget
 *       caps so one heavily-called utility method can't blow up runtime.</li>
 * </ol>
 *
 * <h2>Soot classes used</h2>
 * <ul>
 *   <li>{@link ExceptionalUnitGraph} — intra-procedural CFG that models
 *       exceptional control flow (try/catch). Used for predecessor queries
 *       in the control-dependence step.</li>
 *   <li>{@link SimpleLocalDefs} — efficient, intra-procedural reaching-
 *       definition analysis. {@code getDefsOfAt(local, unit)} answers
 *       "which statements could have last defined {@code local} when
 *       execution reaches {@code unit}?"</li>
 *   <li>{@link InstanceInvokeExpr} — allows extraction of the implicit
 *       {@code this} / base-object receiver so it is also tracked backward.</li>
 * </ul>
 */
public final class BackwardSlicer {

    private BackwardSlicer() { /* static utility class */ }

    // Caps bounding the inter-procedural resolution so a heavily fanned-in
    // utility/wrapper method can't cause unbounded recursion or runtime blowup.
    private static final int MAX_DEPTH = 3;
    private static final int MAX_CALLERS_PER_PARAM = 5;
    private static final int MAX_TOTAL_CALLER_METHODS = 15;

    // ─────────────────────────────────────────────────────────────────────────
    // Result type for inter-procedural slicing
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * One method's contribution to an inter-procedural slice: either the
     * original method containing the suspicious call ({@code label ==
     * "callee"}), or a caller method whose slice resolves one of the
     * callee's undeclared parameters.
     */
    public static final class MethodSlice {
        private final SootMethod method;
        private final Set<Unit> units;
        private final String label;

        public MethodSlice(SootMethod method, Set<Unit> units, String label) {
            this.method = method;
            this.units = units;
            this.label = label;
        }

        public SootMethod getMethod() { return method; }
        public Set<Unit> getUnits() { return units; }
        public String getLabel() { return label; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — intra-procedural (original entry point, unchanged)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Computes the intra-procedural backward slice for a single suspicious
     * API call site.
     *
     * @param criterion the slicing seed produced by {@link ApiScanner}
     * @return set of all Jimple units in {@code criterion}'s own method that
     *         are data-flow or control-dependence relevant to the suspicious
     *         call
     */
    public static Set<Unit> slice(SliceCriterion criterion) {
        SootMethod method  = criterion.getMethod();
        Stmt       callSite = criterion.getCallSite();
        InvokeExpr ie       = criterion.getInvokeExpr();
        Body body = method.getActiveBody();

        Set<Local> seedRelevant = new HashSet<>();
        for (Value arg : ie.getArgs()) {
            if (arg instanceof Local) {
                seedRelevant.add((Local) arg);
            }
        }
        // Also seed: the base ("receiver") object for instance method calls.
        // e.g. for  $mgr.getDeviceId()  we also track $mgr backward.
        if (ie instanceof InstanceInvokeExpr) {
            Value base = ((InstanceInvokeExpr) ie).getBase();
            if (base instanceof Local) {
                seedRelevant.add((Local) base);
            }
        }

        return sliceCore(body, callSite, seedRelevant);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API — inter-procedural resolution
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Computes the intra-procedural slice for {@code criterion}, then
     * recursively resolves any undeclared (parameter-sourced) variables by
     * slicing into callers — per the paper's Appendix D. Best-effort: any
     * failure during the inter-procedural step leaves the intra-procedural
     * primary slice untouched and simply stops expanding further.
     *
     * @param criterion   the slicing seed produced by {@link ApiScanner}
     * @param callerIndex app-scope caller index from {@link CallerIndex#build()}
     * @return ordered list of {@link MethodSlice}s: element 0 is always the
     *         primary (callee) method; any further elements are resolved
     *         callers.
     */
    public static List<MethodSlice> sliceInterProcedural(
            SliceCriterion criterion,
            Map<SootMethod, List<CallerIndex.CallEdge>> callerIndex) {

        List<MethodSlice> results = new ArrayList<>();
        Set<Unit> primary = slice(criterion);
        results.add(new MethodSlice(criterion.getMethod(), primary, "callee"));

        try {
            Set<SootMethod> visited = new HashSet<>();
            visited.add(criterion.getMethod());
            int[] remainingBudget = { MAX_TOTAL_CALLER_METHODS };
            resolveCallers(criterion.getMethod(), primary, callerIndex, results, visited, 1, remainingBudget);
        } catch (Exception e) {
            // Best-effort: keep the intra-procedural primary slice on any failure.
        }

        return results;
    }

    /**
     * Finds locals in {@code methodSlice} whose only reaching definition is
     * an unresolved method parameter, and — for each — recursively slices
     * into every known caller of {@code method}, seeded from the actual
     * argument expression at that call site.
     */
    private static void resolveCallers(
            SootMethod method,
            Set<Unit> methodSlice,
            Map<SootMethod, List<CallerIndex.CallEdge>> callerIndex,
            List<MethodSlice> results,
            Set<SootMethod> visited,
            int depth,
            int[] remainingBudget) {

        if (depth > MAX_DEPTH || remainingBudget[0] <= 0) {
            return;
        }

        // An "undeclared variable" (paper's term) is exactly a local whose
        // defining unit — already present in the slice, since the intra-
        // procedural BFS walks every reaching definition backward — is an
        // IdentityStmt binding a formal parameter. Such a unit has no
        // further Local uses of its own, so the BFS naturally treats it as
        // a leaf: it can't resolve any further within this method.
        List<Integer> unresolvedParamIndices = new ArrayList<>();
        for (Unit u : methodSlice) {
            if (u instanceof IdentityStmt) {
                IdentityStmt id = (IdentityStmt) u;
                if (id.getRightOp() instanceof ParameterRef) {
                    unresolvedParamIndices.add(((ParameterRef) id.getRightOp()).getIndex());
                }
            }
        }
        if (unresolvedParamIndices.isEmpty()) {
            return;
        }

        List<CallerIndex.CallEdge> callers = callerIndex.get(method);
        if (callers == null || callers.isEmpty()) {
            return;
        }

        for (int paramIdx : unresolvedParamIndices) {
            int callersUsed = 0;
            for (CallerIndex.CallEdge edge : callers) {
                if (callersUsed >= MAX_CALLERS_PER_PARAM || remainingBudget[0] <= 0) {
                    break;
                }

                SootMethod callerMethod = edge.getCaller();
                if (visited.contains(callerMethod)) {
                    // Already resolved (or on the current recursion path) —
                    // skip to avoid cycles and redundant work.
                    continue;
                }

                InvokeExpr callerIe = edge.getInvokeExpr();
                List<Value> args = callerIe.getArgs();
                if (paramIdx < 0 || paramIdx >= args.size()) {
                    continue;
                }
                Value argVal = args.get(paramIdx);
                if (!(argVal instanceof Local)) {
                    // Constant / field / new-expr argument — nothing further
                    // to trace backward; the value itself IS the answer and
                    // is already visible at the call site once we include it.
                    continue;
                }

                Body callerBody;
                try {
                    callerBody = callerMethod.getActiveBody();
                } catch (Exception e) {
                    continue;
                }

                Set<Local> seedRelevant = new HashSet<>();
                seedRelevant.add((Local) argVal);
                Set<Unit> callerSlice;
                try {
                    callerSlice = sliceCore(callerBody, edge.getCallSite(), seedRelevant);
                } catch (Exception e) {
                    continue;
                }

                visited.add(callerMethod);
                remainingBudget[0]--;
                callersUsed++;

                results.add(new MethodSlice(
                        callerMethod, callerSlice,
                        "caller, resolves parameter p" + paramIdx + " of " + method.getName()));

                resolveCallers(callerMethod, callerSlice, callerIndex, results, visited, depth + 1, remainingBudget);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Shared BFS core (used by both the primary slice and caller resolution)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Runs the backward BFS (data-flow + control-dependence) within a single
     * method body, starting from {@code seedUnit} with {@code seedRelevant}
     * as the initial set of relevant locals.
     */
    private static Set<Unit> sliceCore(Body body, Unit seedUnit, Set<Local> seedRelevant) {
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        SimpleLocalDefs      defs  = new SimpleLocalDefs(graph);

        Set<Unit>   slice          = new LinkedHashSet<>();
        Set<Local>  relevantLocals = new HashSet<>(seedRelevant);
        Deque<Unit> worklist       = new ArrayDeque<>();

        slice.add(seedUnit);
        worklist.add(seedUnit);

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
     * executed. Including it in the slice preserves the conditional structure
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
