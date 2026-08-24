import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Lightweight, app-scope-only caller index: maps a callee {@link SootMethod}
 * to every call site within application classes that invokes it.
 *
 * <h2>Why not Soot's whole-program call graph</h2>
 * {@link SootSetup} deliberately keeps {@code whole_program} disabled — an
 * earlier attempt at enabling Soot's CHA/Spark call graph caused crashes on
 * large real-world APKs (see the comment on {@code set_whole_program(false)}).
 * This index covers exactly what {@link BackwardSlicer} needs for inter-
 * procedural resolution (finding which app methods call a given app method)
 * by reusing the same direct-invoke-resolution approach {@link ApiScanner}
 * already uses to find suspicious calls, without triggering whole-program
 * analysis or its associated crash risk.
 *
 * <p>Limitation: only *statically resolvable* invokes are captured (where
 * {@code InvokeExpr#getMethod()} succeeds). Virtual dispatch through an
 * interface/overridden method whose exact receiver type Soot cannot resolve
 * intra-procedurally is not captured. The caller-resolution step in
 * {@link BackwardSlicer} is best-effort by design — this matches the paper's
 * "recursively resolve callers until variables are resolved" intent without
 * requiring a full points-to analysis.
 */
public final class CallerIndex {

    private CallerIndex() { /* static utility class */ }

    /** One call site: {@code caller} invokes some callee at {@code callSite}. */
    public static final class CallEdge {
        private final SootMethod caller;
        private final Unit callSite;
        private final InvokeExpr invokeExpr;

        public CallEdge(SootMethod caller, Unit callSite, InvokeExpr invokeExpr) {
            this.caller = caller;
            this.callSite = callSite;
            this.invokeExpr = invokeExpr;
        }

        public SootMethod getCaller() { return caller; }
        public Unit getCallSite() { return callSite; }
        public InvokeExpr getInvokeExpr() { return invokeExpr; }
    }

    /**
     * Scans all application classes/methods once and builds a
     * callee -&gt; {@link CallEdge} list index covering every statically
     * resolvable call site within the app's own code.
     *
     * <p>Must be called after {@link SootSetup#run()}, same as
     * {@link ApiScanner#scan()}.
     */
    public static Map<SootMethod, List<CallEdge>> build() {
        Map<SootMethod, List<CallEdge>> index = new HashMap<>();

        List<SootClass> appClasses = new ArrayList<>(Scene.v().getApplicationClasses());
        for (SootClass sc : appClasses) {
            List<SootMethod> methods = new ArrayList<>(sc.getMethods());
            for (SootMethod method : methods) {
                if (!method.isConcrete()) {
                    continue;
                }

                Body body;
                try {
                    body = method.retrieveActiveBody();
                } catch (Exception e) {
                    continue;
                }

                for (Unit unit : body.getUnits()) {
                    Stmt stmt = (Stmt) unit;
                    if (!stmt.containsInvokeExpr()) {
                        continue;
                    }

                    InvokeExpr ie = stmt.getInvokeExpr();
                    SootMethod callee;
                    try {
                        callee = ie.getMethod();
                    } catch (Exception e) {
                        continue; // phantom/unresolvable callee — skip
                    }

                    index.computeIfAbsent(callee, k -> new ArrayList<>())
                         .add(new CallEdge(method, unit, ie));
                }
            }
        }

        return index;
    }
}
