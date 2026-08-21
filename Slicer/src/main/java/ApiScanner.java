import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.util.ArrayList;
import java.util.List;

/**
 * Scans every application class loaded by Soot and collects
 * {@link SliceCriterion} objects wherever a call to a suspicious
 * Android API is found.
 *
 * <p>This produces the complete <b>seed set</b> for Algorithm 1.
 * The scanner:
 * <ol>
 *   <li>Iterates over all application classes in the loaded scene.</li>
 *   <li>For each concrete method (one with a body), retrieves the Jimple body.</li>
 *   <li>For each statement that contains an invoke expression, checks the
 *       callee against {@link SuspiciousApiList}.</li>
 *   <li>Records a {@link SliceCriterion} for every match.</li>
 * </ol>
 *
 * <p><b>Why we use {@code retrieveActiveBody()} instead of
 * {@code getActiveBody()}:</b> {@code getActiveBody()} throws if the body
 * has not been built yet; {@code retrieveActiveBody()} forces construction.
 */
public final class ApiScanner {

    private ApiScanner() { /* static utility class */ }

    /**
     * Scans all application classes for suspicious API call sites.
     *
     * <p>Must be called <em>after</em> {@link SootSetup#run()} so that
     * method bodies are available.
     *
     * @return ordered list of slicing criteria (may be empty if the APK
     *         makes no suspicious API calls)
     */
    public static List<SliceCriterion> scan() {
        List<SliceCriterion> criteria = new ArrayList<>();

        // Snapshot the class list to avoid ConcurrentModificationException
        // if Soot adds phantom classes during body retrieval.
        List<SootClass> appClasses = new ArrayList<>(Scene.v().getApplicationClasses());

        for (SootClass sc : appClasses) {
            // Snapshot method list for the same reason.
            List<SootMethod> methods = new ArrayList<>(sc.getMethods());

            for (SootMethod method : methods) {
                if (!method.isConcrete()) {
                    // Skip: abstract, native, or interface methods have no body.
                    continue;
                }

                Body body = retrieveBody(method);
                if (body == null) {
                    continue;
                }

                scanBody(method, body, criteria);
            }
        }

        return criteria;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Attempts to retrieve (and build) the Jimple body for {@code method}.
     *
     * @return the body, or {@code null} if retrieval fails for any reason
     *         (e.g. synthetic / incomplete method, unresolvable class)
     */
    private static Body retrieveBody(SootMethod method) {
        try {
            return method.retrieveActiveBody();
        } catch (Exception e) {
            // Silently ignore: these are typically synthetic bridge methods,
            // methods with missing superclass bodies, or Soot internal issues.
            return null;
        }
    }

    /**
     * Walks every unit in {@code body} and adds a {@link SliceCriterion}
     * for every suspicious API invocation found.
     */
    private static void scanBody(SootMethod method,
                                 Body body,
                                 List<SliceCriterion> criteria) {
        for (Unit unit : body.getUnits()) {
            // Every Jimple unit is a Stmt; cast is always safe here.
            Stmt stmt = (Stmt) unit;

            if (!stmt.containsInvokeExpr()) {
                continue;
            }

            InvokeExpr ie = stmt.getInvokeExpr();

            SootMethod callee;
            try {
                callee = ie.getMethod();
            } catch (Exception e) {
                // Phantom or unresolvable callee — skip.
                continue;
            }

            if (SuspiciousApiList.isSuspicious(callee)) {
                criteria.add(new SliceCriterion(method, stmt, ie));
                System.out.printf("  [CRITERION] %-30s  in  %s%n",
                        callee.getName(),
                        method.getDeclaringClass().getShortName() + "." + method.getName());
            }
        }
    }
}
