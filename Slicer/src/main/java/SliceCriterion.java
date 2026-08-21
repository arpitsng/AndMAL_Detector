import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

/**
 * An immutable data holder representing a single <b>slicing criterion</b>:
 * the (method, call-site statement, invoke-expression) triple at which a
 * suspicious Android API is invoked.
 *
 * <p>This is the seed / entry-point for Algorithm 1's backward slice.
 * One {@code SliceCriterion} is produced per suspicious call site found
 * by {@link ApiScanner}.
 */
public final class SliceCriterion {

    /** The method whose body contains the suspicious call. */
    private final SootMethod method;

    /**
     * The Jimple statement at which the suspicious API is invoked.
     * This is the starting point of the backward traversal.
     */
    private final Stmt callSite;

    /**
     * The {@link InvokeExpr} embedded in {@link #callSite}.
     * Provides access to the callee signature and argument list used to
     * seed the set of relevant variables.
     */
    private final InvokeExpr invokeExpr;

    // ──────────────────────────────────────────────────────────────────────────

    public SliceCriterion(SootMethod method, Stmt callSite, InvokeExpr invokeExpr) {
        this.method     = method;
        this.callSite   = callSite;
        this.invokeExpr = invokeExpr;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /** @return the method that contains the suspicious API call. */
    public SootMethod getMethod() { return method; }

    /** @return the Jimple statement at which the suspicious API is invoked. */
    public Stmt getCallSite()    { return callSite; }

    /**
     * @return the {@link InvokeExpr} of the suspicious call, used by
     *         {@link BackwardSlicer} to seed the relevant-variable set.
     */
    public InvokeExpr getInvokeExpr() { return invokeExpr; }

    // ──────────────────────────────────────────────────────────────────────────

    @Override
    public String toString() {
        return "[" + method.getDeclaringClass().getShortName()
                + "." + method.getName() + "] => " + callSite;
    }
}
