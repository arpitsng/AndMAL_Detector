import soot.G;
import soot.PackManager;
import soot.options.Options;

public class Main {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java Main <apk_path> <output_txt_file>");
            System.exit(1);
        }

        String apkPath = args[0];
        String outputTxtFile = args[1];

        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(new String[] { apkPath });
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_none);

        PackManager.v().runPacks();

        // TODO: Implement Algorithm 1 (Backward Slicing) and write results to
        // outputTxtFile
        System.out.println("Soot analysis complete. Output target: " + outputTxtFile);
    }
}
