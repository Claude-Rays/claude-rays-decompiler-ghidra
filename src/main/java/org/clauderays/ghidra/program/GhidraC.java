package org.clauderays.ghidra.program;

import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Text;

/**
 * The C of Ghidra's own decompiler for one function, as a draft for the
 * model: each line that comes from instructions starts with the address
 * annotation of its first instruction (/*0x401020*&#47;), the format the model
 * writes, so it can carry the addresses over to its own code.
 */
public final class GhidraC {

    /** seconds for Ghidra's decompiler */
    static final int TIMEOUT = 60;
    /** wide lines: one statement per line, so one annotation per statement */
    static final int MAX_WIDTH = 400;
    /**
     * Ghidra's C is left out when larger than the listing it comes from (it is
     * usually half of it; intrinsics as cpuid_*_info() blow it up), and at
     * least this many characters are always allowed.
     */
    static final double MAX_RATIO = 1.0;
    static final int MIN_CHARS = 2000;

    /** Ghidra's C of 'chars' characters is too large next to a listing of 'listingChars'. */
    static boolean tooLarge(int chars, int listingChars) {
        return chars > Math.max(MIN_CHARS, (int) (listingChars * MAX_RATIO));
    }

    /** The result: the annotated C, or why there is none. */
    public static final class Result {
        public String code = "";
        public String error = "";
        /** lines with an address annotation / all the lines */
        public int annotated;
        public int lines;
    }

    private GhidraC() {
    }

    /**
     * The lowest address of the code tokens of the line inside the function,
     * null if none (a comment line has the address of its comment, not code).
     */
    static Address lineAddress(ClangLine line, AddressSetView body) {
        Address best = null;
        for (ClangToken t : line.getAllTokens()) {
            if (t instanceof ClangCommentToken) {
                continue;
            }
            Address a = t.getMinAddress();
            if (a != null && body.contains(a) && (best == null || a.compareTo(best) < 0)) {
                best = a;
            }
        }
        return best;
    }

    public static Result decompile(Function f, TaskMonitor monitor) {
        Result out = new Result();
        DecompInterface ifc = new DecompInterface();
        try {
            DecompileOptions opts = new DecompileOptions();
            opts.grabFromProgram(f.getProgram());
            opts.setMaxWidth(MAX_WIDTH);
            ifc.setOptions(opts);
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(true);
            ifc.setSimplificationStyle("decompile");
            if (!ifc.openProgram(f.getProgram())) {
                out.error = "Ghidra's decompiler could not start: " + ifc.getLastMessage();
                return out;
            }
            DecompileResults r = ifc.decompileFunction(f, TIMEOUT, monitor != null ? monitor : TaskMonitor.DUMMY);
            if (r == null || !r.decompileCompleted() || r.getCCodeMarkup() == null) {
                out.error = "Ghidra's decompiler failed"
                    + (r != null && !Text.trim(r.getErrorMessage()).isEmpty() ? ": " + Text.trim(r.getErrorMessage())
                    : "");
                return out;
            }
            AddressSetView body = f.getBody();
            StringBuilder sb = new StringBuilder();
            for (ClangLine line : DecompilerUtils.toLines(r.getCCodeMarkup())) {
                StringBuilder text = new StringBuilder();
                for (ClangToken t : line.getAllTokens()) {
                    text.append(t.getText());
                }
                String s = Text.trim(text.toString());
                if (s.isEmpty()) {
                    continue;
                }
                out.lines++;
                Address a = lineAddress(line, body);
                sb.append(line.getIndentString());
                if (a != null) {
                    sb.append("/*").append(Names.hex(a)).append("*/ ");
                    out.annotated++;
                }
                sb.append(s).append('\n');
            }
            out.code = sb.toString();
            return out;
        }
        catch (Exception e) {
            Log.debug("Ghidra's decompiler on %s: %s", Names.hex(f.getEntryPoint()), e);
            out.error = "Ghidra's decompiler failed: " + e.getMessage();
            return out;
        }
        finally {
            ifc.dispose();
        }
    }
}
