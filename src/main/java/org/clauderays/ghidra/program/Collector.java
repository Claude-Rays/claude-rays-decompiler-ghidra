package org.clauderays.ghidra.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Section;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Context collector: the deterministic equivalent of what
 * Claude would look up with tools; each step of that analysis becomes a
 * section extracted with the Ghidra API.
 */
public final class Collector {

    private static final int SMALL_CALLEE_INSNS = 30;      // listed in full below this
    private static final int MAX_SMALL_CALLEES = 12;
    private static final int MAX_CALLERS = 3;
    private static final int MAX_CALLER_NAMES = 8;
    private static final int CALL_SITE_INSNS = 6;
    private static final int MAX_DATA_ITEMS = 60;
    private static final int MAX_STRING_LEN = 300;
    private static final int MAX_COMMENT_LEN = 300;
    private static final int MAX_TYPE_LEN = 3000;
    private static final int MAX_TYPES = 20;
    private static final int MAX_REQUESTS = 5;
    private static final int MAX_DATA_XREFS = 10;
    private static final int MAX_REQUESTED_INSNS = 400;     // a requested function listing
    private static final int FACTS_COLUMN = 48;

    private final Program program;
    private final TaskMonitor monitor;
    private final Listing listing;
    private final CodeUnitFormat format;
    /** Settings.CONTEXT_...: what collect() gives of the function */
    private String context = Settings.get().context;

    public Collector(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
        this.listing = program.getListing();
        this.format = new CodeUnitFormat(CodeUnitFormatOptions.ShowBlockName.NEVER,
            CodeUnitFormatOptions.ShowNamespace.NON_LOCAL);
    }

    /** Another context mode than the one of the settings (the A/B check). */
    public Collector context(String mode) {
        this.context = Settings.contextOf(mode);
        return this;
    }

    public String context() {
        return context;
    }

    /** The collected context. */
    public static final class Collected {
        /** the user message */
        public String text = "";
        /** the sections alone, without the task line */
        public String body = "";
        /** not empty: nothing to send (too large...) */
        public String error = "";
        public int ninsns;
        public final List<Section.Size> sizes = new ArrayList<>();
        /** the context mode used */
        public String context = Settings.CONTEXT_LISTING;
        /** why the C of Ghidra's decompiler was not sent ("" if it was, or was not asked for) */
        public String ghidraNote = "";
    }

    //--------------------------------------------------------------------------
    // small helpers
    //--------------------------------------------------------------------------
    static String funcName(Function f) {
        return Names.functionName(f);
    }

    /** Regular and repeatable function comments, on one line. */
    static String funcComment(Function f) {
        String cmt = f.getComment();
        String rcmt = f.getRepeatableComment();
        String out = cmt != null ? cmt : "";
        if (rcmt != null && !rcmt.isEmpty() && !rcmt.equals(cmt)) {
            out += (out.isEmpty() ? "" : " / ") + rcmt;
        }
        return Text.oneLine(out, MAX_COMMENT_LEN);
    }

    String disasmLine(Instruction insn) {
        return Text.trim(format.getRepresentationString(insn));
    }

    /** The prototype of 'f'; known[0] tells if it is from the program (not Ghidra's default). */
    static String prototypeOf(Function f, boolean[] known) {
        known[0] = f.getSignatureSource() != ghidra.program.model.symbol.SourceType.DEFAULT;
        String proto = f.getPrototypeString(false, false);
        if (proto == null) {
            return "";
        }
        // the qualified name of a method, as the listing writes it
        String qualified = funcName(f);
        int p = proto.indexOf(f.getName() + "(");
        if (!qualified.equals(f.getName()) && p >= 0) {
            proto = proto.substring(0, p) + qualified + proto.substring(p + f.getName().length());
        }
        return Text.oneLine(proto, 400);
    }

    public static int countInsns(Function f) {
        int n = 0;
        InstructionIterator it = f.getProgram().getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            it.next();
            n++;
        }
        return n;
    }

    //--------------------------------------------------------------------------
    // types used by the function, printed once in the Types section
    //--------------------------------------------------------------------------
    static final class TypeSet {
        final Map<String, DataType> types = new LinkedHashMap<>();     // in discovery order

        void add(DataType t) {
            for (int guard = 0; guard < 8 && t != null; guard++) {
                if (t instanceof Pointer p) {
                    t = p.getDataType();
                }
                else if (t instanceof Array a) {
                    t = a.getDataType();
                }
                else if (t instanceof TypeDef td && !(td.getBaseDataType() instanceof Composite
                    || td.getBaseDataType() instanceof Enum)) {
                    t = td.getDataType();
                }
                else {
                    break;
                }
            }
            if (t instanceof FunctionDefinition fd) {
                addSimple(fd.getReturnType());
                for (ParameterDefinition a : fd.getArguments()) {
                    addSimple(a.getDataType());
                }
                return;
            }
            addSimple(t);
        }

        void addSimple(DataType t) {
            for (int guard = 0; guard < 8 && t != null; guard++) {
                if (t instanceof Pointer p) {
                    t = p.getDataType();
                }
                else if (t instanceof Array a) {
                    t = a.getDataType();
                }
                else if (t instanceof TypeDef td) {
                    t = td.getBaseDataType();
                }
                else {
                    break;
                }
            }
            if (!(t instanceof Composite) && !(t instanceof Enum)) {
                return;
            }
            types.putIfAbsent(t.getPathName(), t);
        }

        void addFunction(Function f) {
            add(f.getReturnType());
            for (Parameter p : f.getParameters()) {
                add(p.getDataType());
            }
        }
    }

    String typeDefinition(DataType t) {
        try {
            if (t instanceof Composite c && (c.isNotYetDefined() || c.getNumComponents() == 0)) {
                return "";      // a placeholder: nothing to tell
            }
            StringWriter w = new StringWriter();
            DataTypeManager dtm = t.getDataTypeManager() != null ? t.getDataTypeManager()
                : program.getDataTypeManager();
            DataTypeWriter dw = new DataTypeWriter(dtm, w, false);
            // the writer starts with the declarations of Ghidra's built-in types
            int preamble = w.getBuffer().length();
            dw.write(List.of(t), monitor);
            String s = Text.trim(w.getBuffer().substring(preamble));
            if (s.length() > MAX_TYPE_LEN) {
                s = s.substring(0, MAX_TYPE_LEN) + "\n  ... (cut)";
            }
            return s;
        }
        catch (Exception e) {
            return "";
        }
    }

    //--------------------------------------------------------------------------
    // the annotated listing
    //--------------------------------------------------------------------------
    String listingLine(Instruction insn, String facts) {
        String line = "  " + Names.addr(insn.getAddress()) + "  " + disasmLine(insn);
        if (facts != null && !facts.isEmpty()) {
            line = Text.pad(line, FACTS_COLUMN) + " ; " + facts;
        }
        return line;
    }

    /** The listing of a whole function by basic blocks. */
    String functionListing(Cfg cfg) {
        return functionListing(cfg, true);
    }

    /** ... without the instruction facts when 'withFacts' is false. */
    String functionListing(Cfg cfg, boolean withFacts) {
        StringBuilder out = new StringBuilder();
        for (Cfg.Block blk : cfg.blocks) {
            out.append(cfg.blockHeader(blk.number)).append('\n');
            Map<Address, String> facts = withFacts ? InsnFacts.blockFacts(blk) : Map.of();
            for (Instruction insn : blk.insns) {
                out.append(listingLine(insn, facts.get(insn.getAddress()))).append('\n');
            }
        }
        return out.toString();
    }

    //--------------------------------------------------------------------------
    // sections
    //--------------------------------------------------------------------------
    String archText() {
        Language lang = program.getLanguage();
        StringBuilder out = new StringBuilder(lang.getProcessor().toString());
        out.append(", ").append(lang.getLanguageDescription().getSize()).append("-bit");
        out.append(lang.isBigEndian() ? ", big endian" : ", little endian");
        String fmt = program.getExecutableFormat();
        if (fmt != null && !fmt.isEmpty()) {
            out.append(", file: ").append(fmt);
        }
        String compiler = program.getCompiler();
        if (compiler != null && !compiler.isEmpty() && !compiler.equalsIgnoreCase("unknown")) {
            out.append(", compiler: ").append(compiler);
        }
        else {
            out.append(", compiler spec: ").append(program.getCompilerSpec().getCompilerSpecID());
        }
        return out.toString();
    }

    Section headerSection(Function f, int ninsns, int nblocks, TypeSet types) {
        Section s = new Section("Function");
        StringBuilder t = new StringBuilder();
        t.append("Name: ").append(funcName(f))
            .append(Names.hasUserName(f) ? " (set by the analyst or the binary)" : " (default name)").append('\n');
        AddressSetView body = f.getBody();
        t.append("Address: ").append(Names.hex(body.getMinAddress())).append(" - ")
            .append(Names.hex(body.getMaxAddress().add(1)));
        if (body.getNumAddressRanges() > 1) {
            t.append(" (").append(body.getNumAddressRanges()).append(" chunks)");
        }
        t.append('\n');
        t.append("Architecture: ").append(archText()).append('\n');
        boolean[] known = new boolean[1];
        String proto = prototypeOf(f, known);
        if (!proto.isEmpty()) {
            t.append("Prototype: ").append(proto)
                .append(known[0] ? " (from the program)" : " (guessed by Ghidra, may be wrong)").append('\n');
        }
        String cc = f.getCallingConventionName();
        if (cc != null && !cc.isEmpty() && !cc.equals("unknown") && (proto.isEmpty() || !proto.contains(cc))) {
            t.append("Calling convention: ").append(cc).append('\n');
        }
        types.addFunction(f);
        if (f.hasNoReturn()) {
            t.append("Returns: no (noreturn function)\n");
        }
        if (f.isThunk()) {
            t.append("Thunk function\n");
        }
        String cmt = funcComment(f);
        if (!cmt.isEmpty()) {
            t.append("Comment: ").append(cmt).append('\n');
        }
        t.append(String.format("Size: %d instructions, %d basic blocks\n", ninsns, nblocks));
        s.intro = t.toString();
        return s;
    }

    Section frameSection(Function f, TypeSet types) {
        Section s = new Section("Stack frame");
        StackFrame frame = f.getStackFrame();
        // register parameters first: the listing refers to them by register
        for (Parameter p : f.getParameters()) {
            if (p.isStackVariable()) {
                continue;
            }
            types.add(p.getDataType());
            String line = String.format("  %-20s %-12s size %d  %s  (argument %d)", p.getName(),
                p.getVariableStorage().toString(), p.getLength(), p.getDataType().getDisplayName(),
                p.getOrdinal() + 1);
            if (p.getComment() != null && !p.getComment().isEmpty()) {
                line += "  // " + Text.oneLine(p.getComment(), MAX_COMMENT_LEN);
            }
            s.items.add(line);
        }
        for (Variable v : frame.getStackVariables()) {
            int off = v.getStackOffset();
            types.add(v.getDataType());
            String line = String.format("  %-20s %s0x%x  size %d  %s%s", v.getName(), off < 0 ? "-" : "+",
                Math.abs((long) off), v.getLength(), v.getDataType().getDisplayName(),
                v instanceof Parameter ? "  (argument)" : "");
            if (v.getComment() != null && !v.getComment().isEmpty()) {
                line += "  // " + Text.oneLine(v.getComment(), MAX_COMMENT_LEN);
            }
            s.items.add(line);
        }
        if (!s.items.isEmpty()) {
            int purge = f.getStackPurgeSize();
            boolean purgeKnown = purge > 0 && purge != Function.UNKNOWN_STACK_DEPTH_CHANGE
                && purge != Function.INVALID_STACK_DEPTH_CHANGE;
            s.intro = String.format("Locals 0x%x bytes, parameters 0x%x bytes, return address at %s0x%x%s. "
                    + "Offsets are from the stack pointer at the function entry "
                    + "(negative: locals, positive: return address and arguments). Register arguments are "
                    + "listed with their register.\n",
                frame.getLocalSize(), frame.getParameterSize(), frame.getReturnAddressOffset() < 0 ? "-" : "+",
                Math.abs((long) frame.getReturnAddressOffset()),
                purgeKnown ? String.format(", purges 0x%x bytes of arguments", purge) : "");
        }
        return s;
    }

    /** "caseD_1a" -> 0x1a, "default" -> null. */
    private static Long caseValue(String label) {
        if (label.startsWith("caseD_")) {
            return Text.parseHex(label.substring(6));
        }
        if (label.startsWith("case_")) {
            return Text.parseHex(label.substring(5));
        }
        return null;
    }

    Section switchSection(Function f, Cfg cfg) {
        Section s = new Section("Switch");
        InstructionIterator it = listing.getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            FlowType ft = insn.getFlowType();
            if (!(ft.isComputed() && ft.isJump())) {
                continue;
            }
            List<Address> targets = new ArrayList<>();
            for (Reference r : insn.getReferencesFrom()) {
                if (r.getReferenceType().isJump() && r.getToAddress().isMemoryAddress()
                    && !targets.contains(r.getToAddress())) {
                    targets.add(r.getToAddress());
                }
            }
            if (targets.size() < 2) {
                continue;
            }
            StringBuilder t = new StringBuilder("switch at ").append(Names.hex(insn.getAddress()));
            String reg = firstRegister(insn);
            if (!reg.isEmpty()) {
                t.append(" on ").append(reg);
            }
            t.append(": ").append(targets.size()).append(" targets\n");
            targets.sort(null);
            for (Address target : targets) {
                List<String> cases = new ArrayList<>();
                boolean isDefault = false;
                for (Symbol sym : program.getSymbolTable().getSymbols(target)) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns == null || !ns.getName().startsWith("switchD")) {
                        continue;
                    }
                    Long v = caseValue(sym.getName());
                    if (v != null) {
                        cases.add(Long.toString(v));
                    }
                    else if (sym.getName().equals("default") || sym.getName().startsWith("caseD_default")) {
                        isDefault = true;
                    }
                }
                t.append("  ");
                t.append(cases.isEmpty() ? (isDefault ? "default" : "target") : "case " + String.join(", ", cases));
                t.append(" -> ").append(Names.hex(target));
                int blk = cfg.blockIndex(target);
                if (blk >= 0) {
                    t.append(" (block ").append(blk).append(")");
                }
                if (isDefault && !cases.isEmpty()) {
                    t.append(" (also the default)");
                }
                t.append('\n');
            }
            s.items.add(t.toString());
        }
        return s;
    }

    /** The register of the first operand of an indirect jump, "" if none. */
    private static String firstRegister(Instruction insn) {
        if (insn.getNumOperands() > 0) {
            for (Object o : insn.getOpObjects(0)) {
                if (o instanceof ghidra.program.model.lang.Register r) {
                    return r.getName();
                }
            }
        }
        return "";
    }

    /**
     * The functions called by 'f' in order of appearance (directly, through an
     * import pointer or by a tail jump).
     */
    public static List<Address> functionCallees(Function f) {
        Program program = f.getProgram();
        Set<Address> seen = new LinkedHashSet<>();
        InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            FlowType ft = insn.getFlowType();
            boolean isJump = ft.isJump() && ft.isUnConditional();
            if (!ft.isCall() && !isJump) {
                continue;
            }
            Address t = InsnFacts.callTarget(insn);
            if (t == null || t.equals(f.getEntryPoint())) {
                continue;
            }
            // a jump is a call only when it leaves the function for another one
            if (!ft.isCall()) {
                if (f.getBody().contains(t)) {
                    continue;
                }
                Function g = t.isMemoryAddress() ? program.getFunctionManager().getFunctionContaining(t) : null;
                if (g != null && !g.getEntryPoint().equals(t)) {
                    continue;
                }
            }
            seen.add(t);
        }
        return new ArrayList<>(seen);
    }

    void calleeSections(Function f, TypeSet types, Section protos, Section small) throws CancelledException {
        protos.title = "Called functions";
        small.title = "Listings of small unnamed callees";
        small.trimRank = 4;
        for (Address t : functionCallees(f)) {
            Function g = Names.functionAt(program, t);
            String name = g != null ? funcName(g) : Names.nameAt(program, t);
            boolean[] known = new boolean[1];
            String proto = g != null ? prototypeOf(g, known) : "";
            // an import reached through a reference to its external location: no address of its own
            StringBuilder line = new StringBuilder("  ").append(t.isMemoryAddress() ? Names.hex(t) : "(import)")
                .append("  ")
                .append(proto.isEmpty() ? name : proto);
            if (!proto.isEmpty() && !known[0]) {
                line.append("  (prototype guessed by Ghidra)");
            }
            if (g == null) {
                protos.items.add(line.toString());
                continue;
            }
            types.addFunction(g);
            if (Names.isImport(g)) {
                line.append("  [import");
                Function ext = g.isExternal() ? g : g.getThunkedFunction(true);
                if (ext != null && ext.getExternalLocation() != null) {
                    line.append(" from ").append(ext.getExternalLocation().getLibraryName());
                }
                line.append("]");
            }
            if (g.hasNoReturn()) {
                line.append("  [noreturn]");
            }
            if (g.isThunk() && !Names.isImport(g)) {
                Function to = g.getThunkedFunction(true);
                if (to != null) {
                    line.append("  [thunk to ").append(funcName(to)).append("]");
                }
            }
            String cmt = funcComment(g);
            if (!cmt.isEmpty()) {
                line.append("  // ").append(cmt);
            }
            protos.items.add(line.toString());

            // small functions without a name: their whole listing, one level deep
            if (!g.isExternal() && g.getEntryPoint().equals(t) && !Names.hasUserName(g) && !g.isThunk()
                && small.items.size() < MAX_SMALL_CALLEES) {
                int n = countInsns(g);
                if (n < SMALL_CALLEE_INSNS) {
                    String head = "-- " + name + " (" + Names.hex(t) + ", " + n + " instructions)";
                    if (!proto.isEmpty()) {
                        head += ": " + proto;
                    }
                    small.items.add(head + "\n" + functionListing(new Cfg(g, monitor)));
                }
            }
        }
    }

    Section callSiteSection(Function f) throws CancelledException {
        Section s = new Section("Call sites", 3);
        Address entry = f.getEntryPoint();
        // the calls, grouped by calling function
        Map<Function, Address> firstSite = new LinkedHashMap<>();
        ReferenceIterator it = program.getReferenceManager().getReferencesTo(entry);
        while (it.hasNext()) {
            Reference r = it.next();
            if (!r.getReferenceType().isCall() && !r.getReferenceType().isJump()) {
                continue;
            }
            Function caller = program.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (caller == null || caller.equals(f)) {
                continue;
            }
            firstSite.putIfAbsent(caller, r.getFromAddress());
        }
        if (firstSite.isEmpty()) {
            return s;
        }
        List<Function> callers = new ArrayList<>(firstSite.keySet());
        List<String> names = new ArrayList<>();
        for (Function c : callers) {
            names.add(funcName(c));
        }
        s.intro = "Called by " + callers.size() + " function(s): " + Text.shortList(names, MAX_CALLER_NAMES) + "\n";

        for (int i = 0; i < callers.size() && i < MAX_CALLERS; i++) {
            Function caller = callers.get(i);
            Address site = firstSite.get(caller);
            Instruction call = listing.getInstructionAt(site);
            if (call == null) {
                continue;
            }
            List<Instruction> lines = new ArrayList<>();
            Instruction p = call;
            for (int k = 0; k < CALL_SITE_INSNS; k++) {
                p = p.getPrevious();
                if (p == null || !caller.getBody().contains(p.getAddress())) {
                    break;
                }
                lines.add(0, p);
            }
            lines.add(call);
            // the result use is the fact of the call instruction itself
            Cfg cfg = new Cfg(caller, monitor);
            int bi = cfg.blockIndex(site);
            Address bstart = bi >= 0 ? cfg.blocks.get(bi).start : site;
            Address bend = bi >= 0 ? cfg.blocks.get(bi).end : caller.getBody().getMaxAddress();
            StringBuilder t = new StringBuilder("in ").append(funcName(caller)).append(" at ")
                .append(Names.hex(site)).append(":\n");
            for (Instruction insn : lines) {
                t.append(listingLine(insn, insn == call ? InsnFacts.factsAt(insn, bstart, bend) : "")).append('\n');
            }
            s.items.add(t.toString());
        }
        return s;
    }

    /** The string at 'a', null if there is none. */
    String stringAt(Address a) {
        Data d = listing.getDefinedDataAt(a);
        if (d != null && d.hasStringValue()) {
            Object v = d.getValue();
            return v != null ? v.toString() : null;
        }
        return null;
    }

    /** A description of the data at 'a' on one line, "" for code / imports. */
    String describeData(Address a, TypeSet types) {
        Memory mem = program.getMemory();
        if (a == null || !a.isMemoryAddress() || !mem.contains(a)) {
            return "";
        }
        MemoryBlock block = mem.getBlock(a);
        if (block != null && block.isExternalBlock()) {
            return "";
        }
        Instruction insn = listing.getInstructionContaining(a);
        if (insn != null) {
            Function fn = program.getFunctionManager().getFunctionAt(a);
            if (fn != null) {
                return Names.hex(a) + "  address of the function " + funcName(fn);
            }
            return "";
        }
        Data data = listing.getDataContaining(a);
        Address head = data != null ? data.getAddress() : a;
        String name = Names.nameAt(program, head);
        StringBuilder where = new StringBuilder(name.isEmpty() ? Names.hex(head) : name + " (" + Names.hex(head) + ")");
        if (!head.equals(a)) {
            where.append(String.format(" + 0x%x", a.subtract(head)));
        }
        String text = stringAt(head);
        if (text != null) {
            return where + "  string " + Text.oneLine(Text.quote(text), MAX_STRING_LEN);
        }
        StringBuilder out = new StringBuilder(where);
        if (block != null) {
            out.append("  [").append(block.getName()).append("]");
        }
        DataType dt = data != null ? data.getDataType() : null;
        boolean undefined = dt == null || dt instanceof DefaultDataType || Undefined.isUndefined(dt);
        if (!undefined) {
            out.append("  type ").append(dt.getDisplayName());
            types.add(dt);
        }
        int size = data != null ? Math.max(data.getLength(), 1) : 1;
        if (block != null && !block.isInitialized()) {
            return out + String.format("  size %d, uninitialized (bss)", size);
        }
        if (data != null && data.isPointer()) {
            Object v = data.getValue();
            if (v instanceof Address p) {
                out.append("  pointer to ").append(Names.hex(p));
                String pn = Names.nameAt(program, p);
                if (!pn.isEmpty()) {
                    out.append(' ').append(pn);
                }
                String s = stringAt(p);
                if (s != null) {
                    out.append(" = string ").append(Text.oneLine(Text.quote(s), MAX_STRING_LEN));
                }
                return out.toString();
            }
        }
        if (!undefined && (size == 1 || size == 2 || size == 4 || size == 8)) {
            Object v = data.getValue();
            if (v instanceof Scalar sc) {
                return out + String.format("  size %d, value 0x%x", size, sc.getUnsignedValue());
            }
            if (v instanceof Number num) {
                return out + "  value " + num;
            }
        }
        // first bytes of the item (or of what follows an undefined address)
        int n = undefined ? 16 : Math.min(size, 32);
        byte[] bytes = new byte[n];
        int got;
        try {
            got = mem.getBytes(head, bytes);
        }
        catch (Exception e) {
            got = 0;
        }
        if (undefined) {
            out.append("  no data type, bytes");
        }
        else {
            out.append("  size ").append(size).append(", bytes");
        }
        for (int i = 0; i < got; i++) {
            out.append(String.format(" %02x", bytes[i] & 0xff));
        }
        if (undefined || size > got) {
            out.append(" ...");
        }
        return out.toString();
    }

    Section dataSection(Function f, TypeSet types) {
        Section s = new Section("Data", 1);
        Set<Address> seen = new LinkedHashSet<>();
        InstructionIterator it = listing.getInstructions(f.getBody(), true);
        while (it.hasNext() && s.items.size() < MAX_DATA_ITEMS) {
            Instruction insn = it.next();
            for (Reference r : insn.getReferencesFrom()) {
                if (r.getReferenceType().isFlow() || r.isStackReference() || r.isRegisterReference()) {
                    continue;
                }
                Address x = r.getToAddress();
                if (!x.isMemoryAddress()) {
                    continue;
                }
                if (f.getBody().contains(x) && listing.getInstructionContaining(x) != null) {
                    continue;
                }
                if (!seen.add(x)) {
                    continue;
                }
                String d = describeData(x, types);
                if (!d.isEmpty()) {
                    s.items.add("  " + d);
                }
            }
        }
        return s;
    }

    Section typesSection(TypeSet types) {
        Section s = new Section("Types", 2);
        for (DataType t : types.types.values()) {
            if (s.items.size() >= MAX_TYPES) {
                break;
            }
            String def = typeDefinition(t);
            if (!def.isEmpty()) {
                s.items.add(def);
            }
        }
        return s;
    }

    //--------------------------------------------------------------------------
    /**
     * The C of Ghidra's decompiler. A draft next to the listing: trimmed with
     * the call sites when the budget is short. Untouchable when it comes first
     * (CONTEXT_GHIDRA). null, with the reason in 'out', when the decompiler
     * fails or when its C is larger than the listing of 'listingChars'.
     */
    Section ghidraSection(Function f, boolean first, int listingChars, Collected out) {
        GhidraC.Result r = GhidraC.decompile(f, monitor);
        if (r.code.isEmpty()) {
            out.ghidraNote = r.error.isEmpty() ? "Ghidra's decompiler gave no code" : r.error;
        }
        else if (GhidraC.tooLarge(r.code.length(), listingChars)) {
            out.ghidraNote = String.format("Ghidra's C left out: %d chars, %.1f times the listing (%d chars)",
                r.code.length(), r.code.length() / (double) Math.max(listingChars, 1), listingChars);
        }
        if (!out.ghidraNote.isEmpty()) {
            Log.info("%s: %s", funcName(f), out.ghidraNote);
            return null;
        }
        Section s = new Section("Ghidra decompiler", first ? 0 : 3);
        s.intro = "Draft C by Ghidra's decompiler, /*0x...*/ = address of the first instruction of the line "
            + "(the listing is right when they disagree).\n";
        s.items.add(r.code);
        return s;
    }

    /** The context of the function 'f'; 'budget' 0 uses the one of the settings. */
    public Collected collect(Function f, int budget) throws CancelledException {
        Collected out = new Collected();
        if (f == null) {
            out.error = "the cursor is not in a function";
            return out;
        }
        if (f.isExternal()) {
            out.error = funcName(f) + " is an import: there is no code to decompile";
            return out;
        }
        out.ninsns = countInsns(f);
        Settings st = Settings.get();
        if (out.ninsns > st.maxInsns) {
            out.error = String.format("%s has %d instructions, more than the limit of %d "
                + "(Claude-Rays Decompiler > Settings): large functions are not sent yet", funcName(f), out.ninsns,
                st.maxInsns);
            return out;
        }
        if (out.ninsns == 0) {
            out.error = funcName(f) + " has no instructions";
            return out;
        }

        TypeSet types = new TypeSet();
        Cfg cfg = new Cfg(f, monitor);
        List<Section> sections = new ArrayList<>();
        sections.add(headerSection(f, out.ninsns, cfg.size(), types));
        sections.add(frameSection(f, types));

        out.context = context;
        boolean ghidraFirst = context.equals(Settings.CONTEXT_GHIDRA);
        String fullListing = functionListing(cfg, InsnFacts.hasInsnFacts(program));
        String plainListing = ghidraFirst ? functionListing(cfg, false) : fullListing;
        Section ghidraSec = context.equals(Settings.CONTEXT_LISTING) ? null
            : ghidraSection(f, ghidraFirst, plainListing.length(), out);
        if (ghidraSec == null) {
            ghidraFirst = false;        // without the draft, the whole listing (CONTEXT_GHIDRA too)
        }
        if (ghidraSec != null && ghidraFirst) {
            sections.add(ghidraSec);
        }
        Section listingSec = new Section("Listing");
        boolean facts = !ghidraFirst && InsnFacts.hasInsnFacts(program);
        listingSec.intro = facts
            ? "Annotated disassembly by basic block ('; ' facts at the end of the lines are exact).\n"
            : "Disassembly by basic block (no instruction facts).\n";
        listingSec.items.add(ghidraFirst ? plainListing : fullListing);
        sections.add(listingSec);
        if (ghidraSec != null && !ghidraFirst) {
            sections.add(ghidraSec);
        }
        sections.add(switchSection(f, cfg));
        Section protos = new Section("Called functions");
        Section small = new Section("Listings of small unnamed callees", 4);
        calleeSections(f, types, protos, small);
        sections.add(protos);
        if (!ghidraFirst) {
            sections.add(small);
        }
        sections.add(callSiteSection(f));
        sections.add(dataSection(f, types));
        sections.add(typesSection(types));

        out.body = Section.assemble(sections, budget != 0 ? budget : st.budget, out.sizes);
        if (ghidraSec != null && ghidraSec.dropped > 0) {
            out.ghidraNote = "Ghidra's C left out for the context budget (" + (budget != 0 ? budget : st.budget)
                + " chars)";
            Log.info("%s: %s", funcName(f), out.ghidraNote);
        }
        out.text = "Decompile the function " + funcName(f) + " at " + Names.hex(f.getEntryPoint()) + ".\n\n"
            + out.body;
        if (st.verbose) {
            for (Section.Size sz : out.sizes) {
                Log.debug("section %-36s %6d chars", sz.title(), sz.chars());
            }
        }
        return out;
    }

    //--------------------------------------------------------------------------
    // need_more
    //--------------------------------------------------------------------------
    private String requestedFunction(Address a, String[] why) throws CancelledException {
        Function f = program.getFunctionManager().getFunctionContaining(a);
        if (f == null) {
            f = Names.functionAt(program, a);
        }
        if (f == null || f.isExternal()) {
            why[0] = f == null ? "not a function" : "an import: no code";
            return "";
        }
        int n = countInsns(f);
        if (n > MAX_REQUESTED_INSNS) {
            why[0] = "too large (" + n + " instructions)";
            return "";
        }
        TypeSet types = new TypeSet();
        Cfg cfg = new Cfg(f, monitor);
        return "-- function " + funcName(f) + " (" + Names.hex(f.getEntryPoint()) + ")\n"
            + headerSection(f, n, cfg.size(), types).render()
            + frameSection(f, types).render()
            + "Listing:\n" + functionListing(cfg);
    }

    private String requestedData(Address a, String[] why) {
        TypeSet types = new TypeSet();
        String d = describeData(a, types);
        if (d.isEmpty()) {
            why[0] = "not a data item";
            return "";
        }
        StringBuilder out = new StringBuilder("-- data ").append(d).append('\n');
        // the uses of the item
        Data data = listing.getDataContaining(a);
        Address head = data != null ? data.getAddress() : a;
        ReferenceIterator it = program.getReferenceManager().getReferencesTo(head);
        int n = 0;
        while (it.hasNext() && n < MAX_DATA_XREFS) {
            Reference r = it.next();
            Instruction insn = listing.getInstructionAt(r.getFromAddress());
            if (insn == null) {
                continue;
            }
            Function f = program.getFunctionManager().getFunctionContaining(r.getFromAddress());
            out.append("  used ").append(f != null ? "in " + funcName(f) + " " : "").append("at ")
                .append(Names.hex(r.getFromAddress())).append(": ").append(disasmLine(insn)).append('\n');
            n++;
        }
        for (DataType t : types.types.values()) {
            String def = typeDefinition(t);
            if (!def.isEmpty()) {
                out.append(def).append('\n');
            }
        }
        return out.toString();
    }

    private DataType findType(String name) {
        List<DataType> found = new ArrayList<>();
        program.getDataTypeManager().findDataTypes(name, found);
        for (DataType t : found) {
            if (t instanceof Composite || t instanceof Enum) {
                return t;
            }
        }
        for (DataType t : found) {
            TypeSet ts = new TypeSet();
            ts.add(t);
            if (!ts.types.isEmpty()) {
                return ts.types.values().iterator().next();
            }
        }
        return null;
    }

    private String requestedStruct(String target, String[] why) {
        String name = target;
        // an address: the type of the item there
        Address a = Names.parseAddress(program, target);
        if (a != null && findType(target) == null) {
            Data d = listing.getDataContaining(a);
            TypeSet ts = new TypeSet();
            if (d != null) {
                ts.add(d.getDataType());
            }
            if (ts.types.isEmpty()) {
                why[0] = "no structure type at that address";
                return "";
            }
            DataType t = ts.types.values().iterator().next();
            return "-- type " + t.getName() + "\n" + typeDefinition(t) + "\n";
        }
        // "struct foo" / "foo *" -> foo
        for (String kw : new String[]{"struct ", "union ", "enum ", "const "}) {
            if (name.startsWith(kw)) {
                name = name.substring(kw.length());
            }
        }
        name = Text.trim(name);
        while (!name.isEmpty() && (name.endsWith("*") || name.endsWith(" "))) {
            name = name.substring(0, name.length() - 1);
        }
        DataType t = findType(name);
        String def = t != null ? typeDefinition(t) : "";
        if (def.isEmpty()) {
            why[0] = "unknown type";
            return "";
        }
        return "-- type " + name + "\n" + def + "\n";
    }

    /**
     * One need_more round: the context for the valid requests, "" if none.
     * 'seen' keeps the requests already served (across rounds); the requests
     * that cannot be served are described in 'ignored'.
     */
    public String collectRequested(List<Backend.NeedMore> reqs, Set<String> seen, int budget, List<String> ignored)
        throws CancelledException {
        StringBuilder out = new StringBuilder();
        int served = 0;
        for (Backend.NeedMore r : reqs) {
            String what = r.what();
            String[] why = {""};
            String text = "";
            String key = "";
            if (served >= MAX_REQUESTS) {
                why[0] = "too many requests in one round";
            }
            else if (what.equals("struct")) {
                key = "struct:" + r.target();
                if (seen.contains(key)) {
                    why[0] = "already given";
                }
                else {
                    text = requestedStruct(r.target(), why);
                }
            }
            else if (what.equals("function") || what.equals("data")) {
                Address a = Names.parseAddress(program, r.target());
                if (a == null) {
                    why[0] = "not an address or a name of the program";
                }
                else {
                    if (what.equals("function")) {
                        Function f = program.getFunctionManager().getFunctionContaining(a);
                        if (f != null) {
                            a = f.getEntryPoint();
                        }
                    }
                    key = what + ":" + Names.hex(a);
                    if (seen.contains(key)) {
                        why[0] = "already given";
                    }
                    else {
                        text = what.equals("function") ? requestedFunction(a, why) : requestedData(a, why);
                    }
                }
            }
            else {
                why[0] = "unknown kind '" + what + "'";
            }
            if (text.isEmpty() || out.length() + text.length() > budget) {
                if (!text.isEmpty()) {
                    why[0] = "too large for the size budget";
                }
                ignored.add(what + " " + r.target() + ": " + why[0]);
                continue;
            }
            seen.add(key);
            out.append(text).append('\n');
            served++;
        }
        return out.toString();
    }
}
