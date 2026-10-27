package org.clauderays.ghidra.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.CodeShaper;
import org.clauderays.ghidra.core.Text;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Cheap validation of an answer; nothing is executed.
 * Calls: every call of the function appears in the code, by name.
 * Coverage: every basic block has an address annotation inside it.
 * Range: no annotation points outside the function.
 */
public final class Validator {

    private static final int MAX_LISTED = 8;      // warnings of one kind listed one by one
    private static final int MERGED_MAX_INSNS = 4;

    private Validator() {
    }

    /**
     * Compiler helpers a decompiler may leave out: stack cookies, stack probes,
     * CFG checks, profiling hooks.
     */
    static boolean isCompilerHelper(Program program, Address callee) {
        String[] helpers = {
            "security_check_cookie", "stack_chk_fail", "RTC_CheckStackVars", "chkstk",
            "alloca_probe", "guard_check_icall", "guard_dispatch_icall", "GSHandlerCheck",
            "__gnu_mcount_nc", "_mcount", "__cyg_profile_func_enter", "__cyg_profile_func_exit",
            "__aeabi_unwind_cpp_pr",
        };
        for (String name : Names.calleeNameVariants(program, callee)) {
            for (String h : helpers) {
                if (name.contains(h)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Runtime routines behind C operators on processors without the instruction:
     * division, 64-bit shifts, soft float (ARM EABI, libgcc, MSVC x86): the C
     * code writes '/', '<<' or '+' instead of the call.
     */
    private static final Pattern ARITH_HELPER = Pattern.compile(
        "^_*(aeabi_(?!memcpy|memmove|memset|memclr|unwind)\\w+"
            + "|u?(div|mod|mul|ash[lr]|lshr|neg|cmp|ucmp|ffs|clz|ctz|popcount|bswap)[sdt]i[23]"
            + "|u?divmod[sdt]i4"
            + "|(add|sub|mul|div|neg|cmp|eq|ne|lt|le|gt|ge|unord|fix|fixuns|float|floatun|extend|trunc)"
            + "[sdtxh]f\\w*[0-9]"
            + "|all(div|rem|mul|shl|shr)|aull(div|rem|shr)|alldvrm|aulldvrm)$");

    static boolean isArithmeticHelper(Program program, Address callee) {
        for (String name : Names.calleeNameVariants(program, callee)) {
            int colons = Names.lastScope(name);
            if (ARITH_HELPER.matcher(colons < 0 ? name : name.substring(colons + 2)).matches()) {
                return true;
            }
        }
        return false;
    }

    /** Calls that idiomatic C++ does not spell out: destructors. */
    static boolean isDestructor(Program program, Address callee) {
        for (String q : Names.calleeNameVariants(program, callee)) {
            int colons = Names.lastScope(q);
            String last = colons < 0 ? q : q.substring(colons + 2);
            if (last.startsWith("~")) {
                return true;
            }
        }
        return false;
    }

    /** ... and the runtime call behind a C++ 'throw'. */
    static boolean isThrowHelper(Program program, Address callee) {
        for (String name : Names.calleeNameVariants(program, callee)) {
            if (name.contains("CxxThrowException") || name.contains("cxa_throw")) {
                return true;
            }
        }
        return false;
    }

    /** Epilogue restore of a callee-saved register from its home slot: 'mov rbx, [rsp+...]'. */
    static boolean restoresSavedReg(Instruction insn) {
        Set<String> saved = Set.of("rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15", "ebx", "ebp", "esi", "edi");
        String dst = InsnFacts.operandText(insn, 0);
        String src = InsnFacts.operandText(insn, 1);
        boolean stackSrc = src.contains("[rsp") || src.contains("[esp") || src.contains("[r11");
        return saved.contains(dst) && stackSrc;
    }

    /**
     * A block that needs no statement: only unconditional jumps / nops, or a
     * function epilogue (stack cookie check, stack release, pops, return).
     */
    static boolean trivialBlock(Program program, Cfg.Block blk) {
        if (!ArchInfo.of(program).x86) {
            return pcodeTrivialBlock(program, blk);
        }
        boolean helperCall = false;
        boolean cookieOps = false;      // mov / xor / lea that prepare the cookie check
        for (Instruction insn : blk.insns) {
            String m = InsnFacts.mnem(insn);
            if (m.startsWith("nop") || m.equals("int3") || m.equals("endbr64") || m.equals("endbr32")) {
                continue;
            }
            if (InsnFacts.isCall(insn)) {
                Address t = InsnFacts.callTarget(insn);
                if (t == null || !isCompilerHelper(program, t)) {
                    return false;
                }
                helperCall = true;
                continue;
            }
            if (InsnFacts.isRet(insn) || m.equals("pop") || m.equals("leave")) {
                continue;
            }
            if (m.equals("add")) {
                // only the release of the stack frame
                String reg = InsnFacts.operandText(insn, 0);
                if (!reg.equals("rsp") && !reg.equals("esp")) {
                    return false;
                }
                continue;
            }
            if (m.equals("mov") && restoresSavedReg(insn)) {
                continue;
            }
            if (m.equals("mov") || m.equals("xor") || m.equals("lea")) {
                cookieOps = true;
                continue;
            }
            FlowType ft = insn.getFlowType();
            boolean jump = ft.isJump() && ft.isUnConditional() && !ft.isComputed();
            if (!jump) {
                return false;
            }
        }
        // a "mov eax, 1; ret" block is a real return statement
        return !cookieOps || helperCall;
    }

    /**
     * trivialBlock for any processor, from the p-code: no store, no condition,
     * and every register written is either one an epilogue restores (stack
     * pointer, callee-saved registers, return address, flags) or only feeds one
     * of those or the return jump (PowerPC 'lwz r0; mtlr r0'). A value left in
     * another register ('mov r0, #1; bx lr') is a real return statement, even
     * when flags are computed from it.
     */
    static boolean pcodeTrivialBlock(Program program, Cfg.Block blk) {
        ArchInfo arch = ArchInfo.of(program);
        boolean helperCall = false;
        Set<Register> pending = new HashSet<>();
        for (Instruction insn : blk.insns) {
            FlowType ft = insn.getFlowType();
            if (ft.isCall()) {
                Address t = InsnFacts.callTarget(insn);
                if (t == null || !isCompilerHelper(program, t)) {
                    return false;
                }
                helperCall = true;
                pending.clear();        // the arguments of the helper
                continue;
            }
            if (ft.isConditional() || ft.isJump() && ft.isComputed() && !ft.isTerminal()) {
                return false;
            }
            // the pending registers each temporary of the instruction comes from
            Map<Varnode, Set<Register>> temps = new HashMap<>();
            for (PcodeOp op : insn.getPcode()) {
                int opc = op.getOpcode();
                if (opc == PcodeOp.STORE || opc == PcodeOp.CBRANCH) {
                    return false;       // a store, or conditionally executed (ARM)
                }
                Set<Register> from = new HashSet<>();
                for (int k = 0; k < op.getNumInputs(); k++) {
                    Varnode in = op.getInput(k);
                    Register r = arch.reg(in);
                    if (r != null && pending.contains(r)) {
                        from.add(r);
                    }
                    else if (in.isUnique() && temps.containsKey(in)) {
                        from.addAll(temps.get(in));
                    }
                }
                Varnode out = op.getOutput();
                if (out == null) {
                    if (opc == PcodeOp.RETURN || opc == PcodeOp.BRANCHIND) {
                        pending.removeAll(from);       // the return address ('bx r3')
                    }
                    continue;
                }
                if (out.isUnique()) {
                    if (!from.isEmpty()) {
                        temps.put(out, from);
                    }
                    continue;
                }
                Register r = arch.reg(out);
                if (r == null) {
                    return false;       // a write to memory
                }
                if (!arch.isEpilogueReg(r)) {
                    pending.removeAll(from);           // the value moves ('mtlr r0'; 'blr')
                    pending.add(r);
                }
                else if (!arch.isFlagBase(r)) {
                    pending.removeAll(from);           // restored into a preserved register
                }
            }
        }
        return pending.isEmpty() || helperCall;
    }

    /** What an expression piece may compute into a register: copies, loads, compares, bit operations. */
    private static final Set<Integer> MERGED_OPS = Set.of(PcodeOp.COPY, PcodeOp.LOAD, PcodeOp.INT_ZEXT,
        PcodeOp.INT_SEXT, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL,
        PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL, PcodeOp.BOOL_NEGATE,
        PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR, PcodeOp.SUBPIECE);

    /** mergedBlock for any processor, from the p-code. */
    static boolean pcodeMergedBlock(Program program, Cfg.Block blk) {
        ArchInfo arch = ArchInfo.of(program);
        int n = 0;
        for (Instruction insn : blk.insns) {
            if (InsnFacts.isCall(insn) || InsnFacts.isRet(insn) || ++n > MERGED_MAX_INSNS) {
                return false;
            }
            for (PcodeOp op : insn.getPcode()) {
                if (op.getOpcode() == PcodeOp.STORE) {
                    return false;
                }
                Varnode out = op.getOutput();
                if (out == null || out.isUnique()) {
                    continue;
                }
                Register r = arch.reg(out);
                if (r == null) {
                    return false;
                }
                if (arch.isFlagBase(r) || r.isZero() || r.isProgramCounter() || r.isProcessorContext()) {
                    continue;
                }
                if (!MERGED_OPS.contains(op.getOpcode())) {
                    return false;
                }
            }
        }
        return n > 0;
    }

    /**
     * A piece of an expression rather than a statement: a few instructions that
     * only compare, branch or set a register. No call, no store.
     */
    static boolean mergedBlock(Cfg.Block blk) {
        if (!blk.insns.isEmpty() && !ArchInfo.of(blk.insns.get(0).getProgram()).x86) {
            return pcodeMergedBlock(blk.insns.get(0).getProgram(), blk);
        }
        int n = 0;
        for (Instruction insn : blk.insns) {
            if (InsnFacts.isCall(insn) || ++n > MERGED_MAX_INSNS) {
                return false;
            }
            String m = InsnFacts.mnem(insn);
            if (m.equals("cmp") || m.equals("test") || m.startsWith("j")) {
                continue;
            }
            boolean regDest = InsnFacts.isRegisterOperand(insn, 0);
            if (regDest && (m.equals("mov") || m.equals("xor") || m.equals("or") || m.equals("and")
                || m.equals("movzx") || m.startsWith("set"))) {
                continue;
            }
            return false;
        }
        return n > 0;
    }

    /**
     * Every call to 'callee' follows an annotation of its own block with no other
     * call in between: the statement written there is that call, under whatever
     * name the model gave it.
     */
    static boolean callSitesAnnotated(Function f, Address callee, TreeSet<Long> notes, Cfg cfg) {
        Program program = f.getProgram();
        int sites = 0;
        InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            if (!InsnFacts.isCall(insn) || !callee.equals(InsnFacts.callTarget(insn))) {
                continue;
            }
            sites++;
            long ea = insn.getAddress().getOffset();
            Long note = notes.floor(ea);
            if (note == null) {
                return false;
            }
            int blk = cfg.blockIndex(insn.getAddress());
            Address noteAddr = Names.toAddress(program, note);
            if (blk < 0 || noteAddr == null || cfg.blockIndex(noteAddr) != blk) {
                return false;
            }
            for (Instruction x : cfg.blocks.get(blk).insns) {
                long xa = x.getAddress().getOffset();
                if (xa >= note && xa < ea && InsnFacts.isCall(x)) {
                    return false;
                }
            }
        }
        return sites > 0;
    }

    private static void addList(List<String> out, String what, List<String> items) {
        if (!items.isEmpty()) {
            out.add(what + " " + Text.shortList(items, MAX_LISTED));
        }
    }

    /** The address of a finding ("0x401020", "401020"), NO_ADDRESS if it is not a number. */
    static long parseFindingAddress(String s) {
        String t = Text.trim(s).toLowerCase(java.util.Locale.ROOT);
        if (t.startsWith("0x")) {
            t = t.substring(2);
        }
        try {
            return t.isEmpty() || t.length() > 16 ? CodeShaper.NO_ADDRESS : Long.parseUnsignedLong(t, 16);
        }
        catch (NumberFormatException e) {
            return CodeShaper.NO_ADDRESS;
        }
    }

    /**
     * The findings anchored to the listing: each address must fall in an
     * instruction of the function (an address inside one moves to its start).
     * The others are dropped, and so is a finding left without addresses, with
     * a warning: nothing is highlighted where the model only guessed.
     */
    public static List<Backend.Finding> anchorFindings(Function f, List<Backend.Finding> findings,
                                                       List<String> warnings) {
        List<Backend.Finding> out = new ArrayList<>();
        if (f == null) {
            return out;
        }
        Program program = f.getProgram();
        for (Backend.Finding x : findings) {
            List<String> kept = new ArrayList<>();
            List<String> bad = new ArrayList<>();
            for (String s : x.addresses()) {
                long ea = parseFindingAddress(s);
                Address a = ea != CodeShaper.NO_ADDRESS ? Names.toAddress(program, ea) : null;
                Instruction insn = a != null ? program.getListing().getInstructionContaining(a) : null;
                if (insn == null || !f.getBody().contains(insn.getAddress())) {
                    bad.add(s);
                    continue;
                }
                String hex = Names.hex(insn.getAddress());
                if (!kept.contains(hex)) {
                    kept.add(hex);
                }
            }
            String what = x.level() + " " + (x.bugClass().isEmpty() ? "finding" : x.bugClass());
            if (kept.isEmpty()) {
                warnings.add("security finding dropped (" + what + "): no address is an instruction of the function "
                    + Text.shortList(x.addresses(), MAX_LISTED));
                continue;
            }
            if (!bad.isEmpty()) {
                addList(warnings, "security finding (" + what + "): addresses outside the function ignored:", bad);
            }
            out.add(new Backend.Finding(x.level(), x.bugClass(), kept, x.description(), x.precondition()));
        }
        return out;
    }

    /** One readable warning per problem, empty if none. */
    public static List<String> validate(Function f, Backend.DecompResult res, TaskMonitor monitor)
        throws CancelledException {
        List<String> out = new ArrayList<>();
        if (f == null) {
            return out;
        }
        Program program = f.getProgram();
        List<Long> notes = CodeShaper.annotations(res.code);
        TreeSet<Long> uniq = new TreeSet<>(notes);
        Cfg cfg = new Cfg(f, monitor);

        // calls: by name, or else by an annotated statement right before each call
        // site (a callee the model renamed, e.g. a COMDAT-folded destructor)
        List<String> missingCalls = new ArrayList<>();
        for (Address callee : Collector.functionCallees(f)) {
            if (isCompilerHelper(program, callee) || isDestructor(program, callee)
                || isArithmeticHelper(program, callee)) {
                continue;
            }
            List<String> names = Names.calleeNameVariants(program, callee);
            boolean found = isThrowHelper(program, callee) && Text.hasWord(res.code, "throw");
            for (String n : names) {
                found |= Text.hasWord(res.code, n);
            }
            if (!found) {
                found = callSitesAnnotated(f, callee, uniq, cfg);
            }
            if (!found) {
                missingCalls.add(names.isEmpty() ? Names.hex(callee) : names.get(0));
            }
        }
        addList(out, "missing calls to", missingCalls);

        // annotations
        if (notes.isEmpty()) {
            out.add("the code has no /*0x...*/ address annotations: it cannot be checked against the listing");
            return out;
        }
        List<String> outside = new ArrayList<>();
        List<String> notInsn = new ArrayList<>();
        for (long ea : uniq) {
            Address a = Names.toAddress(program, ea);
            if (a == null || !f.getBody().contains(a)) {
                outside.add(Text.hex(ea));
            }
            else if (program.getListing().getInstructionAt(a) == null) {
                notInsn.add(Text.hex(ea));
            }
        }
        addList(out, "annotations outside the function:", outside);
        addList(out, "annotations that are not an instruction address:", notInsn);

        // coverage
        int n = cfg.size();
        boolean[] ok = new boolean[n];
        for (int i = 0; i < n; i++) {
            Cfg.Block b = cfg.blocks.get(i);
            Long p = uniq.ceiling(b.start.getOffset());
            boolean annotated = false;
            for (; p != null && p <= b.end.getOffset(); p = uniq.higher(p)) {
                Address a = Names.toAddress(program, p);
                if (a != null && b.contains(a)) {
                    annotated = true;
                    break;
                }
            }
            ok[i] = annotated || trivialBlock(program, b);
        }
        // the other tests of 'a || b', the arms of 'c ? x : y' or of a boolean
        // being built: expression pieces reached only from covered blocks or from
        // other such pieces, merged in the statement of the covered block
        for (boolean changed = true; changed; ) {
            changed = false;
            for (int i = 0; i < n; i++) {
                Cfg.Block b = cfg.blocks.get(i);
                if (ok[i] || b.pred.isEmpty() || !mergedBlock(b)) {
                    continue;
                }
                boolean predsOk = true;
                for (int pr : b.pred) {
                    predsOk &= ok[pr];
                }
                if (predsOk) {
                    ok[i] = true;
                    changed = true;
                }
            }
        }
        List<String> uncovered = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (!ok[i]) {
                uncovered.add(Names.hex(cfg.blocks.get(i).start));
            }
        }
        if (!uncovered.isEmpty()) {
            addList(out, String.format("%d of %d basic block(s) not covered by any annotation:", uncovered.size(), n),
                uncovered);
        }
        return out;
    }
}
