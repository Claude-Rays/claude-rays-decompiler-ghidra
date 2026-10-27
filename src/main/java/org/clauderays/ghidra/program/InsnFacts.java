package org.clauderays.ghidra.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import org.clauderays.ghidra.core.InsnTable;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Annotated instruction facts: the facts the plugin computes
 * exactly from the instruction semantics so the model does not have to guess
 * them: signedness of conditional jumps, size and extension of memory
 * accesses, call properties, constants. x86 / x64 from the mnemonics;
 * any other processor from the p-code (fewer facts, as exact).
 */
public final class InsnFacts {

    private static final int MAX_RESULT_SCAN = 12;    // instructions looked at after a call
    private static final Set<String> RESULT_REGS = Set.of("RAX", "EAX", "XMM0", "YMM0", "ZMM0", "ST0");

    private InsnFacts() {
    }

    /** Every processor has instruction facts: x86 / x64 from the mnemonics, the others from the p-code. */
    public static boolean hasInsnFacts(Program program) {
        return program != null;
    }

    static boolean isX86(Program program) {
        return ArchInfo.of(program).x86;
    }

    /** The lowercase mnemonic without Ghidra's prefix suffixes ("stosb.rep" -> "stosb"). */
    public static String mnem(Instruction insn) {
        String m = insn.getMnemonicString().toLowerCase(Locale.ROOT);
        int dot = m.indexOf('.');
        return dot > 0 ? m.substring(0, dot) : m;
    }

    /** A rep / repe / repne prefix (".REP" suffix of the mnemonic in Ghidra). */
    static boolean hasRep(Instruction insn) {
        String m = insn.getMnemonicString().toLowerCase(Locale.ROOT);
        return m.contains(".rep");
    }

    static String operandText(Instruction insn, int n) {
        if (n >= insn.getNumOperands()) {
            return "";
        }
        return insn.getDefaultOperandRepresentation(n).toLowerCase(Locale.ROOT);
    }

    static boolean isCall(Instruction insn) {
        return insn.getFlowType().isCall();
    }

    static boolean isRet(Instruction insn) {
        return insn.getFlowType().isTerminal();
    }

    /** An explicit memory operand ("dword ptr [rbp + -0x10]"). */
    static boolean isMemOperand(Instruction insn, int n) {
        return operandText(insn, n).contains("[");
    }

    /** A memory operand addressed through registers (o_phrase / o_displ), not an absolute one. */
    static boolean isRegisterMemOperand(Instruction insn, int n) {
        if (!isMemOperand(insn, n)) {
            return false;
        }
        for (Object o : insn.getOpObjects(n)) {
            if (o instanceof Register r) {
                String name = r.getName().toUpperCase(Locale.ROOT);
                if (!name.equals("RIP") && !name.equals("EIP")) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean isRegisterOperand(Instruction insn, int n) {
        return n < insn.getNumOperands() && insn.getRegister(n) != null && !isMemOperand(insn, n);
    }

    private static boolean isResultReg(Object o) {
        if (!(o instanceof Register r)) {
            return false;
        }
        Register base = r.getBaseRegister();
        return RESULT_REGS.contains(r.getName().toUpperCase(Locale.ROOT))
            || (base != null && RESULT_REGS.contains(base.getName().toUpperCase(Locale.ROOT)));
    }

    private static void addFact(StringBuilder facts, String f) {
        if (f == null || f.isEmpty()) {
            return;
        }
        if (facts.length() > 0) {
            facts.append("; ");
        }
        facts.append(f);
    }

    //--------------------------------------------------------------------------
    /**
     * The function called by the call (or jump) instruction: the direct target,
     * or the import pointer it goes through; null if indirect or unknown.
     */
    public static Address callTarget(Instruction insn) {
        Program program = insn.getProgram();
        Address[] flows = insn.getFlows();
        if (flows != null && flows.length > 0) {
            return flows[0];
        }
        // call [import pointer]: the pointer (as the listing shows it) leads to an external function
        Reference[] refs = insn.getReferencesFrom();
        for (Reference ref : refs) {
            Address to = ref.getToAddress();
            if (!to.isMemoryAddress() || ref.isStackReference()) {
                continue;
            }
            Function f = program.getFunctionManager().getReferencedFunction(to);
            if (f != null && !to.equals(f.getEntryPoint())) {
                return to;
            }
        }
        for (Reference ref : refs) {
            if (ref.isExternalReference() && (ref.getReferenceType().isCall() || ref.getReferenceType().isJump())) {
                return ref.getToAddress();
            }
        }
        return null;
    }

    /** The function the call target resolves to, null if none. */
    static Function targetFunction(Program program, Address target) {
        return Names.functionAt(program, target);
    }

    //--------------------------------------------------------------------------
    /** What the code after a call does with the return register. */
    static String callResultUse(Instruction call, Address blockEnd) {
        ArchInfo arch = ArchInfo.of(call.getProgram());
        Instruction insn = call;
        for (int i = 0; i < MAX_RESULT_SCAN; i++) {
            insn = insn.getNext();
            if (insn == null || insn.getAddress().compareTo(blockEnd) > 0) {
                return "";
            }
            if (insn.isInDelaySlot()) {
                continue;       // runs before the call (MIPS, SPARC)
            }
            String m = mnem(insn);
            if (arch.x86) {
                // zeroing idioms write without reading
                if ((m.equals("xor") || m.equals("sub") || m.equals("pxor") || m.equals("xorps"))
                    && operandText(insn, 0).equals(operandText(insn, 1))
                    && isResultReg(insn.getRegister(0))) {
                    return "result ignored";
                }
                if (m.equals("cdq") || m.equals("cdqe") || m.equals("cqo") || m.equals("cwde")) {
                    return "result used";
                }
            }
            boolean read = false;
            for (Object o : insn.getInputObjects()) {
                read |= arch.x86 ? isResultReg(o) : arch.isReturnReg(o);
            }
            boolean written = false;
            for (Object o : insn.getResultObjects()) {
                written |= arch.x86 ? isResultReg(o) : arch.isReturnReg(o);
            }
            if (read) {
                return "result used";
            }
            if (written) {
                return "result ignored";
            }
            if (isCall(insn)) {
                return "result ignored";
            }
            if (isRet(insn)) {
                return "result returned";
            }
            FlowType ft = insn.getFlowType();
            if (ft.isJump() || ft.isTerminal() || insn.getFallThrough() == null) {
                return "";
            }
        }
        return "";
    }

    /** The facts of a call, or of an unconditional jump ('tail') that may be a tail call. */
    static String callFacts(Instruction insn, boolean tail, Address blockEnd) {
        Program program = insn.getProgram();
        StringBuilder facts = new StringBuilder();
        Address target = callTarget(insn);
        boolean x86 = isX86(program);
        // through a pointer in memory: the import pointer of x86 'call [imp]', or a
        // computed flow (blr x16, jalr t9) whose target Ghidra resolved
        boolean throughPtr = x86 ? isMemOperand(insn, 0) && !isRegisterMemOperand(insn, 0)
            : insn.getFlowType().isComputed() && target != null;
        boolean regOrPhrase = x86 ? isRegisterOperand(insn, 0) || isRegisterMemOperand(insn, 0)
            : insn.getFlowType().isComputed() && target == null;
        if (regOrPhrase) {
            addFact(facts, tail ? "indirect jump" : "indirect call");
        }
        else if (throughPtr || x86 && isMemOperand(insn, 0)) {
            if (target != null) {
                addFact(facts, "through import pointer");
            }
            else {
                addFact(facts, tail ? "indirect jump through global pointer" : "indirect call through global pointer");
            }
        }
        if (tail) {
            // a jump to another function is a tail call
            Function cur = program.getFunctionManager().getFunctionContaining(insn.getAddress());
            Function dst = target != null ? targetFunction(program, target) : null;
            boolean outside = target != null && cur != null && !cur.getBody().contains(target);
            Function containing = target != null && target.isMemoryAddress()
                ? program.getFunctionManager().getFunctionContaining(target) : null;
            if (outside && (containing == null || containing.getEntryPoint().equals(target) || dst != null)) {
                String f = "tail call";
                if (x86 ? isMemOperand(insn, 0) : throughPtr) {
                    f += " through import pointer";
                }
                facts.setLength(0);
                facts.append(f);
            }
            else if (facts.length() == 0) {
                return "";
            }
        }
        Function f = target != null ? targetFunction(program, target) : null;
        if (f != null) {
            Function real = f.isThunk() && f.getThunkedFunction(true) != null ? f.getThunkedFunction(true) : f;
            if (f.hasNoReturn() || real.hasNoReturn()) {
                addFact(facts, "noreturn");
            }
        }
        if (!tail) {
            // no result to look for when the callee is known to return void
            boolean isVoid = false;
            if (f != null && f.getSignatureSource() != ghidra.program.model.symbol.SourceType.DEFAULT) {
                DataType rt = f.getReturnType();
                isVoid = rt instanceof VoidDataType;
            }
            if (!isVoid) {
                addFact(facts, callResultUse(insn, blockEnd));
            }
        }
        return facts.length() == 0 ? "" : "call: " + facts;
    }

    //--------------------------------------------------------------------------
    /** The instruction that set the flags read by 'insn', null if not in the block. */
    static Instruction findFlagSetter(Instruction insn, Address blockStart, String[] mnemOut) {
        Instruction p = insn;
        for (int i = 0; i < 16; i++) {
            p = p.getPrevious();
            if (p == null || p.getAddress().compareTo(blockStart) < 0) {
                return null;
            }
            String m = mnem(p);
            if (InsnTable.keepsFlags(m)) {
                continue;
            }
            if (isCall(p)) {
                return null;
            }
            mnemOut[0] = m;
            return p;
        }
        return null;
    }

    static String conditionFacts(Instruction insn, String cc, Address blockStart) {
        String[] setterMnem = new String[1];
        Instruction setter = findFlagSetter(insn, blockStart, setterMnem);
        InsnTable.FlagSetter kind = InsnTable.FlagSetter.UNKNOWN;
        if (setter != null) {
            boolean same = setterMnem[0].equals("test") && operandText(setter, 0).equals(operandText(setter, 1));
            kind = InsnTable.classifyFlagSetter(setterMnem[0], same);
        }
        String rel = InsnTable.ccRelation(cc, kind);
        if (rel.isEmpty()) {
            return "";
        }
        if (setter == null) {
            return rel + " (flags from a previous block)";
        }
        if (kind == InsnTable.FlagSetter.UNKNOWN) {
            rel += " (flags from the " + setterMnem[0] + " result)";
        }
        Instruction prev = insn.getPrevious();
        if (prev == null || !prev.getAddress().equals(setter.getAddress())) {
            rel += " (flags set at " + Names.addr(setter.getAddress()) + ")";
        }
        return rel;
    }

    //--------------------------------------------------------------------------
    /** The size of a memory operand from its "dword ptr" prefix, 0 if not written. */
    static int ptrSize(String op) {
        if (op.startsWith("byte ptr")) {
            return 1;
        }
        if (op.startsWith("word ptr")) {
            return 2;
        }
        if (op.startsWith("dword ptr")) {
            return 4;
        }
        if (op.startsWith("qword ptr")) {
            return 8;
        }
        if (op.startsWith("tword ptr") || op.startsWith("tbyte ptr")) {
            return 10;
        }
        if (op.startsWith("xmmword ptr")) {
            return 16;
        }
        if (op.startsWith("ymmword ptr")) {
            return 32;
        }
        if (op.startsWith("zmmword ptr")) {
            return 64;
        }
        return 0;
    }

    /** The size of the first LOAD or STORE of the instruction p-code, 0 if none. */
    static int pcodeAccessSize(Instruction insn) {
        for (PcodeOp op : insn.getPcode()) {
            if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null) {
                return op.getOutput().getSize();
            }
            if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2) {
                return op.getInput(2).getSize();
            }
        }
        return 0;
    }

    private static final Set<String> X87_INT = Set.of("fild", "fist", "fistp", "fisttp", "fiadd", "fisub",
        "fisubr", "fimul", "fidiv", "fidivr", "ficom", "ficomp", "fldcw", "fnstcw", "fstcw", "fnstsw", "fstsw",
        "fldenv", "fnstenv", "fstenv", "frstor", "fnsave", "fsave", "fxsave", "fxrstor", "fbld", "fbstp");

    /** The memory data of the instruction is floating point (x87 or scalar SSE). */
    static boolean floatData(String mnem) {
        if (mnem.startsWith("f")) {
            return !X87_INT.contains(mnem);
        }
        if (mnem.startsWith("cvtsi2") || mnem.startsWith("vcvtsi2")) {
            return false;
        }
        return mnem.endsWith("ss") || mnem.endsWith("sd");
    }

    private static final Set<String> STRING_OPS = Set.of("movsb", "movsw", "movsd", "movsq", "stosb", "stosw",
        "stosd", "stosq", "lodsb", "lodsw", "lodsd", "lodsq", "scasb", "scasw", "scasd", "scasq", "cmpsb",
        "cmpsw", "cmpsd", "cmpsq");

    /** A string instruction (its memory operands are implicit in IDA: no facts). */
    static boolean isStringOp(Instruction insn, String mnem) {
        if (!STRING_OPS.contains(mnem)) {
            return false;
        }
        for (int n = 0; n < insn.getNumOperands(); n++) {
            if (operandText(insn, n).startsWith("xmm")) {
                return false;     // the SSE movsd / cmpsd
            }
        }
        return true;
    }

    static String memoryFacts(Instruction insn, String mnem) {
        if (mnem.equals("lea") || mnem.startsWith("nop") || mnem.startsWith("prefetch") || mnem.equals("clflush")
            || isStringOp(insn, mnem)) {
            return "";
        }
        StringBuilder facts = new StringBuilder();
        int ext = InsnTable.extensionKind(mnem);
        for (int n = 0; n < insn.getNumOperands(); n++) {
            String op = operandText(insn, n);
            if (op.contains("[")) {
                RefType rt = insn.getOperandRefType(n);
                boolean use = rt == null || rt.isRead() || (!rt.isWrite());
                boolean chg = rt != null && rt.isWrite();
                String access = use && chg ? "load+store" : chg ? "store" : "load";
                int size = ptrSize(op);
                if (size == 0) {
                    size = pcodeAccessSize(insn);
                }
                boolean isFloat = ext == 0 && floatData(mnem) && size <= 10;
                String f = access + " " + InsnTable.sizeName(size, ext, isFloat);
                if (ext == 1) {
                    f += ", sign-extend";
                }
                else if (ext == 2) {
                    f += ", zero-extend";
                }
                addFact(facts, f);
            }
            else if (ext != 0 && n > 0 && insn.getRegister(n) != null) {
                Register r = insn.getRegister(n);
                addFact(facts, (ext == 1 ? "sign-extend " : "zero-extend ")
                    + InsnTable.sizeName(r.getMinimumByteSize(), ext, false));
            }
        }
        return facts.toString();
    }

    static String constantFacts(Instruction insn, String mnem) {
        Program program = insn.getProgram();
        StringBuilder facts = new StringBuilder();
        for (int n = 0; n < insn.getNumOperands(); n++) {
            Scalar sc = insn.getScalar(n);
            if (sc == null || operandText(insn, n).contains("[")) {
                continue;
            }
            // shown as an equate (enum) or as a reference (offset): already symbolic
            if (insn.getOperandReferences(n).length > 0
                || program.getEquateTable().getEquate(insn.getAddress(), n, sc.getValue()) != null) {
                continue;
            }
            int size = sc.bitLength() / 8;
            long v = sc.getUnsignedValue();
            if (size > 0 && size < 8) {
                v &= (1L << (size * 8)) - 1;
            }
            // a constant that is the address of a named item
            if (Long.compareUnsigned(v, 0x10000) >= 0) {
                Address a = Names.toAddress(program, v);
                if (a != null) {
                    Symbol s = program.getSymbolTable().getPrimarySymbol(a);
                    if (s != null) {
                        addFact(facts, "address of " + s.getName(true));
                        continue;
                    }
                }
            }
            if (Set.of("and", "or", "xor", "test", "shl", "shr", "sar", "rol", "ror").contains(mnem)) {
                continue;
            }
            // single characters only where a character is likely
            boolean single = Long.compareUnsigned(v, 0x100) < 0;
            if (single && !(mnem.equals("cmp") || mnem.equals("sub") || mnem.equals("mov") || mnem.equals("push")
                || size == 1)) {
                continue;
            }
            addFact(facts, InsnTable.asciiConstant(v, size == 0 ? 8 : size));
        }
        return facts.toString();
    }

    //--------------------------------------------------------------------------
    // any processor, from the p-code
    //--------------------------------------------------------------------------
    /** The op of 'ops' before 'end' that writes 'vn', null if none. */
    private static PcodeOp definition(PcodeOp[] ops, int end, Varnode vn) {
        for (int i = end - 1; i >= 0; i--) {
            if (vn.equals(ops[i].getOutput())) {
                return ops[i];
            }
        }
        return null;
    }

    /**
     * The address 'addr' of a LOAD / STORE is computed from the stack pointer,
     * through the registers the instruction itself computes (mult_addr of ARM
     * ldm / stm).
     */
    private static boolean stackAddress(ArchInfo arch, PcodeOp[] ops, int at, Varnode addr) {
        for (int guard = 0; guard < 16 && addr != null; guard++) {
            PcodeOp def = definition(ops, at, addr);
            if (def == null) {
                return addr.isRegister() && arch.sp != null && arch.sp.equals(arch.reg(addr));
            }
            if (def.getNumInputs() == 0) {
                return false;
            }
            int opc = def.getOpcode();
            if (opc != PcodeOp.COPY && opc != PcodeOp.INT_ADD && opc != PcodeOp.INT_SUB && opc != PcodeOp.PTRADD
                && opc != PcodeOp.PTRSUB && opc != PcodeOp.INT_AND) {
                return false;
            }
            at = java.util.Arrays.asList(ops).indexOf(def);
            addr = def.getInput(0);
        }
        return false;
    }

    /** How the loaded value 'out' is extended in the instruction: 1 sign, 2 zero, 0 not. */
    private static int loadExtension(PcodeOp[] ops, int from, Varnode out) {
        for (int i = from + 1; i < ops.length; i++) {
            PcodeOp op = ops[i];
            for (int k = 0; k < op.getNumInputs(); k++) {
                if (out.equals(op.getInput(k))) {
                    return op.getOpcode() == PcodeOp.INT_SEXT ? 1 : op.getOpcode() == PcodeOp.INT_ZEXT ? 2 : 0;
                }
            }
        }
        return 0;
    }

    private static boolean feedsFloat(PcodeOp[] ops, int from, Varnode out) {
        for (int i = from + 1; i < ops.length; i++) {
            PcodeOp op = ops[i];
            for (int k = 0; k < op.getNumInputs(); k++) {
                if (out.equals(op.getInput(k))) {
                    int opc = op.getOpcode();
                    return opc >= PcodeOp.FLOAT_EQUAL && opc <= PcodeOp.FLOAT_ROUND && opc != PcodeOp.FLOAT_INT2FLOAT;
                }
            }
        }
        return false;
    }

    /**
     * Sizes and extensions of the memory accesses, from the LOAD / STORE ops.
     * Several accesses through the stack pointer (push / pop, ldm / stm, ldp /
     * stp of an epilogue) are register saves: no facts.
     */
    static String pcodeMemoryFacts(Instruction insn, ArchInfo arch) {
        PcodeOp[] ops = insn.getPcode();
        java.util.List<String> acc = new java.util.ArrayList<>();
        boolean stack = false;
        Varnode loadAddr = null;
        int loadSize = 0;
        for (int i = 0; i < ops.length; i++) {
            PcodeOp op = ops[i];
            if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null && op.getNumInputs() > 1) {
                Varnode out = op.getOutput();
                int ext = loadExtension(ops, i, out);
                boolean isFloat = ext == 0 && feedsFloat(ops, i, out);
                String f = "load " + InsnTable.sizeName(out.getSize(), ext, isFloat);
                acc.add(ext == 1 ? f + ", sign-extend" : ext == 2 ? f + ", zero-extend" : f);
                stack |= stackAddress(arch, ops, i, op.getInput(1));
                loadAddr = op.getInput(1);
                loadSize = out.getSize();
            }
            else if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2) {
                int size = op.getInput(2).getSize();
                if (acc.size() == 1 && loadSize == size && op.getInput(1).equals(loadAddr)) {
                    acc.set(0, "load+store " + InsnTable.sizeName(size, 0, false));     // a read-modify-write
                    continue;
                }
                acc.add("store " + InsnTable.sizeName(size, 0, false));
                stack |= stackAddress(arch, ops, i, op.getInput(1));
            }
        }
        if (acc.isEmpty() || acc.size() > 1 && stack) {
            return "";
        }
        if (acc.size() > 1 && acc.stream().distinct().count() == 1) {
            return acc.get(0) + " x" + acc.size();
        }
        return String.join("; ", acc);
    }

    /** The opcodes that read the constant 'v' (of the instruction p-code). */
    private static Set<Integer> constantUses(PcodeOp[] ops, long v) {
        Set<Integer> out = new java.util.HashSet<>();
        for (PcodeOp op : ops) {
            for (int k = 0; k < op.getNumInputs(); k++) {
                Varnode in = op.getInput(k);
                if (in.isConstant() && (in.getOffset() & PcodeCondition.mask(in.getSize()))
                    == (v & PcodeCondition.mask(in.getSize()))) {
                    out.add(op.getOpcode());
                }
            }
        }
        return out;
    }

    private static final Set<Integer> MASK_OPS = Set.of(PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR,
        PcodeOp.INT_MULT);
    private static final Set<Integer> SHIFT_OPS = Set.of(PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT);
    private static final Set<Integer> CHAR_OPS = Set.of(PcodeOp.COPY, PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL,
        PcodeOp.INT_SUB, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL,
        PcodeOp.INT_SBORROW, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT);

    /** Immediates: the address of a named item, or ASCII text (as constantFacts, from the p-code). */
    static String pcodeConstantFacts(Instruction insn, ArchInfo arch) {
        Program program = insn.getProgram();
        StringBuilder facts = new StringBuilder();
        PcodeOp[] ops = null;
        for (int n = 0; n < insn.getNumOperands(); n++) {
            Scalar sc = insn.getScalar(n);
            if (sc == null) {
                continue;
            }
            int type = insn.getOperandType(n);
            String text = operandText(insn, n);
            if (OperandType.isDynamic(type) || OperandType.isAddress(type) || text.contains("[")
                || text.contains("(")) {
                continue;       // a displacement or a branch target
            }
            if (insn.getOperandReferences(n).length > 0
                || program.getEquateTable().getEquate(insn.getAddress(), n, sc.getValue()) != null) {
                continue;
            }
            int size = sc.bitLength() / 8;
            long v = sc.getUnsignedValue();
            if (size > 0 && size < 8) {
                v &= (1L << (size * 8)) - 1;
            }
            if (Long.compareUnsigned(v, 0x10000) >= 0) {
                Address a = Names.toAddress(program, v);
                if (a != null) {
                    Symbol s = program.getSymbolTable().getPrimarySymbol(a);
                    if (s != null) {
                        addFact(facts, "address of " + s.getName(true));
                        continue;
                    }
                }
            }
            if (ops == null) {
                ops = insn.getPcode();
            }
            // a mask or a shift count, not text ('cmp r0, #0x41' of ARM also shifts the
            // constant for the carry: that is not a shift count)
            Set<Integer> uses = constantUses(ops, v);
            if (uses.isEmpty() || uses.stream().anyMatch(MASK_OPS::contains)
                || SHIFT_OPS.containsAll(uses)) {
                continue;
            }
            boolean single = Long.compareUnsigned(v, 0x100) < 0;
            if (single ? uses.stream().noneMatch(CHAR_OPS::contains) : arch.bigEndian) {
                continue;       // multi-byte text is spelled in little endian memory order
            }
            addFact(facts, InsnTable.asciiConstant(v, size == 0 ? 8 : size));
        }
        return facts.toString();
    }

    /** The facts of one instruction of a non-x86 processor. */
    static String pcodeFacts(Instruction insn, Address blockStart, Address blockEnd) {
        ArchInfo arch = ArchInfo.of(insn.getProgram());
        FlowType ft = insn.getFlowType();
        StringBuilder facts = new StringBuilder();
        if (ft.isJump() && ft.isConditional()) {
            addFact(facts, PcodeCondition.of(insn, blockStart));
        }
        else if (ft.isCall() || ft.isJump() && !ft.isTerminal()) {
            addFact(facts, callFacts(insn, !ft.isCall(), blockEnd));
            return facts.toString();
        }
        if (!ft.isTerminal()) {
            addFact(facts, pcodeMemoryFacts(insn, arch));
            addFact(facts, pcodeConstantFacts(insn, arch));
        }
        return facts.toString();
    }

    //--------------------------------------------------------------------------
    /** The facts of one instruction of the basic block [blockStart, blockEnd]. */
    public static String factsAt(Instruction insn, Address blockStart, Address blockEnd) {
        if (insn == null || !hasInsnFacts(insn.getProgram())) {
            return "";
        }
        if (!isX86(insn.getProgram())) {
            return pcodeFacts(insn, blockStart, blockEnd);
        }
        String m = mnem(insn);
        StringBuilder facts = new StringBuilder();
        String cc = InsnTable.conditionCode(m);
        if (!cc.isEmpty()) {
            addFact(facts, conditionFacts(insn, cc, blockStart));
        }
        if (isCall(insn) || m.equals("jmp")) {
            addFact(facts, callFacts(insn, m.equals("jmp"), blockEnd));
        }
        else {
            addFact(facts, memoryFacts(insn, m));
            addFact(facts, constantFacts(insn, m));
        }
        addFact(facts, InsnTable.mnemonicFact(m, insn.getNumOperands(), hasRep(insn)));
        return facts.toString();
    }

    /** The facts of every instruction of a block, keyed by address (instructions without facts left out). */
    public static Map<Address, String> blockFacts(Cfg.Block blk) {
        Map<Address, String> out = new LinkedHashMap<>();
        if (blk.insns.isEmpty() || !hasInsnFacts(blk.insns.get(0).getProgram())) {
            return out;
        }
        for (Instruction insn : blk.insns) {
            String f = factsAt(insn, blk.start, blk.end);
            if (!f.isEmpty()) {
                out.put(insn.getAddress(), f);
            }
        }
        return out;
    }
}
