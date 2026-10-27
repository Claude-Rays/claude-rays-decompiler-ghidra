package org.clauderays.ghidra.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BiPredicate;

/**
 * The relation a conditional branch tests, for any processor: the condition
 * of the branch p-code is followed back through the instructions that compute
 * it (flags, or a compare into a register as MIPS 'slt'), down to one or two
 * values, then evaluated on test values and matched against the known
 * relations ('signed <', 'unsigned >=', '==', 'float <', bit tests). A fact
 * only when exactly one relation gives the same result on every test value:
 * never a guess.
 */
final class PcodeCondition {

    private static final int MAX_BACK = 8;        // instructions looked at before the branch
    private static final int MAX_NODES = 256;

    //--------------------------------------------------------------------------
    // expressions
    //--------------------------------------------------------------------------
    private abstract static class Expr {
        final int size;

        Expr(int size) {
            this.size = size;
        }
    }

    private static final class Leaf extends Expr {
        final int index;

        Leaf(int index, int size) {
            super(size);
            this.index = index;
        }
    }

    private static final class Const extends Expr {
        final long value;

        Const(long value, int size) {
            super(size);
            this.value = value & mask(size);
        }
    }

    private static final class Op extends Expr {
        final int opcode;
        final Expr[] in;

        Op(int opcode, Expr[] in, int size) {
            super(size);
            this.opcode = opcode;
            this.in = in;
        }
    }

    /** Bytes [shift, shift + size) of a wider value. */
    private static final class Part extends Expr {
        final Expr whole;
        final int shift;

        Part(Expr whole, int shift, int size) {
            super(size);
            this.whole = whole;
            this.shift = shift;
        }
    }

    /** One value the condition depends on: a register read, or a load. */
    private static final class LeafInfo {
        final String key;
        /** the register, null for a load */
        final Register reg;
        /** the window instruction that reads it */
        final int insn;
        final int size;
        /** flags set before the window (in a previous block) */
        final boolean flag;

        LeafInfo(String key, Register reg, int insn, int size, boolean flag) {
            this.key = key;
            this.reg = reg;
            this.insn = insn;
            this.size = size;
            this.flag = flag;
        }
    }

    private static final class Fail extends RuntimeException {
        Fail() {
            super(null, null, false, true);
        }
    }

    private final ArchInfo arch;
    /** oldest first, the branch last */
    private final List<Instruction> window = new ArrayList<>();
    private final List<PcodeOp[]> pcode = new ArrayList<>();
    private final List<LeafInfo> leaves = new ArrayList<>();
    private int nodes;
    /** the oldest window instruction the condition comes from */
    private int setter;
    private boolean floats;
    /** what relation() did, for debugging (null: not recorded) */
    private StringBuilder trace;

    private PcodeCondition(ArchInfo arch) {
        this.arch = arch;
    }

    static long mask(int size) {
        return size >= 8 ? -1L : (1L << (size * 8)) - 1;
    }

    static long sext(long v, int size) {
        if (size >= 8) {
            return v;
        }
        int sh = 64 - size * 8;
        return (v << sh) >> sh;
    }

    //--------------------------------------------------------------------------
    // the slice
    //--------------------------------------------------------------------------
    private static boolean overlaps(Varnode a, Varnode b) {
        if (a.getSpace() != b.getSpace()) {
            return false;
        }
        long a0 = a.getOffset();
        long b0 = b.getOffset();
        return a0 < b0 + b.getSize() && b0 < a0 + a.getSize();
    }

    private static boolean contains(Varnode whole, Varnode part) {
        return whole.getSpace() == part.getSpace() && part.getOffset() >= whole.getOffset()
            && part.getOffset() + part.getSize() <= whole.getOffset() + whole.getSize();
    }

    private static boolean isCompare(int opc) {
        return switch (opc) {
            case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS,
                PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL, PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL,
                PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL, PcodeOp.FLOAT_NAN, PcodeOp.BOOL_NEGATE,
                PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR -> true;
            default -> false;
        };
    }

    /** The definition of a register is a comparison (through zero-extensions and copies). */
    private boolean definedByCompare(int insn, int opIndex) {
        PcodeOp[] ops = pcode.get(insn);
        PcodeOp op = ops[opIndex];
        for (int guard = 0; guard < 8; guard++) {
            int opc = op.getOpcode();
            if (isCompare(opc)) {
                return true;
            }
            if (opc != PcodeOp.INT_ZEXT && opc != PcodeOp.COPY) {
                return false;
            }
            Varnode in = op.getInput(0);
            PcodeOp def = null;
            for (int i = opIndex - 1; i >= 0 && def == null; i--) {
                Varnode out = ops[i].getOutput();
                if (out != null && out.equals(in)) {
                    def = ops[i];
                    opIndex = i;
                }
            }
            if (def == null) {
                return false;
            }
            op = def;
        }
        return false;
    }

    /** The value of 'vn' as read by op 'opIndex' of window instruction 'insn'. */
    private Expr value(Varnode vn, int insn, int opIndex) {
        if (++nodes > MAX_NODES || vn.getSize() > 8) {
            throw new Fail();
        }
        if (vn.isConstant()) {
            return new Const(vn.getOffset(), vn.getSize());
        }
        if (vn.isRegister()) {
            Register r = arch.reg(vn);
            if (r != null && r.isZero()) {
                return new Const(0, vn.getSize());
            }
        }
        if (!vn.isRegister() && !vn.isUnique()) {
            throw new Fail();       // a direct memory varnode
        }
        // the same instruction first, then the previous ones
        for (int i = insn; i >= 0; i--) {
            PcodeOp[] ops = pcode.get(i);
            int from = i == insn ? opIndex - 1 : ops.length - 1;
            for (int k = from; k >= 0; k--) {
                Varnode out = ops[k].getOutput();
                if (out == null || !overlaps(out, vn)) {
                    continue;
                }
                if (!contains(out, vn)) {
                    throw new Fail();
                }
                if (i != insn && !arch.isFlag(vn) && !definedByCompare(i, k)) {
                    return leaf(vn, insn);
                }
                setter = Math.min(setter, i);
                Expr whole = define(i, k);
                if (out.getSize() == vn.getSize()) {
                    return whole;
                }
                long off = vn.getOffset() - out.getOffset();
                int shift = (int) (arch.bigEndian ? out.getSize() - vn.getSize() - off : off);
                return new Part(whole, shift, vn.getSize());
            }
            if (vn.isUnique()) {
                throw new Fail();      // temporaries do not cross instructions
            }
        }
        // flags from a previous block: a value the relation must not depend on
        return leaf(vn, insn);
    }

    private Expr leaf(Varnode vn, int insn) {
        // the same register read by the same instruction is the same value
        String key = vn.getSpace() + ":" + vn.getOffset() + ":" + vn.getSize() + "@" + insn;
        for (int i = 0; i < leaves.size(); i++) {
            if (leaves.get(i).key.equals(key)) {
                return new Leaf(i, vn.getSize());
            }
        }
        leaves.add(new LeafInfo(key, arch.reg(vn), insn, vn.getSize(), arch.isFlag(vn)));
        return new Leaf(leaves.size() - 1, vn.getSize());
    }

    private Expr define(int insn, int opIndex) {
        PcodeOp op = pcode.get(insn)[opIndex];
        int opc = op.getOpcode();
        int size = op.getOutput().getSize();
        if (opc == PcodeOp.LOAD) {
            if (++nodes > MAX_NODES || size > 8) {
                throw new Fail();
            }
            String key = "load@" + insn + ":" + opIndex;
            leaves.add(new LeafInfo(key, null, insn, size, false));
            return new Leaf(leaves.size() - 1, size);
        }
        if (!supported(opc)) {
            throw new Fail();
        }
        if (opc >= PcodeOp.FLOAT_EQUAL && opc <= PcodeOp.FLOAT_NAN) {
            floats = true;
        }
        Expr[] in = new Expr[op.getNumInputs()];
        for (int i = 0; i < in.length; i++) {
            in[i] = value(op.getInput(i), insn, opIndex);
        }
        return new Op(opc, in, size);
    }

    private static boolean supported(int opc) {
        return switch (opc) {
            case PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_AND, PcodeOp.INT_OR,
                PcodeOp.INT_XOR, PcodeOp.INT_NEGATE, PcodeOp.INT_2COMP, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL,
                PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW,
                PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_AND,
                PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.POPCOUNT,
                PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL, PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL,
                PcodeOp.FLOAT_NAN, PcodeOp.FLOAT_NEG, PcodeOp.FLOAT_ABS, PcodeOp.FLOAT_FLOAT2FLOAT -> true;
            default -> false;
        };
    }

    //--------------------------------------------------------------------------
    // evaluation
    //--------------------------------------------------------------------------
    private static double fl(long bits, int size) {
        return size == 4 ? Float.intBitsToFloat((int) bits) : Double.longBitsToDouble(bits);
    }

    private static long flBits(double v, int size) {
        return size == 4 ? Float.floatToRawIntBits((float) v) & 0xffffffffL : Double.doubleToRawLongBits(v);
    }

    private static long b(boolean v) {
        return v ? 1 : 0;
    }

    static long eval(Expr e, long[] vals) {
        if (e instanceof Leaf l) {
            return vals[l.index] & mask(l.size);
        }
        if (e instanceof Const c) {
            return c.value;
        }
        if (e instanceof Part p) {
            long w = eval(p.whole, vals);
            return p.shift >= 8 ? 0 : (w >>> (p.shift * 8)) & mask(p.size);
        }
        Op o = (Op) e;
        long a = eval(o.in[0], vals);
        int as = o.in[0].size;
        long c = o.in.length > 1 ? eval(o.in[1], vals) : 0;
        long m = mask(o.size);
        long r = switch (o.opcode) {
            case PcodeOp.COPY, PcodeOp.INT_ZEXT -> a;
            case PcodeOp.INT_SEXT -> sext(a, as);
            case PcodeOp.INT_ADD -> a + c;
            case PcodeOp.INT_SUB -> a - c;
            case PcodeOp.INT_MULT -> a * c;
            case PcodeOp.INT_AND -> a & c;
            case PcodeOp.INT_OR -> a | c;
            case PcodeOp.INT_XOR -> a ^ c;
            case PcodeOp.INT_NEGATE -> ~a;
            case PcodeOp.INT_2COMP -> -a;
            case PcodeOp.INT_EQUAL -> b(a == c);
            case PcodeOp.INT_NOTEQUAL -> b(a != c);
            case PcodeOp.INT_LESS -> b(Long.compareUnsigned(a, c) < 0);
            case PcodeOp.INT_LESSEQUAL -> b(Long.compareUnsigned(a, c) <= 0);
            case PcodeOp.INT_SLESS -> b(sext(a, as) < sext(c, as));
            case PcodeOp.INT_SLESSEQUAL -> b(sext(a, as) <= sext(c, as));
            case PcodeOp.INT_CARRY -> b(Long.compareUnsigned((a + c) & mask(as), a) < 0);
            case PcodeOp.INT_SCARRY -> {
                long s = sext(a + c, as);
                long x = sext(a, as);
                long y = sext(c, as);
                yield b((x >= 0) == (y >= 0) && (s >= 0) != (x >= 0));
            }
            case PcodeOp.INT_SBORROW -> {
                long s = sext(a - c, as);
                long x = sext(a, as);
                long y = sext(c, as);
                yield b((x >= 0) != (y >= 0) && (s >= 0) != (x >= 0));
            }
            case PcodeOp.INT_LEFT -> Long.compareUnsigned(c, as * 8L) >= 0 ? 0 : a << c;
            case PcodeOp.INT_RIGHT -> Long.compareUnsigned(c, as * 8L) >= 0 ? 0 : a >>> c;
            case PcodeOp.INT_SRIGHT -> sext(a, as) >> (Long.compareUnsigned(c, 63) > 0 ? 63 : c);
            case PcodeOp.BOOL_NEGATE -> (a & 1) ^ 1;
            case PcodeOp.BOOL_AND -> a & c & 1;
            case PcodeOp.BOOL_OR -> (a | c) & 1;
            case PcodeOp.BOOL_XOR -> (a ^ c) & 1;
            case PcodeOp.SUBPIECE -> c >= 8 ? 0 : a >>> (c * 8);
            case PcodeOp.PIECE -> (a << (o.in[1].size * 8)) | c;
            case PcodeOp.POPCOUNT -> Long.bitCount(a);
            case PcodeOp.FLOAT_EQUAL -> b(fl(a, as) == fl(c, as));
            case PcodeOp.FLOAT_NOTEQUAL -> b(fl(a, as) != fl(c, as));
            case PcodeOp.FLOAT_LESS -> b(fl(a, as) < fl(c, as));
            case PcodeOp.FLOAT_LESSEQUAL -> b(fl(a, as) <= fl(c, as));
            case PcodeOp.FLOAT_NAN -> b(Double.isNaN(fl(a, as)));
            case PcodeOp.FLOAT_NEG -> flBits(-fl(a, as), o.size);
            case PcodeOp.FLOAT_ABS -> flBits(Math.abs(fl(a, as)), o.size);
            case PcodeOp.FLOAT_FLOAT2FLOAT -> flBits(fl(a, as), o.size);
            default -> throw new Fail();
        };
        return r & m;
    }

    //--------------------------------------------------------------------------
    // relations
    //--------------------------------------------------------------------------
    private record Relation(String name, BiPredicate<Long, Long> test) {
    }

    private static List<Relation> intRelations(int size, boolean againstZero) {
        String z = againstZero ? " 0" : "";
        List<Relation> out = new ArrayList<>();
        out.add(new Relation("==" + z, (a, c) -> a.longValue() == c.longValue()));
        out.add(new Relation("!=" + z, (a, c) -> a.longValue() != c.longValue()));
        out.add(new Relation("signed <" + z, (a, c) -> sext(a, size) < sext(c, size)));
        out.add(new Relation("signed <=" + z, (a, c) -> sext(a, size) <= sext(c, size)));
        out.add(new Relation("signed >" + z, (a, c) -> sext(a, size) > sext(c, size)));
        out.add(new Relation("signed >=" + z, (a, c) -> sext(a, size) >= sext(c, size)));
        if (!againstZero) {
            out.add(new Relation("unsigned <", (a, c) -> Long.compareUnsigned(a, c) < 0));
            out.add(new Relation("unsigned <=", (a, c) -> Long.compareUnsigned(a, c) <= 0));
            out.add(new Relation("unsigned >", (a, c) -> Long.compareUnsigned(a, c) > 0));
            out.add(new Relation("unsigned >=", (a, c) -> Long.compareUnsigned(a, c) >= 0));
            out.add(new Relation("(a & b) == 0", (a, c) -> (a & c) == 0));
            out.add(new Relation("(a & b) != 0", (a, c) -> (a & c) != 0));
        }
        return out;
    }

    private static List<Relation> floatRelations(int size, boolean againstZero) {
        String z = againstZero ? " 0" : "";
        List<Relation> out = new ArrayList<>();
        String[] ops = { "<", "<=", ">", ">=", "==", "!=" };
        for (String op : ops) {
            BiPredicate<Double, Double> t = switch (op) {
                case "<" -> (x, y) -> x < y;
                case "<=" -> (x, y) -> x <= y;
                case ">" -> (x, y) -> x > y;
                case ">=" -> (x, y) -> x >= y;
                case "==" -> (x, y) -> x.doubleValue() == y.doubleValue();
                default -> (x, y) -> x.doubleValue() != y.doubleValue() && !x.isNaN() && !y.isNaN();
            };
            out.add(new Relation("float " + op + z + (op.equals("!=") ? " (and ordered)" : ""),
                (a, c) -> t.test(fl(a, size), fl(c, size))));
            out.add(new Relation("float " + op + z + " (or unordered)", (a, c) -> {
                double x = fl(a, size);
                double y = fl(c, size);
                return Double.isNaN(x) || Double.isNaN(y) || t.test(x, y);
            }));
        }
        out.add(new Relation("float unordered (NaN)", (a, c) -> Double.isNaN(fl(a, size)) || Double.isNaN(fl(c, size))));
        out.add(new Relation("float ordered (no NaN)",
            (a, c) -> !Double.isNaN(fl(a, size)) && !Double.isNaN(fl(c, size))));
        return out;
    }

    private static List<Long> intValues(int size, Long k) {
        long m = mask(size);
        long min = size >= 8 ? Long.MIN_VALUE : 1L << (size * 8 - 1);
        List<Long> v = new ArrayList<>(List.of(0L, 1L, 2L, 3L, -1L, -2L, -3L, min, min + 1, min - 1, min - 2,
            0x7fL, 0x80L, 0xffL, 0x100L, 0x5555555555555555L, 0xaaaaaaaaaaaaaaaaL));
        if (k != null) {
            v.addAll(List.of(k - 1, k, k + 1, ~k, -k));
        }
        Random rnd = new Random(0x5eed);
        for (int i = 0; i < 16; i++) {
            v.add(rnd.nextLong());
        }
        List<Long> out = new ArrayList<>();
        for (long x : v) {
            if (!out.contains(x & m)) {
                out.add(x & m);
            }
        }
        return out;
    }

    private static List<Long> floatValues(int size) {
        double[] d = { 0.0, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, 3.5, -3.5, 1e30, -1e30, Double.POSITIVE_INFINITY,
            Double.NEGATIVE_INFINITY, Double.NaN };
        List<Long> out = new ArrayList<>();
        for (double x : d) {
            out.add(flBits(x, size));
        }
        return out;
    }

    /**
     * The first relation that gives the same result as 'cond' on every pair:
     * leaf 'ia' takes the values 'as', leaf 'ic' (-1 if none: the constant
     * 'fixed') the values 'cs', the other leaves are 0. null if none.
     */
    private String match(Expr cond, List<Relation> rels, List<Long> as, List<Long> cs, int ia, int ic, long fixed) {
        long[] vals = new long[leaves.size()];
        for (Relation r : rels) {
            boolean ok = true;
            for (int i = 0; i < as.size() && ok; i++) {
                for (int j = 0; j < (ic >= 0 ? cs.size() : 1) && ok; j++) {
                    vals[ia] = as.get(i);
                    long c = ic >= 0 ? cs.get(j) : fixed;
                    if (ic >= 0) {
                        vals[ic] = c;
                    }
                    long got = eval(cond, vals);
                    ok = (got != 0) == r.test.test(vals[ia], c);
                }
            }
            if (ok) {
                return r.name;
            }
        }
        return null;
    }

    /**
     * The leaves the condition depends on: changing one of them changes the
     * result for some values of the others (PowerPC 'bgt' reads the cr0 field
     * that 'cmpw' also fills with the summary overflow bit, unused). Every
     * combination of edge values, so equal values are tried too.
     */
    private boolean[] relevantLeaves(Expr cond) {
        int n = leaves.size();
        boolean[] rel = new boolean[n];
        long[] edges = { 0, 1, 2, -1, -2, Long.MIN_VALUE, Long.MAX_VALUE, 0x41, 0x80000000L, 0x7fffffffL };
        long[] vals = new long[n];
        int combos = 1;
        for (int i = 0; i < n; i++) {
            combos *= edges.length;
        }
        for (int t = 0; t < combos; t++) {
            for (int i = 0, x = t; i < n; i++, x /= edges.length) {
                vals[i] = edges[x % edges.length];
            }
            long base = eval(cond, vals);
            for (int i = 0; i < n; i++) {
                if (rel[i]) {
                    continue;
                }
                long save = vals[i];
                for (long alt : edges) {
                    vals[i] = alt;
                    if (eval(cond, vals) != base) {
                        rel[i] = true;
                        break;
                    }
                }
                vals[i] = save;
            }
        }
        return rel;
    }

    /** The operand of 'insn' that holds the leaf, -1 if not found. */
    private static int operandOf(Instruction insn, LeafInfo leaf) {
        for (int n = 0; n < insn.getNumOperands(); n++) {
            if (leaf.reg == null) {
                if (OperandType.isDynamic(insn.getOperandType(n))
                    || insn.getDefaultOperandRepresentation(n).contains("[")) {
                    return n;
                }
                continue;
            }
            for (Object o : insn.getOpObjects(n)) {
                Register r = ArchInfo.base(o);
                if (leaf.reg.equals(r)) {
                    return n;
                }
            }
        }
        return -1;
    }

    /** The single immediate operand of 'insn' (no register in it), null if none or several. */
    private static Long immediate(Instruction insn) {
        Long k = null;
        for (int n = 0; n < insn.getNumOperands(); n++) {
            if (OperandType.isAddress(insn.getOperandType(n))) {
                continue;
            }
            Scalar sc = insn.getScalar(n);
            boolean reg = false;
            for (Object o : insn.getOpObjects(n)) {
                reg |= o instanceof Register;
                if (sc == null && o instanceof Scalar s) {
                    sc = s;         // '#0x3' of tbnz, not reported as a scalar operand
                }
            }
            if (sc == null || reg) {
                continue;
            }
            if (k != null) {
                return null;
            }
            k = sc.getValue();
        }
        return k;
    }

    private String relation(Instruction branch, Address blockStart) {
        // the window: the branch and the instructions before it in the block, up to a call
        Instruction p = branch;
        List<Instruction> rev = new ArrayList<>();
        rev.add(branch);
        for (int i = 0; i < MAX_BACK; i++) {
            p = p.getPrevious();
            if (p == null || p.getAddress().compareTo(blockStart) < 0 || p.getFlowType().isCall()
                || p.getFlowType().isJump() || p.getFlowType().isTerminal()) {
                break;
            }
            rev.add(p);
        }
        for (int i = rev.size() - 1; i >= 0; i--) {
            window.add(rev.get(i));
            pcode.add(rev.get(i).getPcode());
        }
        int last = window.size() - 1;
        PcodeOp[] ops = pcode.get(last);
        int cb = -1;
        for (int i = ops.length - 1; i >= 0 && cb < 0; i--) {
            if (ops[i].getOpcode() == PcodeOp.CBRANCH && !ops[i].getInput(0).isConstant()) {
                cb = i;
            }
        }
        if (cb < 0) {
            return "";
        }
        setter = last;
        Expr cond = value(ops[cb].getInput(1), last, cb);
        if (leaves.isEmpty() || leaves.size() > 3 || cond.size != 1) {
            return "";
        }
        boolean[] relevant = relevantLeaves(cond);
        if (trace != null) {
            for (int i = 0; i < leaves.size(); i++) {
                LeafInfo l = leaves.get(i);
                trace.append(String.format("leaf %d %s reg %s insn %d size %d flag %b relevant %b operand %d%n", i,
                    l.key, l.reg, l.insn, l.size, l.flag, relevant[i], operandOf(window.get(l.insn), l)));
            }
        }
        List<Integer> used = new ArrayList<>();
        for (int i = 0; i < relevant.length; i++) {
            if (relevant[i]) {
                if (leaves.get(i).flag) {
                    return "";      // flags from a previous block
                }
                used.add(i);
            }
        }
        if (used.isEmpty() || used.size() > 2) {
            return "";
        }
        int ia = used.get(0);
        LeafInfo a = leaves.get(ia);
        String rel;
        if (used.size() == 2) {
            int ic = used.get(1);
            LeafInfo c = leaves.get(ic);
            if (a.insn != c.insn || a.size != c.size) {
                return "";
            }
            Instruction at = window.get(a.insn);
            int na = operandOf(at, a);
            int nc = operandOf(at, c);
            if (na < 0 || nc < 0 || na == nc) {
                return "";
            }
            if (na > nc) {
                // relations are 'first operand REL second operand'
                int t = ia;
                ia = ic;
                ic = t;
            }
            List<Long> vs = floats ? floatValues(a.size) : intValues(a.size, null);
            rel = match(cond, floats ? floatRelations(a.size, false) : intRelations(a.size, false), vs, vs, ia, ic, 0);
        }
        else {
            Long k = immediate(window.get(a.insn));
            // against zero, given or implied (cbz, beqz, a register compared with zero)
            boolean zero = k == null || k == 0;
            long kv = zero ? (floats ? flBits(0.0, a.size) : 0) : k & mask(a.size);
            List<Long> vs = floats ? floatValues(a.size) : intValues(a.size, zero ? null : kv);
            List<Relation> rels = floats ? floatRelations(a.size, zero) : intRelations(a.size, zero);
            if (!zero && !floats && k >= 0 && k < a.size * 8L) {
                // a bit number (tbz / tbnz, bbit)
                long bit = 1L << k;
                rels.add(new Relation("bit " + k + " == 0", (x, c) -> (x & bit) == 0));
                rels.add(new Relation("bit " + k + " == 1", (x, c) -> (x & bit) != 0));
            }
            rel = match(cond, rels, vs, null, ia, -1, kv);
        }
        if (rel == null) {
            return "";
        }
        if (setter < last - 1) {
            rel += " (condition set at " + Names.addr(window.get(setter).getAddress()) + ")";
        }
        return rel;
    }

    /** How the relation of 'branch' was found, or why not (for the checks). */
    static String explain(Instruction branch, Address blockStart) {
        PcodeCondition pc = new PcodeCondition(ArchInfo.of(branch.getProgram()));
        pc.trace = new StringBuilder();
        try {
            pc.trace.append("relation '").append(pc.relation(branch, blockStart)).append("'\n");
        }
        catch (Fail e) {
            StackTraceElement[] st = e.getStackTrace();
            pc.trace.append("failed at ").append(st.length > 0 ? st[0] : "?").append('\n');
        }
        return pc.trace.toString();
    }

    /** The relation tested by the conditional branch 'branch', "" if not exactly known. */
    static String of(Instruction branch, Address blockStart) {
        try {
            return new PcodeCondition(ArchInfo.of(branch.getProgram())).relation(branch, blockStart);
        }
        catch (Fail e) {
            return "";
        }
    }
}
