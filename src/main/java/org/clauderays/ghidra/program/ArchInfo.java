package org.clauderays.ghidra.program;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * What the plugin needs to know of the processor, from the language and the
 * compiler spec of the program, for any architecture: the stack pointer, the
 * registers a function must preserve, where results come back, the flags.
 * Registers are kept as base registers (EAX -> RAX, w0 -> x0).
 */
final class ArchInfo {

    private static final Map<Program, ArchInfo> CACHE = new WeakHashMap<>();

    // no reference to the program: it is the key of the cache
    final Language lang;
    final boolean x86;
    final boolean bigEndian;
    /** null if the compiler spec has none */
    final Register sp;
    /** preserved across calls (callee-saved), the stack pointer included */
    final Set<Register> calleeSaved = new HashSet<>();
    /** where an integer, pointer or float result comes back */
    final Set<Register> returnRegs = new HashSet<>();
    /** the return address (lr, ra, x30); empty when it is on the stack */
    final Set<Register> returnAddress = new HashSet<>();
    /** registers that may hold arguments */
    final Set<Register> argRegs = new HashSet<>();

    private ArchInfo(Program program) {
        this.lang = program.getLanguage();
        this.x86 = lang.getProcessor().toString().equalsIgnoreCase("x86");
        this.bigEndian = lang.isBigEndian();
        CompilerSpec cs = program.getCompilerSpec();
        Register s = cs.getStackPointer();
        this.sp = s == null ? null : s.getBaseRegister();
        PrototypeModel model = cs.getDefaultCallingConvention();
        if (model != null) {
            addRegs(calleeSaved, model.getUnaffectedList());
            addRegs(returnAddress, model.getReturnAddress());
            try {
                for (VariableStorage vs : model.getPotentialInputRegisterStorage(program)) {
                    for (Register r : vs.getRegisters()) {
                        if (r != null) {
                            argRegs.add(r.getBaseRegister());
                        }
                    }
                }
            }
            catch (RuntimeException e) {
                // a model without register arguments
            }
            DataType[] results = { PointerDataType.dataType, LongLongDataType.dataType, FloatDataType.dataType,
                DoubleDataType.dataType };
            for (DataType dt : results) {
                try {
                    VariableStorage vs = model.getReturnLocation(dt, program);
                    if (vs != null && (vs.isRegisterStorage() || vs.isCompoundStorage())) {
                        for (Register r : vs.getRegisters()) {
                            if (r != null) {
                                returnRegs.add(r.getBaseRegister());
                            }
                        }
                    }
                }
                catch (RuntimeException e) {
                    // no storage for this type in this model
                }
            }
        }
        if (sp != null) {
            calleeSaved.add(sp);
        }
    }

    static synchronized ArchInfo of(Program program) {
        return CACHE.computeIfAbsent(program, ArchInfo::new);
    }

    private void addRegs(Set<Register> out, Varnode[] vns) {
        if (vns == null) {
            return;
        }
        for (Varnode vn : vns) {
            Register r = reg(vn);
            if (r != null) {
                out.add(r);
            }
        }
    }

    /** The base register of a register varnode, null for anything else. */
    Register reg(Varnode vn) {
        if (vn == null || !vn.isRegister()) {
            return null;
        }
        Register r = lang.getRegister(vn.getAddress(), vn.getSize());
        if (r == null) {
            Register[] at = lang.getRegisters(vn.getAddress());
            r = at.length > 0 ? at[0] : null;
        }
        return r == null ? null : r.getBaseRegister();
    }

    static Register base(Object o) {
        return o instanceof Register r ? r.getBaseRegister() : null;
    }

    /**
     * A base register that holds condition flags, on a 32- or 64-bit processor
     * (on 8- and 16-bit processors data registers are that small too): a 1-byte
     * register of its own (CF / ZF on x86, NG / ZR / CY / OV on ARM), or a
     * register made of 1-byte fields only (crall and its fields cr0 - cr7 on
     * PowerPC; a data register as RBX also has a 2-byte BX).
     */
    boolean isFlagBase(Register base) {
        if (base == null || base.isProcessorContext() || lang.getLanguageDescription().getSize() < 32) {
            return false;
        }
        if (base.getMinimumByteSize() == 1) {
            return true;
        }
        if (argRegs.contains(base) || returnRegs.contains(base) || returnAddress.contains(base)
            || base.isProgramCounter() || base.equals(sp)) {
            return false;
        }
        int fields = 0;
        for (Register c : base.getChildRegisters()) {
            int size = c.getMinimumByteSize();
            if (size == 1) {
                fields++;
            }
            else if (size == 2) {
                return false;
            }
        }
        return fields >= 2;
    }

    /** A 1-byte read or write of a flag register. */
    boolean isFlag(Varnode vn) {
        return vn != null && vn.isRegister() && vn.getSize() == 1 && isFlagBase(reg(vn));
    }

    /** Written by an epilogue: the stack pointer, preserved registers, return address, flags, pc. */
    boolean isEpilogueReg(Register r) {
        return r != null && (calleeSaved.contains(r) || returnAddress.contains(r) || isFlagBase(r) || r.isProgramCounter()
            || r.isZero() || r.isProcessorContext() || r.isHidden());
    }

    boolean isReturnReg(Object o) {
        Register r = base(o);
        return r != null && returnRegs.contains(r);
    }
}
