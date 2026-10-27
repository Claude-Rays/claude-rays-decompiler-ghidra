package org.clauderays.ghidra.core;

import java.util.Set;

/**
 * Mnemonic tables (x86/x64): pure functions over lowercase
 * mnemonics and values, free of Ghidra so they can be tested on their own.
 */
public final class InsnTable {

    private InsnTable() {
    }

    /** How a flag-setting instruction compared its operands. */
    public enum FlagSetter {
        /** arithmetic / logic, or no setter found in the block */
        UNKNOWN,
        /** cmp a, b */
        CMP,
        /** test a, a */
        TEST_SAME,
        /** test a, b */
        TEST,
        /** comiss / ucomisd / fcomi ...: CF/ZF/PF from a float compare */
        FLOAT,
    }

    private static final Set<String> FLOAT_COMPARES = Set.of(
        "comiss", "comisd", "ucomiss", "ucomisd", "vcomiss", "vcomisd", "vucomiss", "vucomisd",
        "fcomi", "fcomip", "fucomi", "fucomip");

    /** The kind of flag setter 'mnem' is; 'sameOperands' for test a, a. */
    public static FlagSetter classifyFlagSetter(String mnem, boolean sameOperands) {
        if (mnem.equals("cmp")) {
            return FlagSetter.CMP;
        }
        if (mnem.equals("test")) {
            return sameOperands ? FlagSetter.TEST_SAME : FlagSetter.TEST;
        }
        return FLOAT_COMPARES.contains(mnem) ? FlagSetter.FLOAT : FlagSetter.UNKNOWN;
    }

    private static final Set<String> KEEP_FLAGS = Set.of(
        "mov", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop",
        "xchg", "bswap", "not", "cdq", "cdqe", "cqo", "cwde", "cbw", "cwd",
        "movd", "movq", "movss", "movsd", "movaps", "movups", "movdqa", "movdqu",
        "endbr64", "endbr32");

    /** Does 'mnem' leave the flags alone (mov, lea, push, pop, ...)? */
    public static boolean keepsFlags(String mnem) {
        if (KEEP_FLAGS.contains(mnem)) {
            return true;
        }
        // cmovcc / setcc read the flags but do not change them
        return mnem.startsWith("cmov") || (mnem.startsWith("set") && !mnem.equals("setssbsy"));
    }

    private static final Set<String> CONDITION_CODES = Set.of(
        "o", "no", "b", "c", "nae", "ae", "nb", "nc", "e", "z", "ne", "nz",
        "be", "na", "a", "nbe", "s", "ns", "p", "pe", "np", "po",
        "l", "nge", "ge", "nl", "le", "ng", "g", "nle");

    /**
     * Condition code of a jcc / setcc / cmovcc mnemonic ("l" for jl, "nbe" for
     * cmovnbe), "" if 'mnem' is not a conditional instruction.
     */
    public static String conditionCode(String mnem) {
        String cc;
        if (mnem.startsWith("cmov")) {
            cc = mnem.substring(4);
        }
        else if (mnem.startsWith("set")) {
            cc = mnem.substring(3);
        }
        else if (mnem.startsWith("j") && !mnem.equals("jmp")) {
            cc = mnem.substring(1);
        }
        else {
            return "";
        }
        return CONDITION_CODES.contains(cc) ? cc : "";
    }

    /** Canonical name of a condition code. */
    private static String canonCc(String cc) {
        return switch (cc) {
            case "c", "nae" -> "b";
            case "nb", "nc" -> "ae";
            case "z" -> "e";
            case "nz" -> "ne";
            case "na" -> "be";
            case "nbe" -> "a";
            case "pe" -> "p";
            case "po" -> "np";
            case "nge" -> "l";
            case "nl" -> "ge";
            case "ng" -> "le";
            case "nle" -> "g";
            default -> cc;
        };
    }

    /**
     * The relation tested by a condition code after a given flag setter, e.g.
     * "signed <", "unsigned >=", "==", "float <", "signed <= 0", "(a & b) == 0".
     * "" if the condition code is unknown.
     */
    public static String ccRelation(String rawCc, FlagSetter setter) {
        if (!CONDITION_CODES.contains(rawCc)) {
            return "";
        }
        String cc = canonCc(rawCc);
        if (setter == FlagSetter.FLOAT) {
            // ZF/PF/CF as set by comiss & co. (unordered sets all three)
            switch (cc) {
                case "b": return "float < (or unordered)";
                case "ae": return "float >=";
                case "be": return "float <= (or unordered)";
                case "a": return "float >";
                case "e": return "float == (or unordered)";
                case "ne": return "float != (and ordered)";
                case "p": return "float unordered (NaN)";
                case "np": return "float ordered (no NaN)";
                default: break;
            }
        }
        if (setter == FlagSetter.TEST_SAME) {
            // test x, x: CF = OF = 0, the relations are against 0
            switch (cc) {
                case "e": return "== 0";
                case "ne": return "!= 0";
                case "l", "s": return "signed < 0";
                case "ge", "ns": return "signed >= 0";
                case "le": return "signed <= 0";
                case "g": return "signed > 0";
                case "a": return "!= 0";
                case "be": return "== 0";
                case "b": return "never (CF = 0 after test)";
                case "ae": return "always (CF = 0 after test)";
                default: break;
            }
        }
        if (setter == FlagSetter.TEST) {
            switch (cc) {
                case "e": return "(a & b) == 0";
                case "ne": return "(a & b) != 0";
                case "s", "l": return "(a & b) sign bit set";
                case "ns", "ge": return "(a & b) sign bit clear";
                default: break;
            }
        }
        return switch (cc) {
            case "b" -> "unsigned <";
            case "ae" -> "unsigned >=";
            case "be" -> "unsigned <=";
            case "a" -> "unsigned >";
            case "l" -> "signed <";
            case "ge" -> "signed >=";
            case "le" -> "signed <=";
            case "g" -> "signed >";
            case "e" -> "==";
            case "ne" -> "!=";
            case "s" -> "result < 0 (sign set)";
            case "ns" -> "result >= 0 (sign clear)";
            case "o" -> "signed overflow";
            case "no" -> "no signed overflow";
            case "p" -> "parity even";
            case "np" -> "parity odd";
            default -> "";
        };
    }

    /**
     * Facts of the mnemonic itself ("sign-extend", "unsigned divide", ...), ""
     * if none. 'nops' is the number of explicit operands, 'rep' a rep prefix.
     */
    public static String mnemonicFact(String mnem, int nops, boolean rep) {
        switch (mnem) {
            case "idiv": return "signed divide";
            case "div": return "unsigned divide";
            case "mul": return "unsigned widening multiply";
            case "sar": return "arithmetic shift right (signed)";
            case "shr": return "logical shift right (unsigned)";
            case "cdq": return "sign-extend eax into edx:eax";
            case "cqo": return "sign-extend rax into rdx:rax";
            case "cwd": return "sign-extend ax into dx:ax";
            case "cdqe": return "sign-extend eax to rax";
            case "cwde": return "sign-extend ax to eax";
            case "cbw": return "sign-extend al to ax";
            case "cvttss2si", "cvttsd2si": return "float to int, truncating";
            case "cvtsi2ss", "cvtsi2sd": return "signed int to float";
            default: break;
        }
        if (mnem.equals("imul") && nops == 1) {
            return "signed widening multiply";
        }
        if (mnem.startsWith("stos")) {
            return rep ? "memset idiom: rcx/ecx elements of al/ax/eax/rax to [rdi]" : "";
        }
        if (mnem.startsWith("movs") && mnem.length() == 5 && "bwdq".indexOf(mnem.charAt(4)) >= 0) {
            return rep ? "memcpy idiom: rcx/ecx elements from [rsi] to [rdi]" : "";
        }
        if (mnem.startsWith("scas")) {
            return rep ? "repne scas: strlen / memchr idiom" : "";
        }
        if (mnem.startsWith("cmps") && mnem.length() == 5) {
            return rep ? "repe cmps: memcmp idiom" : "";
        }
        return "";
    }

    /** Extension done by a load: 1 = sign (movsx, movsxd), 2 = zero (movzx), 0. */
    public static int extensionKind(String mnem) {
        if (mnem.equals("movsx") || mnem.equals("movsxd")) {
            return 1;
        }
        return mnem.equals("movzx") ? 2 : 0;
    }

    /**
     * "u8", "i16", "32-bit", "f64", "128-bit"... 'ext' as returned by
     * extensionKind(), 'isFloat' for floating point data.
     */
    public static String sizeName(int bytes, int ext, boolean isFloat) {
        if (isFloat && (bytes == 4 || bytes == 8 || bytes == 10)) {
            return "f" + (bytes * 8);
        }
        if (ext == 1) {
            return "i" + (bytes * 8);
        }
        if (ext == 2) {
            return "u" + (bytes * 8);
        }
        if (bytes == 0) {
            return "?-bit";
        }
        return (bytes * 8) + "-bit";
    }

    /**
     * A printable ASCII rendering of a constant: "'/'" for 0x2F, "\"MZ\" in
     * memory" for 0x5A4D (bytes in memory order); "" if the value is not
     * printable text.
     */
    public static String asciiConstant(long value, int nbytes) {
        if (nbytes <= 0 || nbytes > 8) {
            nbytes = 8;
        }
        // significant bytes in memory (little endian) order
        int n = 0;
        long v = value;
        for (int i = 0; i < nbytes && v != 0; i++, v >>>= 8) {
            n = i + 1;
        }
        if (n == 0) {
            return "";
        }
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int c = (int) ((value >>> (i * 8)) & 0xff);
            if (c < 0x20 || c > 0x7e) {
                return "";
            }
            text.append((char) c);
        }
        String t = text.toString();
        if (n == 1) {
            if (t.equals("'")) {
                return "'\\''";
            }
            if (t.equals("\\")) {
                return "'\\\\'";
            }
            return "'" + t + "'";
        }
        // "ab" style multi character constants need two or more letters to be
        // worth it (avoids annotating sizes like 0x2020)
        int alpha = 0;
        for (int i = 0; i < t.length(); i++) {
            alpha += Character.isLetter(t.charAt(i)) ? 1 : 0;
        }
        return alpha < 2 ? "" : "\"" + t + "\" in memory";
    }
}
