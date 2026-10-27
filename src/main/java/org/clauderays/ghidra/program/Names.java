package org.clauderays.ghidra.program;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import org.clauderays.ghidra.core.Text;

import java.util.ArrayList;
import java.util.List;

/**
 * Names and addresses: the name helpers (callee name variants, demangled
 * names, templates), over Ghidra symbols.
 */
public final class Names {

    private Names() {
    }

    /** "0x401000" (the offset in its space). */
    public static String hex(Address a) {
        return a == null ? "" : Text.hex(a.getOffset());
    }

    /** "401000": the listing format. */
    public static String addr(Address a) {
        return a == null ? "" : Text.addr(a.getOffset());
    }

    /** The address 'offset' of the default space, null if it is not in memory. */
    public static Address toAddress(Program program, long offset) {
        try {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address a = space.getAddress(offset);
            return program.getMemory().contains(a) ? a : null;
        }
        catch (Exception e) {
            return null;
        }
    }

    /** The primary label at 'a' ("" if none). */
    public static String labelAt(Program program, Address a) {
        Symbol s = program.getSymbolTable().getPrimarySymbol(a);
        return s != null ? s.getName() : "";
    }

    /** The name of the item at 'a', with its namespace when it is not global ("" if none). */
    public static String nameAt(Program program, Address a) {
        Function f = program.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            return functionName(f);
        }
        Symbol s = program.getSymbolTable().getPrimarySymbol(a);
        return s != null ? s.getName(!s.getParentNamespace().isGlobal() && !s.isExternal()) : "";
    }

    /**
     * The name a C decompilation uses for 'f': qualified for C++ methods
     * ("Ns::Cls::f"), bare for imports (the library is not part of the name).
     */
    public static String functionName(Function f) {
        if (f.isExternal()) {
            return f.getName();
        }
        Function thunked = f.isThunk() ? f.getThunkedFunction(true) : null;
        if (thunked != null && thunked.isExternal() && f.getName().equals(thunked.getName())) {
            return f.getName();
        }
        return f.getName(!f.getParentNamespace().isGlobal());
    }

    /** The function the call target 'a' resolves to: its entry, or a pointer to it (an import). */
    public static Function functionAt(Program program, Address a) {
        if (a == null) {
            return null;
        }
        Function f = program.getFunctionManager().getFunctionAt(a);
        return f != null ? f : program.getFunctionManager().getReferencedFunction(a);
    }

    public static boolean hasUserName(Function f) {
        return f.getSymbol().getSource() != SourceType.DEFAULT;
    }

    /** A thunk to an import or an import itself. */
    public static boolean isImport(Function f) {
        if (f == null) {
            return false;
        }
        if (f.isExternal()) {
            return true;
        }
        Function t = f.isThunk() ? f.getThunkedFunction(true) : null;
        return t != null && t.isExternal();
    }

    /** "0x401000", "401000h", "401000" or a name; null if it does not resolve. */
    public static Address parseAddress(Program program, String str) {
        String s = Text.trim(str);
        if (s.isEmpty()) {
            return null;
        }
        Long v = Text.parseHex(s);
        if (v != null) {
            Address a = toAddress(program, v);
            if (a != null) {
                return a;
            }
        }
        try {
            List<Symbol> syms = NamespaceUtils.getSymbols(s, program);
            for (Symbol sym : syms) {
                if (sym.getAddress().isMemoryAddress()) {
                    return sym.getAddress();
                }
            }
        }
        catch (Exception e) {
            // not a valid name
        }
        for (Symbol sym : program.getSymbolTable().getSymbols(s)) {
            if (sym.getAddress().isMemoryAddress()) {
                return sym.getAddress();
            }
        }
        return null;
    }

    //--------------------------------------------------------------------------
    // C++ names
    //--------------------------------------------------------------------------
    /** The "::" before the last component (-1 if none), outside template arguments. */
    public static int lastScope(String s) {
        int depth = 0;
        boolean quoted = false;
        int found = -1;
        for (int i = 0; i + 1 < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '`') {
                quoted = true;
            }
            else if (c == '\'') {
                quoted = false;
            }
            else if (quoted) {
                continue;
            }
            else if (c == '<') {
                depth++;
            }
            else if (c == '>' && depth > 0) {
                depth--;
            }
            else if (depth == 0 && c == ':' && s.charAt(i + 1) == ':') {
                found = i++;
            }
        }
        return found;
    }

    /** 'Ns::Cls<a::b>::f' -> 'Ns::Cls::f' */
    public static String stripTemplates(String s) {
        StringBuilder out = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') {
                depth++;
            }
            else if (c == '>' && depth > 0) {
                depth--;
            }
            else if (depth == 0) {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** The name without its arguments ("f(int)" -> "f"), outside templates and quoted scopes. */
    static String withoutArguments(String s) {
        int depth = 0;
        boolean quoted = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '`') {
                quoted = true;
            }
            else if (c == '\'') {
                quoted = false;
            }
            else if (quoted) {
                continue;
            }
            else if (c == '<') {
                depth++;
            }
            else if (c == '>' && depth > 0) {
                depth--;
            }
            else if (c == '(' && depth == 0) {
                return Text.trim(s.substring(0, i));
            }
        }
        return Text.trim(s);
    }

    /**
     * The qualified C++ names of the function or label at 'a' ("Ns::Cls::f<int>"),
     * then without template arguments ("Ns::Cls::f"); empty if not qualified.
     */
    public static List<String> qualifiedNames(Program program, Address a) {
        List<String> out = new ArrayList<>();
        String q;
        Function f = functionAt(program, a);
        if (f != null) {
            q = f.isExternal() ? f.getName() : f.getName(true);
        }
        else {
            Symbol s = program.getSymbolTable().getPrimarySymbol(a);
            if (s == null) {
                return out;
            }
            q = s.getName(true);
        }
        q = withoutArguments(q);
        if (q.isEmpty() || lastScope(q) < 0) {
            return out;
        }
        out.add(q);
        String bare = stripTemplates(q);
        if (!bare.equals(q) && !bare.isEmpty()) {
            out.add(bare);
        }
        return out;
    }

    private static void add(List<String> out, String n) {
        n = Text.trim(n);
        if (!n.isEmpty() && !out.contains(n)) {
            out.add(n);
        }
    }

    /** The import prefixes and decorations removed from 'name'. */
    private static void addDecorated(List<String> out, String name) {
        add(out, name);
        String n = name;
        for (String prefix : new String[]{"__imp_", "_imp_", "PTR_"}) {
            if (n.startsWith(prefix)) {
                n = n.substring(prefix.length());
                break;
            }
        }
        add(out, n);
        int at = n.indexOf('@');
        if (at > 0) {
            n = n.substring(0, at);
        }
        add(out, n);
        if (n.length() > 1 && n.charAt(0) == '_') {
            add(out, n.substring(1));
        }
        // thunks
        if (n.startsWith("j_") || n.startsWith("thunk_")) {
            add(out, n.substring(n.indexOf('_') + 1));
        }
    }

    /**
     * The names a call to the function at 'callee' may have in C code: every
     * label there, the function, its qualified and last components (with and
     * without template arguments), with the import prefixes removed.
     */
    public static List<String> calleeNameVariants(Program program, Address callee) {
        List<String> out = new ArrayList<>();
        Function f = functionAt(program, callee);
        if (f != null) {
            addDecorated(out, functionName(f));
            addDecorated(out, f.getName());
            Function t = f.isThunk() ? f.getThunkedFunction(true) : null;
            if (t != null) {
                addDecorated(out, t.getName());
            }
            for (Symbol s : program.getSymbolTable().getSymbols(f.getEntryPoint())) {
                addDecorated(out, s.getName());
            }
        }
        for (Symbol s : program.getSymbolTable().getSymbols(callee)) {
            addDecorated(out, s.getName());
        }
        for (String q : qualifiedNames(program, callee)) {
            add(out, q);
            int colons = lastScope(q);
            if (colons >= 0) {
                add(out, q.substring(colons + 2));
            }
        }
        return out;
    }
}
