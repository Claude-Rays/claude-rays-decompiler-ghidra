package org.clauderays.ghidra.ui;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import org.clauderays.ghidra.core.Text;

import java.awt.Color;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A simple C highlighter: keywords, program
 * names (functions, data, imports), numbers, strings, comments, and the
 * address annotations dimmed.
 */
final class Highlighter {

    enum Kind { PLAIN, KEYWORD, FUNCTION, DATA, IMPORT, NUMBER, STRING, CHAR, COMMENT, ANNOTATION, NOTE, ERROR,
        UNCERTAIN, MARKER }

    record Span(String text, Kind kind) {
    }

    static final Set<String> KEYWORDS = Set.of(
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
        "register", "return", "short", "signed", "sizeof", "static", "struct", "switch",
        "typedef", "union", "unsigned", "void", "volatile", "while", "bool", "true", "false",
        "NULL", "nullptr", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_BOOL1", "_BOOL4",
        "__int8", "__int16", "__int32", "__int64", "__int128",
        "__fastcall", "__cdecl", "__stdcall", "__thiscall", "__usercall", "__noreturn",
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
        "uint64_t", "size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t",
        "undefined", "undefined1", "undefined2", "undefined4", "undefined8", "byte", "word", "dword", "qword");

    private final Program program;
    /** inside a multi line comment */
    private boolean inComment;
    private final Map<String, Kind> names = new HashMap<>();

    Highlighter(Program program) {
        this.program = program;
    }

    private Kind nameKind(String tok) {
        Kind k = names.get(tok);
        if (k != null) {
            return k;
        }
        k = Kind.PLAIN;
        if (program != null && !program.isClosed()) {
            SymbolIterator it = program.getSymbolTable().getSymbols(tok);
            while (it.hasNext()) {
                Symbol s = it.next();
                SymbolType t = s.getSymbolType();
                if (s.isExternal()) {
                    k = Kind.IMPORT;
                    break;
                }
                if (t == SymbolType.FUNCTION) {
                    k = Kind.FUNCTION;
                    break;
                }
                if (t == SymbolType.LABEL) {
                    k = program.getListing().getInstructionAt(s.getAddress()) != null ? Kind.FUNCTION : Kind.DATA;
                    break;
                }
            }
        }
        names.put(tok, k);
        return k;
    }

    List<Span> line(String s) {
        List<Span> out = new ArrayList<>();
        int i = 0;
        int n = s.length();
        StringBuilder plain = new StringBuilder();
        Runnable flush = () -> {
            if (plain.length() > 0) {
                out.add(new Span(plain.toString(), Kind.PLAIN));
                plain.setLength(0);
            }
        };
        while (i < n) {
            if (inComment) {
                int e = s.indexOf("*/", i);
                int end = e < 0 ? n : e + 2;
                flush.run();
                out.add(new Span(s.substring(i, end), Kind.COMMENT));
                inComment = e < 0;
                i = end;
                continue;
            }
            char c = s.charAt(i);
            if (c == '/' && i + 1 < n && s.charAt(i + 1) == '/') {
                flush.run();
                out.add(new Span(s.substring(i), Kind.COMMENT));
                break;
            }
            if (c == '/' && i + 1 < n && s.charAt(i + 1) == '*') {
                int e = s.indexOf("*/", i + 2);
                int end = e < 0 ? n : e + 2;
                String body = s.substring(i, end);
                // the address annotations are dimmed
                boolean annotation = body.startsWith("/*0x") && e >= 0;
                flush.run();
                out.add(new Span(body, annotation ? Kind.ANNOTATION : Kind.COMMENT));
                inComment = e < 0;
                i = end;
                continue;
            }
            if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < n && s.charAt(j) != c) {
                    j += s.charAt(j) == '\\' ? 2 : 1;
                }
                j = Math.min(j + 1, n);
                flush.run();
                out.add(new Span(s.substring(i, j), c == '"' ? Kind.STRING : Kind.CHAR));
                i = j;
                continue;
            }
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && (Character.isLetterOrDigit(s.charAt(j)) || s.charAt(j) == '.')) {
                    j++;
                }
                flush.run();
                out.add(new Span(s.substring(i, j), Kind.NUMBER));
                i = j;
                continue;
            }
            if (Text.isIdentChar(c)) {
                int j = i;
                while (j < n && Text.isIdentChar(s.charAt(j))) {
                    j++;
                }
                String tok = s.substring(i, j);
                flush.run();
                out.add(new Span(tok, KEYWORDS.contains(tok) ? Kind.KEYWORD : nameKind(tok)));
                i = j;
                continue;
            }
            plain.append(c);
            i++;
        }
        flush.run();
        return out;
    }

    //--------------------------------------------------------------------------
    // colors, for a light or a dark background
    //--------------------------------------------------------------------------
    static Color color(Kind k, boolean dark) {
        return switch (k) {
            case KEYWORD -> dark ? new Color(0x86, 0xb3, 0xff) : new Color(0x00, 0x00, 0xb0);
            case FUNCTION -> dark ? new Color(0xff, 0xd2, 0x6e) : new Color(0x00, 0x55, 0xaa);
            case DATA -> dark ? new Color(0xc8, 0xa0, 0xff) : new Color(0x80, 0x00, 0x80);
            case IMPORT -> dark ? new Color(0xff, 0x9e, 0xe6) : new Color(0xc0, 0x00, 0xc0);
            case NUMBER -> dark ? new Color(0x8c, 0xe0, 0xa0) : new Color(0x00, 0x80, 0x00);
            case STRING, CHAR -> dark ? new Color(0x8c, 0xe0, 0xe0) : new Color(0x00, 0x80, 0x80);
            case COMMENT -> dark ? new Color(0x8a, 0xb0, 0x8a) : new Color(0x60, 0x80, 0x60);
            case ANNOTATION, NOTE -> dark ? new Color(0x80, 0x80, 0x80) : new Color(0x90, 0x90, 0x90);
            case ERROR -> dark ? new Color(0xff, 0x70, 0x70) : new Color(0xc0, 0x00, 0x00);
            case UNCERTAIN -> dark ? new Color(0xff, 0xb0, 0x50) : new Color(0xa0, 0x60, 0x00);
            case MARKER -> dark ? new Color(0xe8, 0xe8, 0xe8) : new Color(0x20, 0x20, 0x60);
            default -> null;
        };
    }

    /**
     * The background of the lines of a security finding (Backend.Finding.rank():
     * soft red confirmed, soft orange possible, yellow theoretical).
     */
    static Color findingColor(int rank, boolean dark) {
        return switch (rank) {
            case 0 -> dark ? new Color(0x5c, 0x2a, 0x2a) : new Color(0xff, 0xcc, 0xcc);
            case 1 -> dark ? new Color(0x5c, 0x40, 0x1e) : new Color(0xff, 0xdd, 0xb0);
            default -> dark ? new Color(0x4e, 0x4a, 0x1e) : new Color(0xff, 0xf6, 0xb8);
        };
    }

    /**
     * The background of the lines of a fix (Decompile, analyze and patch): pale
     * green, darker the more severe its finding.
     */
    static Color fixColor(int rank, boolean dark) {
        return switch (rank) {
            case 0 -> dark ? new Color(0x1e, 0x5a, 0x2a) : new Color(0xa8, 0xe4, 0xa8);
            case 1 -> dark ? new Color(0x26, 0x4a, 0x2e) : new Color(0xc8, 0xf0, 0xc8);
            default -> dark ? new Color(0x2c, 0x3e, 0x30) : new Color(0xe4, 0xf8, 0xe4);
        };
    }

    static boolean isDark(Color bg) {
        if (bg == null) {
            return false;
        }
        double lum = 0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue();
        return lum < 128;
    }
}
