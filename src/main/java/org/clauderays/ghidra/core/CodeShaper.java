package org.clauderays.ghidra.core;

import java.util.ArrayList;
import java.util.List;

/**
 * The /*0x...*&#47; address annotations of the code and the shape of the code as
 * the view shows it: the annotations are taken out of the lines (their address is kept
 * per line) and the code is indented again, because the model often writes the
 * annotation in place of the indentation.
 */
public final class CodeShaper {

    private static final int INDENT = 4;

    /** No address on a line. */
    public static final long NO_ADDRESS = -1;

    private CodeShaper() {
    }

    /** The shaped code. */
    public static final class Shaped {
        public final List<String> lines = new ArrayList<>();
        /** The address of each line: its first annotation, NO_ADDRESS if none. */
        public final List<Long> addresses = new ArrayList<>();
    }

    /** The end of the annotation that starts at 'p' ("/*0x"), -1 if it is not one. */
    private static int annotationEnd(String s, int p) {
        if (!s.startsWith("/*0x", p)) {
            return -1;
        }
        int q = p + 4;
        int e = q;
        while (e < s.length() && Character.digit(s.charAt(e), 16) >= 0) {
            e++;
        }
        if (e == q || e - q > 16 || !s.startsWith("*/", e)) {
            return -1;
        }
        return e + 2;
    }

    private static long annotationValue(String s, int p, int end) {
        return Long.parseUnsignedLong(s.substring(p + 4, end - 2), 16);
    }

    /** The /*0x...*&#47; annotations of 'code', in order. */
    public static List<Long> annotations(String code) {
        List<Long> out = new ArrayList<>();
        for (int p = code.indexOf("/*0x"); p >= 0; p = code.indexOf("/*0x", p + 4)) {
            int e = annotationEnd(code, p);
            if (e >= 0) {
                out.add(annotationValue(code, p, e));
            }
        }
        return out;
    }

    /** The first annotation of 's' at or after 'from', NO_ADDRESS if none. */
    public static long firstAnnotation(String s, int from) {
        List<Long> notes = annotations(s.substring(Math.min(Math.max(from, 0), s.length())));
        return notes.isEmpty() ? NO_ADDRESS : notes.get(0);
    }

    /** 'line' without its annotations; ea[0] receives the first one (or NO_ADDRESS). */
    static String stripAnnotations(String line, long[] ea) {
        ea[0] = NO_ADDRESS;
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < line.length()) {
            int e = annotationEnd(line, i);
            if (e >= 0) {
                if (ea[0] == NO_ADDRESS) {
                    ea[0] = annotationValue(line, i, e);
                }
                i = e;
                if (i < line.length() && line.charAt(i) == ' ') {
                    i++;
                }
                continue;
            }
            out.append(line.charAt(i++));
        }
        // annotations at the end of a line leave trailing blanks
        int n = out.length();
        while (n > 0 && (out.charAt(n - 1) == ' ' || out.charAt(n - 1) == '\t')) {
            n--;
        }
        out.setLength(n);
        return out.toString();
    }

    static boolean startsWithWord(String t, String w) {
        return t.startsWith(w) && (t.length() == w.length() || !Text.isIdentChar(t.charAt(w.length())));
    }

    /** Brace / parenthesis balance of a line, outside strings, chars and comments. */
    private static final class LineScan {
        int braces;
        int parens;
        char last;                 // last significant character
        boolean opensComment;      // ends inside a /* comment
        boolean leadingClose;      // the first significant character is '}'
    }

    private static LineScan scanLine(String t) {
        LineScan r = new LineScan();
        boolean first = true;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '/' && i + 1 < t.length() && t.charAt(i + 1) == '/') {
                break;
            }
            if (c == '/' && i + 1 < t.length() && t.charAt(i + 1) == '*') {
                int e = t.indexOf("*/", i + 2);
                if (e < 0) {
                    r.opensComment = true;
                    break;
                }
                i = e + 1;
                continue;
            }
            if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < t.length() && t.charAt(j) != c) {
                    j += t.charAt(j) == '\\' ? 2 : 1;
                }
                i = j;
                r.last = c;
                first = false;
                continue;
            }
            if (c == ' ' || c == '\t') {
                continue;
            }
            if (first && c == '}') {
                r.leadingClose = true;
            }
            first = false;
            if (c == '{') {
                r.braces++;
            }
            else if (c == '}') {
                r.braces--;
            }
            else if (c == '(') {
                r.parens++;
            }
            else if (c == ')') {
                r.parens--;
            }
            r.last = c;
        }
        return r;
    }

    /**
     * Shape the code for the view: annotations out (or kept), indentation rebuilt
     * from the braces, single-statement bodies of if/else/for/while, case labels
     * and the continuation lines of an open parenthesis.
     */
    public static Shaped shape(String code, boolean keepAnnotations) {
        Shaped out = new Shaped();
        int depth = 0;
        int parens = 0;
        int pending = 0;                       // single-statement bodies waiting
        boolean inComment = false;
        List<Integer> caseDepths = new ArrayList<>();   // brace depths of the active case labels
        long[] ea = new long[1];
        for (String raw : Text.splitLines(code)) {
            String stripped = stripAnnotations(raw, ea);
            out.addresses.add(ea[0]);
            if (keepAnnotations) {
                out.lines.add(raw);
                continue;
            }
            String t = Text.trim(stripped);
            if (inComment) {
                // a block comment keeps its own layout
                out.lines.add(stripped);
                inComment = !stripped.contains("*/");
                continue;
            }
            if (t.isEmpty()) {
                out.lines.add("");
                continue;
            }
            LineScan s = scanLine(t);
            boolean isCase = startsWithWord(t, "case") || startsWithWord(t, "default");
            int base = s.leadingClose ? Math.max(depth - 1, 0) : depth;
            while (!caseDepths.isEmpty() && caseDepths.get(caseDepths.size() - 1) > base) {
                caseDepths.remove(caseDepths.size() - 1);
            }
            int lvl = base;
            for (int d : caseDepths) {
                if (isCase ? d < base : d <= base) {
                    lvl++;
                }
            }
            if (t.charAt(0) == '#') {
                lvl = 0;
            }
            else if (parens > 0) {
                lvl += pending + 1;            // continuation of an open parenthesis
            }
            else if (t.charAt(0) == '{') {
                lvl += Math.max(pending - 1, 0);   // the brace of the last header
            }
            else if (!s.leadingClose) {
                lvl += pending;
            }
            out.lines.add(" ".repeat(lvl * INDENT) + t);

            if (isCase && (caseDepths.isEmpty() || caseDepths.get(caseDepths.size() - 1) != depth)) {
                caseDepths.add(depth);
            }
            depth = Math.max(depth + s.braces, 0);
            parens = Math.max(parens + s.parens, 0);
            inComment = s.opensComment;
            boolean commentOnly = t.startsWith("//") || (t.startsWith("/*") && s.last == 0);
            if (commentOnly || parens > 0) {
                continue;
            }
            boolean header = startsWithWord(t, "if") || startsWithWord(t, "else") || startsWithWord(t, "for")
                || startsWithWord(t, "while") || startsWithWord(t, "do")
                || (s.leadingClose && t.contains("else"));
            if (s.last == '{' || s.last == ';' || s.last == '}' || s.last == ':') {
                pending = 0;
            }
            else if (header) {
                pending++;
            }
        }
        return out;
    }

    /** shape() of some lines, with one shaped line for each of them (an empty last line too). */
    public static Shaped shapeLines(List<String> lines, boolean keepAnnotations) {
        Shaped out = shape(String.join("\n", lines), keepAnnotations);
        while (out.lines.size() < lines.size()) {
            out.lines.add("");
            out.addresses.add(NO_ADDRESS);
        }
        return out;
    }

    /** The summary as a block comment ("/*\n * ...\n *&#47;\n"), "" if empty. */
    public static String summaryComment(String summary) {
        if (Text.trim(summary).isEmpty()) {
            return "";
        }
        StringBuilder code = new StringBuilder("/*\n");
        for (String l : Text.splitLines(summary)) {
            // a "*/" inside would end the block early
            String t = l.replace("*/", "* /");
            code.append(t.isEmpty() ? " *\n" : " * " + t + "\n");
        }
        return code.append(" */\n").toString();
    }

    /** Tabs expanded, carriage returns removed. */
    public static String cleanLine(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\t') {
                out.append(" ".repeat(4 - out.length() % 4));
            }
            else if (c != '\r') {
                out.append(c);
            }
        }
        return out.toString();
    }
}
