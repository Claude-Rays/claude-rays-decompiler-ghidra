package org.clauderays.ghidra.core;

/** The token under the cursor of the code view. */
public final class CodeNav {

    private CodeNav() {
    }

    private static boolean ident(char c) {
        return Text.isIdentChar(c) || c == '~';
    }

    private static boolean isOperatorChar(char c) {
        return "+-*/%=<>!&|^~[]".indexOf(c) >= 0;
    }

    /** The qualified name under column 'x': "Ns::Cls<T>::f", "std::operator+", "Cls::~Cls"; "" if none. */
    public static String qualifiedToken(String line, int x) {
        if (x < 0 || x >= line.length() || !ident(line.charAt(x))) {
            return "";
        }
        int b = x;
        for (; ; ) {
            if (b > 0 && ident(line.charAt(b - 1))) {
                b--;
            }
            else if (b >= 2 && line.charAt(b - 1) == ':' && line.charAt(b - 2) == ':') {
                b -= 2;
            }
            else if (b > 0 && line.charAt(b - 1) == '>') {
                int depth = 0;
                int i = b;
                while (i > 0) {
                    char c = line.charAt(--i);
                    if (c == '>') {
                        depth++;
                    }
                    else if (c == '<' && --depth == 0) {
                        break;
                    }
                }
                if (depth != 0) {
                    break;
                }
                b = i;
            }
            else {
                break;
            }
        }
        int e = x;
        for (; ; ) {
            if (e < line.length() && ident(line.charAt(e))) {
                e++;
            }
            else if (e + 1 < line.length() && line.charAt(e) == ':' && line.charAt(e + 1) == ':') {
                e += 2;
            }
            else if (e < line.length() && line.charAt(e) == '<') {
                int depth = 0;
                int i = e;
                for (; i < line.length(); i++) {
                    char c = line.charAt(i);
                    if (c == '<') {
                        depth++;
                    }
                    else if (c == '>' && --depth == 0) {
                        break;
                    }
                    else if (c == ';' || c == '(' || c == ')') {
                        break;
                    }
                }
                if (i >= line.length() || line.charAt(i) != '>') {
                    break;
                }
                e = i + 1;
            }
            else {
                break;
            }
        }
        StringBuilder tok = new StringBuilder(line.substring(b, e));
        // operator+, operator==...
        if (tok.toString().endsWith("operator")) {
            while (e < line.length() && isOperatorChar(line.charAt(e))) {
                tok.append(line.charAt(e++));
            }
        }
        return tok.toString();
    }

    /** The plain identifier under column 'x', "" if none. */
    public static String wordAt(String line, int x) {
        if (x < 0 || x >= line.length() || !Text.isIdentChar(line.charAt(x))) {
            return "";
        }
        int b = x;
        while (b > 0 && Text.isIdentChar(line.charAt(b - 1))) {
            b--;
        }
        int e = x;
        while (e < line.length() && Text.isIdentChar(line.charAt(e))) {
            e++;
        }
        return line.substring(b, e);
    }

    public static String noSpaces(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t') {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** The annotation under column 'x' of 'line', CodeShaper.NO_ADDRESS if none. */
    public static long annotationAt(String line, int x) {
        for (int p = line.indexOf("/*0x"); p >= 0; p = line.indexOf("/*0x", p + 1)) {
            int e = line.indexOf("*/", p + 4);
            if (e >= 0 && x >= p && x < e + 2) {
                return CodeShaper.firstAnnotation(line, p);
            }
        }
        return CodeShaper.NO_ADDRESS;
    }
}
