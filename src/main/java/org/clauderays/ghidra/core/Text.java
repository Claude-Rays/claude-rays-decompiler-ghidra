package org.clauderays.ghidra.core;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/** Small string helpers. */
public final class Text {

    private Text() {
    }

    /** 0x prefix, lowercase digits. */
    public static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    /** No prefix, lowercase digits (the listing format). */
    public static String addr(long v) {
        return Long.toHexString(v);
    }

    public static String trim(String s) {
        if (s == null) {
            return "";
        }
        int b = 0;
        int e = s.length();
        while (b < e && isBlank(s.charAt(b))) {
            b++;
        }
        while (e > b && isBlank(s.charAt(e - 1))) {
            e--;
        }
        return s.substring(b, e);
    }

    private static boolean isBlank(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    /** One line, at most 'max' characters. */
    public static String oneLine(String s, int max) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(c == '\n' || c == '\r' || c == '\t' ? ' ' : c);
        }
        String out = trim(sb.toString());
        if (out.length() > max) {
            int n = max;
            // do not cut a surrogate pair
            if (n > 0 && Character.isHighSurrogate(out.charAt(n - 1))) {
                n--;
            }
            out = out.substring(0, n) + "...";
        }
        return out;
    }

    /** The lines of 's' without their line ends; a final line end adds no empty line. */
    public static List<String> splitLines(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) {
            return out;
        }
        int start = 0;
        while (start < s.length()) {
            int end = s.indexOf('\n', start);
            if (end < 0) {
                end = s.length();
            }
            String line = s.substring(start, end);
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }
            out.add(line);
            start = end + 1;
        }
        return out;
    }

    /** 's' cut at the blanks into lines of at most 'width' characters (longer words stay whole). */
    public static List<String> wrap(String s, int width) {
        List<String> out = new ArrayList<>();
        List<String> paras = splitLines(s);
        for (String para : paras.isEmpty() ? List.of("") : paras) {
            StringBuilder line = new StringBuilder();
            for (String w : para.split(" ")) {
                if (w.isEmpty()) {
                    continue;
                }
                if (line.length() > 0 && line.length() + 1 + w.length() > width) {
                    out.add(line.toString());
                    line.setLength(0);
                }
                if (line.length() > 0) {
                    line.append(' ');
                }
                line.append(w);
            }
            out.add(line.toString());
        }
        return out;
    }

    /** 's' padded with blanks up to 'width' characters. */
    public static String pad(String s, int width) {
        if (s.length() >= width) {
            return s;
        }
        return s + " ".repeat(width - s.length());
    }

    public static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }

    /** Does 'text' contain 'word' delimited by non identifier characters? */
    public static boolean hasWord(String text, String word) {
        if (word == null || word.isEmpty()) {
            return false;
        }
        for (int p = text.indexOf(word); p >= 0; p = text.indexOf(word, p + 1)) {
            boolean left = p == 0 || !(Character.isLetterOrDigit(text.charAt(p - 1)) || text.charAt(p - 1) == '_');
            int e = p + word.length();
            boolean right = e >= text.length() || !(Character.isLetterOrDigit(text.charAt(e)) || text.charAt(e) == '_');
            if (left && right) {
                return true;
            }
        }
        return false;
    }

    /** "0x401000", "401000h" or "401000": the value, or null if not an hexadecimal number. */
    public static Long parseHex(String str) {
        String s = trim(str);
        if (s.length() > 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')) {
            s = s.substring(2);
        }
        else if (s.length() > 1 && (s.endsWith("h") || s.endsWith("H"))) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty() || s.length() > 16) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            if (Character.digit(s.charAt(i), 16) < 0) {
                return null;
            }
        }
        return Long.parseUnsignedLong(s, 16);
    }

    /** The current local time, "2026-10-16 13:24". */
    public static String now() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
    }

    /** A C string literal of 's'. */
    public static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '"', '\\' -> out.append('\\').append(c);
                default -> out.append(c);
            }
        }
        return out.append('"').toString();
    }

    /** "a, b, c and 3 more": at most 'max' items. */
    public static String shortList(List<String> items, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size() && i < max; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(items.get(i));
        }
        if (items.size() > max) {
            sb.append(" and ").append(items.size() - max).append(" more");
        }
        return sb.toString();
    }

    /** FNV-1a, 64 bits, as 16 hexadecimal digits. */
    public static final class Fnv {
        private long h = 0xcbf29ce484222325L;

        public Fnv add(byte[] data, int off, int len) {
            for (int i = off; i < off + len; i++) {
                h ^= data[i] & 0xff;
                h *= 0x100000001b3L;
            }
            return this;
        }

        public Fnv add(byte[] data) {
            return add(data, 0, data.length);
        }

        public Fnv addLong(long v) {
            for (int i = 0; i < 8; i++) {
                h ^= (v >>> (i * 8)) & 0xff;
                h *= 0x100000001b3L;
            }
            return this;
        }

        /** The UTF-8 bytes of 's' and a terminating zero. */
        public Fnv add(String s) {
            add(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            h ^= 0;
            h *= 0x100000001b3L;
            return this;
        }

        @Override
        public String toString() {
            return String.format("%016x", h);
        }
    }
}
