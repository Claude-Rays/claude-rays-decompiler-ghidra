package org.clauderays.ghidra.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;

/**
 * Decompile, analyze and patch: the suggested fixes of the security findings,
 * as edits of the lines of the decompiled code. The model only writes the
 * lines that change; the fixed code, the rows of the side by side view and
 * the unified diff are built here from the validated edits. The findings are
 * numbered from 1 in the order of the result (the most severe first).
 */
public final class Fixes {

    private Fixes() {
    }

    /**
     * Lines first..last (1-based, inclusive) of the code replaced by 'lines',
     * for finding 'finding'; last = first - 1 inserts 'lines' before line first.
     */
    public record Edit(int finding, int first, int last, List<String> lines) {
    }

    /**
     * The fix of one finding (its number). Fixable without edits: covered by
     * the fix of another one, or (as the model also answers) nothing to change;
     * its note says which.
     */
    public record Fix(int finding, boolean fixable, String note, List<Edit> edits) {
    }

    /** The answer of the fix query, as cached with the result. */
    public static final class Result {
        public String model = "";
        public String modelId = "";
        public String effort = "";
        public String date = "";
        public double costUsd;
        public long inputTokens;
        public long outputTokens;
        /** the safety stops of the query, and every model that answered (Backend.Usage) */
        public int safetyStops;
        public final List<String> models = new ArrayList<>();
        /** by finding number */
        public final List<Fix> fixes = new ArrayList<>();
        /** validation */
        public final List<String> warnings = new ArrayList<>();

        /** All the edits, by line. */
        public List<Edit> edits() {
            List<Edit> out = new ArrayList<>();
            for (Fix f : fixes) {
                out.addAll(f.edits());
            }
            out.sort(Comparator.comparingInt(Edit::first));
            return out;
        }

        public boolean hasEdits() {
            return fixes.stream().anyMatch(f -> !f.edits().isEmpty());
        }

        public Fix fixOf(int finding) {
            for (Fix f : fixes) {
                if (f.finding() == finding) {
                    return f;
                }
            }
            return null;
        }

        /** "sonnet -> claude-sonnet-5-5, effort high" */
        public String modelUsed() {
            String s = model;
            if (!modelId.isEmpty() && !modelId.equals(model)) {
                s += " -> " + modelId;
            }
            if (!effort.isEmpty()) {
                s += ", effort " + effort;
            }
            return s;
        }
    }

    /** The findings worth a fix: confirmed and possible (a theoretical one has no bug to fix). */
    public static boolean wanted(Backend.Finding f) {
        return f.rank() <= 1;
    }

    /** The numbers of the findings worth a fix. */
    public static Set<Integer> wantedNumbers(List<Backend.Finding> findings) {
        Set<Integer> out = new LinkedHashSet<>();
        for (int i = 0; i < findings.size(); i++) {
            if (wanted(findings.get(i))) {
                out.add(i + 1);
            }
        }
        return out;
    }

    //--------------------------------------------------------------------------
    // the query
    //--------------------------------------------------------------------------
    /** The user message: the code with line numbers and the findings worth a fix. */
    public static String prompt(String summary, String prototype, String code, List<Backend.Finding> findings) {
        StringBuilder sb = new StringBuilder();
        if (!Text.trim(prototype).isEmpty()) {
            sb.append("== Function ==\n").append(Text.trim(prototype)).append('\n');
        }
        if (!Text.trim(summary).isEmpty()) {
            sb.append("== Summary ==\n").append(Text.trim(summary)).append('\n');
        }
        sb.append("== Decompiled code (line numbers added) ==\n");
        List<String> lines = Text.splitLines(code);
        int width = Integer.toString(lines.size()).length();
        for (int i = 0; i < lines.size(); i++) {
            sb.append(String.format("%" + width + "d| ", i + 1)).append(lines.get(i)).append('\n');
        }
        sb.append("== Findings to fix ==\n");
        for (int n : wantedNumbers(findings)) {
            sb.append("Finding ").append(n).append(": ").append(findings.get(n - 1).text()).append('\n');
        }
        sb.append("\nGive one entry of 'fixes' per finding listed.\n");
        return sb.toString();
    }

    private static int intOf(JsonObject o, String key) {
        JsonElement v = o.get(key);
        try {
            return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber() ? v.getAsInt() : -1;
        }
        catch (NumberFormatException e) {
            return -1;
        }
    }

    /** The same statement: equal without the address comments and the blanks around. */
    static boolean sameLine(String a, String b) {
        long[] ea = new long[1];
        return Text.trim(CodeShaper.stripAnnotations(a, ea)).equals(Text.trim(CodeShaper.stripAnnotations(b, ea)));
    }

    /** The lines of an edit: a string with line ends counts as several lines. */
    private static List<String> editLines(JsonObject o) {
        List<String> out = new ArrayList<>();
        for (String s : Backend.strList(o, "lines")) {
            out.addAll(s.isEmpty() ? List.of("") : Text.splitLines(s.replace("\r", "")));
        }
        return out;
    }

    /**
     * The validated fixes of an answer: only the findings asked for, once each;
     * edits inside the code, not overlapping (the first one by line wins) and
     * not leaving the code as it was. A fixable finding whose edits were all
     * dropped is not fixable; every finding asked for has an entry.
     */
    public static List<Fix> decode(JsonObject answer, List<String> code, Set<Integer> asked, List<String> warnings) {
        TreeMap<Integer, JsonObject> byFinding = new TreeMap<>();
        JsonArray a = Backend.arr(answer, "fixes");
        if (a != null) {
            for (JsonElement x : a) {
                if (!x.isJsonObject()) {
                    continue;
                }
                JsonObject o = x.getAsJsonObject();
                int n = intOf(o, "finding");
                if (!asked.contains(n)) {
                    warnings.add("fix of finding " + n + " dropped: that finding was not asked for");
                }
                else if (byFinding.containsKey(n)) {
                    warnings.add("second fix of finding " + n + " dropped");
                }
                else {
                    byFinding.put(n, o);
                }
            }
        }
        // every edit of the fixable findings, checked against the code
        List<Edit> all = new ArrayList<>();
        for (var kv : byFinding.entrySet()) {
            JsonObject o = kv.getValue();
            if (!Backend.bool(o, "fixable")) {
                continue;
            }
            JsonArray edits = Backend.arr(o, "edits");
            for (JsonElement x : edits != null ? edits : new JsonArray()) {
                if (!x.isJsonObject()) {
                    continue;
                }
                JsonObject e = x.getAsJsonObject();
                int first = intOf(e, "first_line");
                int last = intOf(e, "last_line");
                // last = first - 1: an insertion before line 'first' (after the trimming below, or from the cache)
                if (first < 1 || last < first - 1 || last > code.size()) {
                    warnings.add(String.format("edit of finding %d dropped: lines %d-%d are not lines of the code "
                        + "(1-%d)", kv.getKey(), first, last, code.size()));
                    continue;
                }
                // the lines kept at both ends are not part of the edit: they keep their address comment
                List<String> lines = new ArrayList<>(editLines(e));
                while (first <= last && !lines.isEmpty() && sameLine(code.get(first - 1), lines.get(0))) {
                    first++;
                    lines.remove(0);
                }
                while (first <= last && !lines.isEmpty()
                    && sameLine(code.get(last - 1), lines.get(lines.size() - 1))) {
                    last--;
                    lines.remove(lines.size() - 1);
                }
                if (first > last && lines.isEmpty()) {
                    continue;
                }
                all.add(new Edit(kv.getKey(), first, last, lines));
            }
        }
        all.sort(Comparator.comparingInt(Edit::first).thenComparingInt(Edit::finding));
        List<Edit> kept = new ArrayList<>();
        for (Edit e : all) {
            Edit prev = kept.isEmpty() ? null : kept.get(kept.size() - 1);
            if (prev != null && e.first() <= prev.last()) {
                warnings.add(String.format("edit of finding %d dropped: lines %d-%d overlap the edit of finding %d "
                    + "(lines %d-%d)", e.finding(), e.first(), e.last(), prev.finding(), prev.first(), prev.last()));
                continue;
            }
            kept.add(e);
        }
        List<Fix> out = new ArrayList<>();
        for (int n : new java.util.TreeSet<>(asked)) {
            JsonObject o = byFinding.get(n);
            if (o == null) {
                warnings.add("the model gave no fix for finding " + n);
                out.add(new Fix(n, false, "No answer for this finding.", List.of()));
                continue;
            }
            String note = Text.trim(Backend.str(o, "note"));
            List<Edit> mine = kept.stream().filter(e -> e.finding() == n).toList();
            boolean fixable = Backend.bool(o, "fixable");
            JsonArray given = Backend.arr(o, "edits");
            if (fixable && mine.isEmpty() && given != null && !given.isEmpty()) {
                warnings.add("fix of finding " + n + " dropped: none of its edits could be applied");
                fixable = false;
            }
            out.add(new Fix(n, fixable, note, fixable ? mine : List.of()));
        }
        return out;
    }

    //--------------------------------------------------------------------------
    // the fixed code, side by side and as a unified diff
    //--------------------------------------------------------------------------
    /** The code with the edits applied (edits sorted, not overlapping). */
    public static List<String> apply(List<String> code, List<Edit> edits) {
        List<String> out = new ArrayList<>();
        int next = 1;
        for (Edit e : edits) {
            out.addAll(code.subList(next - 1, e.first() - 1));
            out.addAll(e.lines());
            next = e.last() + 1;
        }
        out.addAll(code.subList(Math.min(next - 1, code.size()), code.size()));
        return out;
    }

    /**
     * One row of the side by side view: the line of the code on the left and of
     * the fixed code on the right (0-based, -1 for a blank filler), and the
     * finding whose fix changed it (0 for an unchanged row).
     */
    public record Row(int left, int right, int finding) {
        public boolean changed() {
            return finding != 0;
        }
    }

    /** The aligned rows of the code (nLines lines) and of its fixed version. */
    public static List<Row> rows(int nLines, List<Edit> edits) {
        List<Row> out = new ArrayList<>();
        int i = 0;
        int j = 0;
        for (Edit e : edits) {
            for (; i < e.first() - 1; i++, j++) {
                out.add(new Row(i, j, 0));
            }
            int nOld = e.last() - e.first() + 1;
            int nNew = e.lines().size();
            for (int k = 0; k < Math.max(nOld, nNew); k++) {
                out.add(new Row(k < nOld ? i + k : -1, k < nNew ? j + k : -1, e.finding()));
            }
            i += nOld;
            j += nNew;
        }
        for (; i < nLines; i++, j++) {
            out.add(new Row(i, j, 0));
        }
        return out;
    }

    private static String range(int start, int count) {
        // an empty range names the line before it
        return count == 1 ? Integer.toString(start + 1) : (count == 0 ? start : start + 1) + "," + count;
    }

    /**
     * The unified diff of 'left' and 'right' (the lines of the rows), with
     * 'context' lines around the changes; each hunk header names its findings
     * ("@@ -10,7 +10,9 @@ F1, F3").
     */
    public static List<String> unifiedDiff(List<String> left, List<String> right, List<Row> rows, int context,
                                           String leftName, String rightName) {
        List<String> out = new ArrayList<>();
        // the ranges of rows of each hunk: the changes with their context, merged
        List<int[]> hunks = new ArrayList<>();
        for (int r = 0; r < rows.size(); r++) {
            if (!rows.get(r).changed()) {
                continue;
            }
            int s = Math.max(r - context, 0);
            int e = r;
            while (e + 1 < rows.size() && rows.get(e + 1).changed()) {
                e++;
            }
            int end = Math.min(e + context + 1, rows.size());
            if (!hunks.isEmpty() && s <= hunks.get(hunks.size() - 1)[1]) {
                hunks.get(hunks.size() - 1)[1] = end;
            }
            else {
                hunks.add(new int[]{s, end});
            }
            r = e;
        }
        if (hunks.isEmpty()) {
            return out;
        }
        out.add("--- " + leftName);
        out.add("+++ " + rightName);
        for (int[] h : hunks) {
            int oldStart = 0;
            int newStart = 0;
            for (int r = 0; r < h[0]; r++) {
                oldStart += rows.get(r).left() >= 0 ? 1 : 0;
                newStart += rows.get(r).right() >= 0 ? 1 : 0;
            }
            int oldCount = 0;
            int newCount = 0;
            Set<Integer> findings = new java.util.TreeSet<>();
            for (int r = h[0]; r < h[1]; r++) {
                Row row = rows.get(r);
                oldCount += row.left() >= 0 ? 1 : 0;
                newCount += row.right() >= 0 ? 1 : 0;
                if (row.changed()) {
                    findings.add(row.finding());
                }
            }
            List<String> names = findings.stream().map(n -> "F" + n).toList();
            out.add(String.format("@@ -%s +%s @@ %s", range(oldStart, oldCount), range(newStart, newCount),
                String.join(", ", names)));
            for (int r = h[0]; r < h[1]; ) {
                Row row = rows.get(r);
                if (!row.changed()) {
                    out.add(" " + left.get(row.left()));
                    r++;
                    continue;
                }
                // a block of changed rows: its old lines, then its new ones
                int e = r;
                while (e < h[1] && rows.get(e).changed()) {
                    e++;
                }
                for (int k = r; k < e; k++) {
                    if (rows.get(k).left() >= 0) {
                        out.add("-" + left.get(rows.get(k).left()));
                    }
                }
                for (int k = r; k < e; k++) {
                    if (rows.get(k).right() >= 0) {
                        out.add("+" + right.get(rows.get(k).right()));
                    }
                }
                r = e;
            }
        }
        return out;
    }

    /**
     * Generate patch: a header that says what the patch is and what became of
     * each finding, then the unified diff of the code as the view shows it
     * (indented again, without the address comments).
     */
    public static List<String> patch(String funcName, String address, String code, List<Backend.Finding> findings,
                                     Result fix) {
        List<String> out = new ArrayList<>();
        out.addAll(Text.wrap(String.format("Claude-Rays Decompiler: suggested fix of %s at %s (%s, %s). A patch of "
            + "the C decompiled by Claude, not of the binary: plausible, not proven.", funcName, address,
            fix.modelUsed(), fix.date), 100));
        for (int n = 1; n <= findings.size(); n++) {
            Fix fx = fix.fixOf(n);
            String what = fx == null ? "not fixed (" + findings.get(n - 1).level() + ")"
                : !fx.edits().isEmpty() ? "FIXED: " + fx.note()
                : fx.fixable() ? "no edits (covered by another fix, or nothing to change): " + fx.note()
                : "NOT FIXABLE in this function: " + fx.note();
            out.addAll(Text.wrap("F" + n + " " + findings.get(n - 1).text(), 100));
            for (String l : Text.wrap(what, 96)) {
                out.add("    " + l);
            }
        }
        out.add("");
        List<String> lines = Text.splitLines(code);
        List<Edit> edits = fix.edits();
        List<String> left = CodeShaper.shapeLines(lines, false).lines;
        List<String> right = CodeShaper.shapeLines(apply(lines, edits), false).lines;
        out.addAll(unifiedDiff(left, right, rows(lines.size(), edits), 3, "a/" + funcName + " (decompiled)",
            "b/" + funcName + " (fixed)"));
        return out;
    }

    //--------------------------------------------------------------------------
    // cache
    //--------------------------------------------------------------------------
    public static JsonObject encode(Result r) {
        JsonObject j = new JsonObject();
        j.addProperty("model", r.model);
        j.addProperty("model_id", r.modelId);
        j.addProperty("effort", r.effort);
        j.addProperty("date", r.date);
        j.addProperty("cost_usd", String.format(Locale.ROOT, "%.6f", r.costUsd));
        j.addProperty("input_tokens", Long.toString(r.inputTokens));
        j.addProperty("output_tokens", Long.toString(r.outputTokens));
        j.addProperty("safety_stops", Integer.toString(r.safetyStops));
        JsonArray models = new JsonArray();
        r.models.forEach(models::add);
        j.add("models", models);
        JsonArray fixes = new JsonArray();
        for (Fix f : r.fixes) {
            JsonObject o = new JsonObject();
            o.addProperty("finding", f.finding());
            o.addProperty("fixable", f.fixable());
            o.addProperty("note", f.note());
            JsonArray edits = new JsonArray();
            for (Edit e : f.edits()) {
                JsonObject eo = new JsonObject();
                eo.addProperty("first_line", e.first());
                eo.addProperty("last_line", e.last());
                JsonArray lines = new JsonArray();
                e.lines().forEach(lines::add);
                eo.add("lines", lines);
                edits.add(eo);
            }
            o.add("edits", edits);
            fixes.add(o);
        }
        j.add("fixes", fixes);
        JsonArray w = new JsonArray();
        r.warnings.forEach(w::add);
        j.add("warnings", w);
        return j;
    }

    private static double parseDouble(String s) {
        try {
            return s.isEmpty() ? 0 : Double.parseDouble(s);
        }
        catch (NumberFormatException e) {
            return 0;
        }
    }

    /** A cached result, checked again against the code it patches (null if 'j' is null). */
    public static Result decodeCached(JsonObject j, List<String> code, int nFindings) {
        if (j == null) {
            return null;
        }
        Result r = new Result();
        r.model = Backend.str(j, "model");
        r.modelId = Backend.str(j, "model_id");
        r.effort = Backend.str(j, "effort");
        r.date = Backend.str(j, "date");
        r.costUsd = parseDouble(Backend.str(j, "cost_usd"));
        r.inputTokens = (long) parseDouble(Backend.str(j, "input_tokens"));
        r.outputTokens = (long) parseDouble(Backend.str(j, "output_tokens"));
        r.safetyStops = (int) parseDouble(Backend.str(j, "safety_stops"));
        r.models.addAll(Backend.strList(j, "models"));
        Set<Integer> asked = new LinkedHashSet<>();
        JsonArray a = Backend.arr(j, "fixes");
        if (a != null) {
            for (JsonElement x : a) {
                int n = x.isJsonObject() ? intOf(x.getAsJsonObject(), "finding") : -1;
                if (n >= 1 && n <= nFindings) {
                    asked.add(n);
                }
            }
        }
        List<String> ignored = new ArrayList<>();
        r.fixes.addAll(decode(j, code, asked, ignored));
        r.warnings.addAll(Backend.strList(j, "warnings"));
        return r;
    }
}
