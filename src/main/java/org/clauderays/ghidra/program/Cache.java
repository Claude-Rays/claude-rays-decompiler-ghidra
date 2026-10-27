package org.clauderays.ghidra.program;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.Fixes;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Text;

import java.util.ArrayList;
import java.util.List;

/**
 * Results cached in the program: a string property map of the program, keyed by the entry point of the function, so
 * the cache is saved with the program. Each command (Mode) has its own map,
 * so the result of one never hides or replaces the result of another. The
 * hash of the function bytes decides if a result is still valid; the hash of
 * the callee names only marks it stale.
 */
public final class Cache {

    /** Decompile; the versions with one result per function kept all of them here */
    static final String MAP_NAME = "Claude-Rays Decompiler";
    static final String DIFF_MAP_NAME = "Claude-Rays Decompiler diff";
    private static final int CACHE_VERSION = 1;

    private Cache() {
    }

    /** The command a result comes from: each has its cached result and its view. */
    public enum Mode {
        DECOMPILE("decompile", MAP_NAME, "Decompile"),
        ANALYZE("analyze", MAP_NAME + " analyze", "Decompile and analyze"),
        PATCH("patch", MAP_NAME + " patch", "Decompile, analyze and patch");

        /** as saved with the open views */
        public final String key;
        final String mapName;
        /** the name of the command */
        public final String label;

        Mode(String key, String mapName, String label) {
            this.key = key;
            this.mapName = mapName;
            this.label = label;
        }

        public static Mode of(boolean analyze, boolean patch) {
            return patch ? PATCH : analyze ? ANALYZE : DECOMPILE;
        }

        /** null if unknown */
        public static Mode parse(String key) {
            for (Mode m : values()) {
                if (m.key.equals(key)) {
                    return m;
                }
            }
            return null;
        }
    }

    public static final class Entry {
        public String bytesHash = "";
        public String namesHash = "";
        /** as asked: an alias or an id */
        public String model = "";
        /** the model that answered ("" if unknown) */
        public String modelId = "";
        /** "" = the CLI default */
        public String effort = "";
        public String date = "";
        /** all rounds, at API prices */
        public double costUsd;
        public long inputTokens;
        public long outputTokens;
        public String summary = "";
        public String prototype = "";
        public String code = "";
        public final List<Backend.Uncertain> uncertain = new ArrayList<>();
        /** validation */
        public final List<String> warnings = new ArrayList<>();
        /** need_more left unanswered */
        public final List<String> missing = new ArrayList<>();
        /** need_more rounds served */
        public int rounds;
        /** the context mode (Settings.CONTEXT_...) the result was made from */
        public String context = org.clauderays.ghidra.core.Settings.CONTEXT_LISTING;
        /** why the C of Ghidra's decompiler was not sent although the mode asks for it ("" if it was) */
        public String contextNote = "";
        /** made by Decompile and analyze: the security analysis was asked for */
        public boolean analyzed;
        /** the findings of the analysis, anchored to instructions of the function */
        public final List<Backend.Finding> findings = new ArrayList<>();
        /** the safety stops of all rounds, and every model that answered (Backend.Usage) */
        public int safetyStops;
        public final List<String> models = new ArrayList<>();
        /** Decompile, analyze and patch: the fixes of the findings (null: never asked for) */
        public Fixes.Result fix;
        /** the command whose cached result this one was taken from (null: its own; not saved) */
        public Mode derivedFrom;

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

    public enum State {
        /** nothing cached (or the bytes changed: dropped) */
        NONE,
        VALID,
        /** the callee names changed */
        STALE,
    }

    //--------------------------------------------------------------------------
    /** FNV-1a of the chunks of the function: their bounds and bytes. */
    public static String bytesHash(Function f) {
        Text.Fnv h = new Text.Fnv();
        Program program = f.getProgram();
        for (AddressRange r : f.getBody()) {
            h.addLong(r.getMinAddress().getOffset());
            h.addLong(r.getMaxAddress().getOffset() + 1);
            long len = r.getLength();
            if (len > 0 && len < (1 << 24)) {
                byte[] buf = new byte[(int) len];
                try {
                    int got = program.getMemory().getBytes(r.getMinAddress(), buf);
                    h.add(buf, 0, Math.max(got, 0));
                }
                catch (Exception e) {
                    // unreadable bytes: only the bounds count
                }
            }
        }
        return h.toString();
    }

    public static String namesHash(Function f) {
        Text.Fnv h = new Text.Fnv();
        for (Address a : Collector.functionCallees(f)) {
            Function g = Names.functionAt(f.getProgram(), a);
            h.add(g != null ? Names.functionName(g) : Names.nameAt(f.getProgram(), a));
        }
        return h.toString();
    }

    //--------------------------------------------------------------------------
    static StringPropertyMap map(Program program, String name, boolean create) {
        PropertyMapManager pm = program.getUsrPropertyManager();
        StringPropertyMap m = pm.getStringPropertyMap(name);
        if (m == null && create) {
            try {
                m = pm.createStringPropertyMap(name);
            }
            catch (Exception e) {
                m = pm.getStringPropertyMap(name);
            }
        }
        return m;
    }

    /** Run 'body' in a transaction of the program (the writes of the cache). */
    static void write(Program program, String what, Runnable body) {
        int tx = program.startTransaction(what);
        boolean ok = false;
        try {
            body.run();
            ok = true;
        }
        finally {
            program.endTransaction(tx, ok);
        }
    }

    static String getString(Program program, String mapName, Address a) {
        StringPropertyMap m = map(program, mapName, false);
        return m != null ? m.getString(a) : null;
    }

    static void putString(Program program, String mapName, Address a, String text, String what) {
        write(program, what, () -> {
            StringPropertyMap m = map(program, mapName, true);
            if (m != null) {
                m.add(a, text);
            }
        });
    }

    static void removeString(Program program, String mapName, Address a) {
        StringPropertyMap m = map(program, mapName, false);
        if (m != null && m.getString(a) != null) {
            write(program, "Claude-Rays Decompiler: drop cached result", () -> m.remove(a));
        }
    }

    //--------------------------------------------------------------------------
    static JsonArray strArray(List<String> v) {
        JsonArray a = new JsonArray();
        for (String s : v) {
            a.add(s);
        }
        return a;
    }

    /**
     * A result of the versions with one result per function made by Decompile
     * and analyze (or patch) goes to the map of its command.
     */
    private static void migrate(Function f) {
        Program program = f.getProgram();
        Address ea = f.getEntryPoint();
        String text = getString(program, MAP_NAME, ea);
        // most results of Decompile are not parsed
        if (text == null || !text.contains("\"analyzed\"")) {
            return;
        }
        JsonObject j = Backend.parseObject(text);
        if (j == null || !Backend.bool(j, "analyzed")) {
            return;
        }
        Mode to = j.has("fix") ? Mode.PATCH : Mode.ANALYZE;
        try {
            write(program, "Claude-Rays Decompiler: move cached result", () -> {
                StringPropertyMap dst = map(program, to.mapName, true);
                if (dst != null && dst.getString(ea) == null) {
                    dst.add(ea, text);
                }
                map(program, MAP_NAME, false).remove(ea);
            });
        }
        catch (Exception e) {
            Log.error("could not move the cached result of %s: %s", Names.hex(ea), e.getMessage());
        }
    }

    /** The cached result of 'f' made by 'mode' (into 'out'). */
    public static State load(Function f, Mode mode, Entry out) {
        Program program = f.getProgram();
        Address ea = f.getEntryPoint();
        migrate(f);
        out.derivedFrom = null;
        String text = getString(program, mode.mapName, ea);
        if (text == null || text.isEmpty()) {
            return State.NONE;
        }
        JsonObject j = Backend.parseObject(text);
        if (j == null) {
            Log.error("the cached result of %s cannot be read: dropped", Names.hex(ea));
            delete(f, mode);
            return State.NONE;
        }
        Entry e = out;
        e.bytesHash = Backend.str(j, "bytes_hash");
        e.namesHash = Backend.str(j, "names_hash");
        e.model = Backend.str(j, "model");
        e.modelId = Backend.str(j, "model_id");
        e.effort = Backend.str(j, "effort");
        e.date = Backend.str(j, "date");
        e.costUsd = parseDouble(Backend.str(j, "cost_usd"));
        e.inputTokens = (long) parseDouble(Backend.str(j, "input_tokens"));
        e.outputTokens = (long) parseDouble(Backend.str(j, "output_tokens"));
        e.summary = Backend.str(j, "summary");
        e.prototype = Backend.str(j, "prototype");
        e.code = Backend.str(j, "code");
        e.rounds = (int) parseDouble(Backend.str(j, "rounds"));
        // results of the versions without the setting were made from the listing
        e.context = org.clauderays.ghidra.core.Settings.contextOf(Backend.str(j, "context"));
        e.contextNote = Backend.str(j, "context_note");
        e.uncertain.clear();
        JsonArray u = Backend.arr(j, "uncertain");
        if (u != null) {
            for (JsonElement x : u) {
                if (x.isJsonObject()) {
                    e.uncertain.add(new Backend.Uncertain(Backend.str(x.getAsJsonObject(), "address"),
                        Backend.str(x.getAsJsonObject(), "reason")));
                }
            }
        }
        e.warnings.clear();
        e.warnings.addAll(Backend.strList(j, "warnings"));
        e.missing.clear();
        e.missing.addAll(Backend.strList(j, "missing"));
        e.safetyStops = (int) parseDouble(Backend.str(j, "safety_stops"));
        e.models.clear();
        e.models.addAll(Backend.strList(j, "models"));
        e.analyzed = Backend.bool(j, "analyzed");
        e.findings.clear();
        e.findings.addAll(Backend.decodeFindings(Backend.arr(j, "findings")));
        e.fix = Fixes.decodeCached(Backend.obj(j, "fix"), Text.splitLines(e.code), e.findings.size());

        if (!e.bytesHash.equals(bytesHash(f))) {
            Log.info("the bytes of %s changed since it was decompiled: the cached result is dropped", Names.hex(ea));
            delete(f, mode);
            return State.NONE;
        }
        return e.namesHash.equals(namesHash(f)) ? State.VALID : State.STALE;
    }

    /**
     * The cached result of 'f' made by 'mode' or, without one, the one taken
     * from the cached result of a more complete command, with nothing queried:
     * Decompile and analyze is Decompile, analyze and patch without the fixes,
     * and Decompile is either of them without the analysis (the code is the
     * same). The result taken is not saved: Regenerate makes one of its own.
     */
    public static State loadOrDerive(Function f, Mode mode, Entry out) {
        State st = load(f, mode, out);
        Mode[] richer = mode == Mode.DECOMPILE ? new Mode[]{Mode.ANALYZE, Mode.PATCH}
            : mode == Mode.ANALYZE ? new Mode[]{Mode.PATCH} : new Mode[0];
        for (int i = 0; st == State.NONE && i < richer.length; i++) {
            st = load(f, richer[i], out);
            if (st != State.NONE) {
                out.derivedFrom = richer[i];
                out.fix = null;
                out.warnings.removeIf(w -> w.startsWith("the fixes could not be made"));
                if (mode == Mode.DECOMPILE) {
                    out.analyzed = false;
                    out.findings.clear();
                    out.warnings.removeIf(w -> w.startsWith("security finding dropped"));
                }
            }
        }
        return st;
    }

    private static double parseDouble(String s) {
        try {
            return s.isEmpty() ? 0 : Double.parseDouble(s);
        }
        catch (NumberFormatException e) {
            return 0;
        }
    }

    public static void save(Function f, Mode mode, Entry e) {
        JsonObject j = new JsonObject();
        j.addProperty("version", CACHE_VERSION);
        j.addProperty("bytes_hash", e.bytesHash);
        j.addProperty("names_hash", e.namesHash);
        j.addProperty("model", e.model);
        j.addProperty("model_id", e.modelId);
        j.addProperty("effort", e.effort);
        j.addProperty("date", e.date);
        j.addProperty("rounds", Integer.toString(e.rounds));
        j.addProperty("context", e.context);
        j.addProperty("context_note", e.contextNote);
        j.addProperty("cost_usd", String.format(java.util.Locale.ROOT, "%.6f", e.costUsd));
        j.addProperty("input_tokens", Long.toString(e.inputTokens));
        j.addProperty("output_tokens", Long.toString(e.outputTokens));
        j.addProperty("summary", e.summary);
        j.addProperty("prototype", e.prototype);
        j.addProperty("code", e.code);
        JsonArray u = new JsonArray();
        for (Backend.Uncertain x : e.uncertain) {
            JsonObject o = new JsonObject();
            o.addProperty("address", x.address());
            o.addProperty("reason", x.reason());
            u.add(o);
        }
        j.add("uncertain", u);
        j.add("warnings", strArray(e.warnings));
        j.add("missing", strArray(e.missing));
        if (e.safetyStops > 0) {
            j.addProperty("safety_stops", Integer.toString(e.safetyStops));
        }
        j.add("models", strArray(e.models));
        if (e.analyzed) {
            j.addProperty("analyzed", true);
            j.add("findings", Backend.encodeFindings(e.findings));
        }
        if (e.fix != null) {
            j.add("fix", Fixes.encode(e.fix));
        }
        try {
            putString(f.getProgram(), mode.mapName, f.getEntryPoint(), j.toString(),
                "Claude-Rays Decompiler: cache result");
        }
        catch (Exception ex) {
            Log.error("could not save the result of %s in the program: %s", Names.hex(f.getEntryPoint()),
                ex.getMessage());
        }
    }

    public static void delete(Function f, Mode mode) {
        try {
            removeString(f.getProgram(), mode.mapName, f.getEntryPoint());
        }
        catch (Exception e) {
            Log.error("could not drop the cached result of %s: %s", Names.hex(f.getEntryPoint()), e.getMessage());
        }
    }

    //--------------------------------------------------------------------------
    // the diff of two versions: one entry per function of the open program
    //--------------------------------------------------------------------------
    /** The cached response, null if none for this pair, orientation and bytes of A. */
    public static JsonObject loadDiff(Function f, String aHash, String bKey, boolean aIsNew) {
        String text = getString(f.getProgram(), DIFF_MAP_NAME, f.getEntryPoint());
        JsonObject j = text != null ? Backend.parseObject(text) : null;
        JsonObject r = Backend.obj(j, "response");
        // another pair, another orientation, or the bytes of A changed
        if (r == null || !Backend.str(j, "a_bytes_hash").equals(aHash) || !Backend.str(j, "b_key").equals(bKey)
            || Backend.bool(j, "a_is_new") != aIsNew) {
            return null;
        }
        return r;
    }

    public static void saveDiff(Function f, String aHash, String bKey, boolean aIsNew, JsonObject response) {
        JsonObject j = new JsonObject();
        j.addProperty("version", CACHE_VERSION);
        j.addProperty("a_bytes_hash", aHash);
        j.addProperty("b_key", bKey);
        j.addProperty("a_is_new", aIsNew);
        j.add("response", response);
        try {
            putString(f.getProgram(), DIFF_MAP_NAME, f.getEntryPoint(), j.toString(), "Claude-Rays Decompiler: cache diff");
        }
        catch (Exception ex) {
            Log.error("could not save the diff of %s in the program: %s", Names.hex(f.getEntryPoint()), ex.getMessage());
        }
    }
}
