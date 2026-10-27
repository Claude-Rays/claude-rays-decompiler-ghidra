package org.clauderays.ghidra.program;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.CodeShaper;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Models;
import org.clauderays.ghidra.core.Prompts;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The diff of two versions of a function in one query, the body
 * of the API used by Diaphora-ng (ClaudeRaysService): version A is a function
 * of the open program, version B comes from the other database (its exported
 * SQLite) inside the request. One query decompiles both, aligned, and lists
 * and assesses the changes. Request and response are JSON; the format is in
 * the README (API for Diaphora-ng).
 */
public final class PairDiff {

    private static final int MAX_ASM_DIFF_LINES = 400;
    private static final int FACTS_COLUMN = 48;

    private PairDiff() {
    }

    static String errorResponse(String err) {
        JsonObject r = new JsonObject();
        r.addProperty("ok", false);
        r.addProperty("error", err);
        return r.toString();
    }

    //--------------------------------------------------------------------------
    // version B: the listing built from the request (Diaphora's exported data)
    //--------------------------------------------------------------------------
    /** Version B as the prompt shows it. */
    public static final class SideB {
        public String name = "";
        /** the sections for the prompt */
        public String text = "";
        /** the instructions of its listing */
        public final Set<Long> addresses = new HashSet<>();
        public int ninsns;
        /** what identifies it in the cache */
        public String key = "";
    }

    static String listingLine(long ea, String text, String comment) {
        String line = "  " + Text.addr(ea) + "  " + Text.trim(text);
        String cmt = Text.oneLine(Text.trim(comment), 200);
        if (!cmt.isEmpty()) {
            line = Text.pad(line, FACTS_COLUMN) + " ; " + cmt;
        }
        return line;
    }

    private static Long hexOf(JsonElement e) {
        return e != null && e.isJsonPrimitive() ? Text.parseHex(e.getAsString()) : null;
    }

    /** Version B from the request; throws IllegalArgumentException with the reason it cannot be sent. */
    public static SideB buildSideB(JsonObject b, int budget, int maxInsns) {
        if (b == null) {
            throw new IllegalArgumentException("the request has no version B");
        }
        SideB out = new SideB();
        out.name = Backend.str(b, "name");
        String demangled = Backend.str(b, "demangled");
        String source = Backend.str(b, "source");

        // blocks, sorted by address; their number is their position
        record Block(long ea, List<Long> succs, JsonArray lines) {
        }
        List<Block> blocks = new ArrayList<>();
        JsonArray jb = Backend.arr(b, "blocks");
        if (jb != null) {
            for (JsonElement x : jb) {
                if (!x.isJsonObject()) {
                    continue;
                }
                JsonObject o = x.getAsJsonObject();
                Long ea = hexOf(o.get("address"));
                if (ea == null) {
                    continue;
                }
                List<Long> succs = new ArrayList<>();
                JsonArray s = Backend.arr(o, "succs");
                if (s != null) {
                    for (JsonElement v : s) {
                        Long t = hexOf(v);
                        if (t != null) {
                            succs.add(t);
                        }
                    }
                }
                blocks.add(new Block(ea, succs, Backend.arr(o, "lines")));
            }
        }
        blocks.sort((x, y) -> Long.compareUnsigned(x.ea(), y.ea()));
        Map<Long, Integer> number = new TreeMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            number.put(blocks.get(i).ea(), i);
        }
        boolean blocksKnown = !Backend.bool(b, "no_blocks");

        StringBuilder listing = new StringBuilder();
        for (Block blk : blocks) {
            if (blocksKnown) {
                String head = Text.pad("block_" + Text.addr(blk.ea()) + ":", 36);
                StringBuilder info = new StringBuilder("block ").append(number.get(blk.ea()));
                if (blk.succs().isEmpty()) {
                    info.append(", no successors (return or noreturn)");
                }
                StringBuilder succ = new StringBuilder();
                for (long t : blk.succs()) {
                    Integer p = number.get(t);
                    succ.append(succ.length() == 0 ? "" : ", ").append(p != null ? p.toString() : "outside " + Text.hex(t));
                }
                if (succ.length() > 0) {
                    info.append(", -> ").append(succ);
                }
                listing.append(head).append(" ; ").append(info).append('\n');
            }
            if (blk.lines() == null) {
                continue;
            }
            for (JsonElement l : blk.lines()) {
                if (!l.isJsonObject()) {
                    continue;
                }
                JsonObject lo = l.getAsJsonObject();
                Long ea = hexOf(lo.get("address"));
                if (ea == null) {
                    continue;
                }
                out.addresses.add(ea);
                out.ninsns++;
                listing.append(listingLine(ea, Backend.str(lo, "text"), Backend.str(lo, "comment"))).append('\n');
            }
        }
        if (out.ninsns == 0) {
            throw new IllegalArgumentException("the request has no listing for version B");
        }
        if (out.ninsns > maxInsns) {
            throw new IllegalArgumentException(String.format("version B has %d instructions, more than the limit "
                + "of %d (Claude-Rays Decompiler > Settings)", out.ninsns, maxInsns));
        }

        StringBuilder head = new StringBuilder("== Function ==\n");
        head.append("Name: ").append(out.name).append('\n');
        if (!demangled.isEmpty() && !demangled.equals(out.name)) {
            head.append("Demangled: ").append(demangled).append('\n');
        }
        Long addr = Text.parseHex(Backend.str(b, "address"));
        if (addr != null) {
            head.append("Address: ").append(Text.hex(addr)).append('\n');
        }
        if (!Text.trim(Backend.str(b, "prototype")).isEmpty()) {
            head.append("Prototype: ").append(Text.oneLine(Backend.str(b, "prototype"), 400))
                .append(" (from the exported database)\n");
        }
        if (!Text.trim(Backend.str(b, "comment")).isEmpty()) {
            head.append("Comment: ").append(Text.oneLine(Backend.str(b, "comment"), 300)).append('\n');
        }
        head.append("Size: ").append(out.ninsns).append(" instructions");
        if (blocksKnown) {
            head.append(", ").append(blocks.size()).append(" basic blocks");
        }
        head.append('\n');
        head.append("Source: ").append(source.isEmpty() ? "another database" : source)
            .append(" (exported data only: no stack frame, types, data or call sites)\n\n");

        String listingIntro = blocksKnown
            ? "== Listing ==\nDisassembly by basic block ('; ' text at the end of a line is a comment of the database).\n"
            : "== Listing ==\nDisassembly in address order: the basic blocks of this version were not exported.\n";
        StringBuilder body = new StringBuilder(head).append(listingIntro).append(listing).append('\n');
        if (body.length() > budget) {
            throw new IllegalArgumentException(String.format("the listing of version B (%d chars) does not fit in "
                + "the context budget of %d chars (Claude-Rays Decompiler > Settings)", body.length(), budget));
        }

        // the calls are trimmed to the budget, never the listing
        StringBuilder calls = new StringBuilder();
        int dropped = 0;
        JsonArray jc = Backend.arr(b, "calls");
        if (jc != null) {
            for (JsonElement c : jc) {
                if (!c.isJsonObject()) {
                    continue;
                }
                JsonObject co = c.getAsJsonObject();
                String proto = Text.trim(Backend.str(co, "prototype"));
                String line = "  " + Backend.str(co, "address") + "  "
                    + (proto.isEmpty() ? Backend.str(co, "name") : Text.oneLine(proto, 400));
                if (body.length() + calls.length() + line.length() + 64 > budget) {
                    dropped++;
                    continue;
                }
                calls.append(line).append('\n');
            }
        }
        if (calls.length() > 0 || dropped != 0) {
            body.append("== Called functions ==\n").append(calls);
            if (dropped != 0) {
                body.append('(').append(dropped).append(" more left out for size)\n");
            }
            body.append('\n');
        }
        List<String> consts = Backend.strList(b, "constants");
        if (!consts.isEmpty()) {
            StringBuilder t = new StringBuilder("== Constants ==\n  ");
            for (int i = 0; i < consts.size(); i++) {
                t.append(i == 0 ? "" : ", ").append(Text.oneLine(consts.get(i), 120));
            }
            t.append("\n\n");
            if (body.length() + t.length() <= budget) {
                body.append(t);
            }
        }
        out.text = body.toString();

        // the cache key: the bytes hash exported by Diaphora, else the listing
        out.key = Text.trim(Backend.str(b, "bytes_hash"));
        if (out.key.isEmpty()) {
            out.key = "listing:" + new Text.Fnv().add(out.text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return out;
    }

    //--------------------------------------------------------------------------
    // the answer
    //--------------------------------------------------------------------------
    /** One version of the answer, with its code shaped for the diff and the address of each line. */
    static JsonObject sideResponse(Backend.DecompResult res) {
        JsonObject s = new JsonObject();
        s.addProperty("summary", res.summary);
        s.addProperty("prototype", res.prototype);
        s.addProperty("code", res.code);
        CodeShaper.Shaped shaped = CodeShaper.shape(res.code, false);
        JsonArray jl = new JsonArray();
        for (int i = 0; i < shaped.lines.size(); i++) {
            JsonObject l = new JsonObject();
            l.addProperty("text", shaped.lines.get(i));
            long ea = i < shaped.addresses.size() ? shaped.addresses.get(i) : CodeShaper.NO_ADDRESS;
            l.addProperty("address", ea != CodeShaper.NO_ADDRESS ? Text.hex(ea) : "");
            jl.add(l);
        }
        s.add("lines", jl);
        JsonArray u = new JsonArray();
        for (Backend.Uncertain x : res.uncertain) {
            JsonObject o = new JsonObject();
            o.addProperty("address", x.address());
            o.addProperty("reason", x.reason());
            u.add(o);
        }
        s.add("uncertain", u);
        return s;
    }

    /** The instruction at 'ea' belongs to the function of the open program. */
    static boolean inFunctionA(Function f, long ea) {
        Address a = Names.toAddress(f.getProgram(), ea);
        return a != null && f.getBody().contains(a) && f.getProgram().getListing().getInstructionAt(a) != null;
    }

    static JsonArray strArray(List<String> v) {
        JsonArray a = new JsonArray();
        for (String s : v) {
            a.add(s);
        }
        return a;
    }

    /** The prompt of the pair: the assembly diff, then OLD and NEW. */
    static String pairPrompt(String aName, boolean aIsNew, List<String> hunks, String aTitle, String partA,
                             String bTitle, String partB) {
        StringBuilder prompt = new StringBuilder(String.format("Compare the two versions of the function %s: "
            + "decompile both, aligned, then list and assess the changes. The open program is the %s version.\n\n",
            aName, aIsNew ? "NEW" : "OLD"));
        prompt.append("== Assembly diff (OLD -> NEW, without addresses) ==\n");
        if (hunks.isEmpty()) {
            prompt.append("(the cleaned listings are equal: only addresses, registers or block order may differ)\n");
        }
        for (int i = 0; i < hunks.size() && i < MAX_ASM_DIFF_LINES; i++) {
            prompt.append(hunks.get(i)).append('\n');
        }
        if (hunks.size() > MAX_ASM_DIFF_LINES) {
            prompt.append('(').append(hunks.size() - MAX_ASM_DIFF_LINES).append(" more lines left out for size)\n");
        }
        prompt.append('\n');
        String oldPart = aIsNew ? partB : partA;
        String newPart = aIsNew ? partA : partB;
        prompt.append("######## OLD version: ").append(aIsNew ? bTitle : aTitle).append(" ########\n\n").append(oldPart);
        prompt.append("######## NEW version: ").append(aIsNew ? aTitle : bTitle).append(" ########\n\n").append(newPart);
        return prompt.toString();
    }

    /**
     * Run the query (or take it from the cache) and return the response; it
     * never fails without a response ("ok": false and "error" then). Blocks:
     * call it from a task, its monitor cancels the query.
     */
    public static String diffFunctions(Program program, String requestJson, TaskMonitor monitor) {
        try {
            return diff(program, requestJson, monitor != null ? monitor : TaskMonitor.DUMMY);
        }
        catch (CancelledException e) {
            return errorResponse("cancelled");
        }
        catch (Exception e) {
            Log.error("the diff failed: %s", e);
            return errorResponse("internal error: " + e);
        }
    }

    private static String diff(Program program, String requestJson, TaskMonitor monitor) throws CancelledException {
        Settings s = Settings.get();
        if (program == null) {
            return errorResponse("no program is open");
        }
        JsonObject req = Backend.parseObject(requestJson != null ? requestJson : "");
        if (req == null) {
            return errorResponse("the request is not valid JSON");
        }

        // version A: a function of the open program
        JsonObject ja = Backend.obj(req, "a");
        Long aEa = ja != null ? Text.parseHex(Backend.str(ja, "ea")) : null;
        if (aEa == null) {
            return errorResponse("the request has no address for version A");
        }
        Address aAddr = Names.toAddress(program, aEa);
        Function f = aAddr != null ? program.getFunctionManager().getFunctionContaining(aAddr) : null;
        if (f == null) {
            return errorResponse(Text.hex(aEa) + " is not a function of the open program");
        }
        String aName = Names.functionName(f);
        boolean aIsNew = Backend.bool(req, "a_is_new");
        boolean force = Backend.bool(req, "force");

        // version B: from the request
        JsonObject jb = Backend.obj(req, "b");
        SideB b;
        try {
            b = buildSideB(jb, s.budget, s.maxInsns);
        }
        catch (IllegalArgumentException e) {
            return errorResponse(e.getMessage());
        }

        String aHash = Cache.bytesHash(f);
        if (!force) {
            JsonObject cached = Cache.loadDiff(f, aHash, b.key, aIsNew);
            if (cached != null) {
                Log.info("%s: cached diff (%s, %s)", aName, Backend.str(cached, "model"), Backend.str(cached, "date"));
                cached.addProperty("cached", true);
                return cached.toString();
            }
        }

        monitor.setMessage("Claude-Rays Decompiler: collecting the context of " + aName);
        Collector.Collected col = new Collector(program, monitor).collect(f, s.budget);
        if (!col.error.isEmpty()) {
            return errorResponse(col.error);
        }

        String aTitle = aName + " (" + Names.hex(f.getEntryPoint()) + "), from the open program";
        String source = Backend.str(jb, "source");
        String bTitle = b.name + ", from " + (source.isEmpty() ? "the other database" : source);
        String prompt = pairPrompt(aName, aIsNew, Backend.strList(req, "asm_diff"), aTitle, col.body, bTitle, b.text);
        Log.debugText("diff input:", prompt);

        // the query (the monitor cancels it)
        Backend.Job job = new Backend.Job();
        job.model = s.defaultModel;
        job.effort = Models.effectiveEffort(job.model, s.effort);
        job.claudePath = s.claudePath;
        job.timeout = s.timeout;
        job.prompt = prompt;
        job.systemPrompt = Prompts.PAIR_SYSTEM_PROMPT;
        job.schema = Prompts.PAIR_SCHEMA;
        Log.info("comparing %s with %s (%d + %d instructions, %d chars of context) with %s...", aName, b.name,
            col.ninsns, b.ninsns, prompt.length(), job.modelText());
        long started = System.currentTimeMillis();
        monitor.setMessage("Claude is comparing the two versions of " + aName + " (" + job.modelText()
            + "). This can take a while (it depends on the size of the two functions, the connection and "
            + "Claude's own processing).");
        CancelledListener cl = job::cancel;
        monitor.addCancelledListener(cl);
        try {
            Backend.run(job);
        }
        finally {
            monitor.removeCancelledListener(cl);
        }
        if (monitor.isCancelled() || job.isCancelled()) {
            Log.info("the diff of %s was cancelled", aName);
            return errorResponse("cancelled");
        }

        String err = "";
        Backend.Answer ans = null;
        Backend.DecompResult resOld = null;
        Backend.DecompResult resNew = null;
        if (!job.ok) {
            err = job.error;
        }
        else {
            ans = Backend.extractResult(job);
            err = ans.error;
        }
        if (err.isEmpty()) {
            JsonObject jo = Backend.obj(ans.result, "old");
            JsonObject jn = Backend.obj(ans.result, "new");
            if (jo == null || jn == null) {
                err = Backend.safetyError(ans.usage, ans.result, "the answer has no old or new version");
            }
            else {
                try {
                    resOld = Backend.decodeResult(jo);
                    resNew = Backend.decodeResult(jn);
                }
                catch (IllegalArgumentException e) {
                    // the model explains a stop in the summary of a version
                    err = Backend.safetyError(ans.usage, Backend.str(jn, "summary").isEmpty() ? jo : jn,
                        "error unpacking the answer (" + e.getMessage() + ")");
                }
            }
        }
        if (!err.isEmpty()) {
            Log.error("comparing %s failed: %s", aName, err);
            return errorResponse(err);
        }
        f = program.getFunctionManager().getFunctionAt(f.getEntryPoint());
        if (f == null) {
            return errorResponse(aName + " is no longer a function: the answer is dropped");
        }

        // validation: version A against the program, version B against the
        // listing of the request, and the addresses of the changes
        List<String> warnings = new ArrayList<>();
        if (ans.usage.safetyStops > 0) {
            warnings.add(Backend.safetyNote(ans.usage.safetyStops, ans.usage.models));
        }
        Backend.DecompResult resA = aIsNew ? resNew : resOld;
        Backend.DecompResult resB = aIsNew ? resOld : resNew;
        String tagA = aIsNew ? "new: " : "old: ";
        String tagB = aIsNew ? "old: " : "new: ";
        for (String w : Validator.validate(f, resA, monitor)) {
            warnings.add(tagA + w);
        }
        List<Long> notes = CodeShaper.annotations(resB.code);
        List<String> bad = new ArrayList<>();
        for (long ea : notes) {
            if (!b.addresses.contains(ea)) {
                bad.add(Text.hex(ea));
            }
        }
        if (notes.isEmpty()) {
            warnings.add(tagB + "the code has no address annotations");
        }
        else if (!bad.isEmpty()) {
            warnings.add(tagB + "annotations that are not instructions of its listing: " + Text.shortList(bad, 8));
        }
        JsonArray changes = new JsonArray();
        JsonArray jch = Backend.arr(ans.result, "changes");
        if (jch != null) {
            int n = 0;
            for (JsonElement c : jch) {
                if (!c.isJsonObject()) {
                    continue;
                }
                n++;
                changes.add(c);
                for (int side = 0; side < 2; side++) {
                    boolean isOld = side == 0;
                    boolean isA = isOld != aIsNew;
                    List<String> badc = new ArrayList<>();
                    for (String a : Backend.strList(c.getAsJsonObject(), isOld ? "old_addresses" : "new_addresses")) {
                        Long ea = Text.parseHex(a);
                        boolean found = ea != null && (isA ? inFunctionA(f, ea) : b.addresses.contains(ea));
                        if (!found) {
                            badc.add(a);
                        }
                    }
                    if (!badc.isEmpty()) {
                        warnings.add(String.format("change %d: %s addresses not in the %s listing: ", n,
                            isOld ? "old" : "new", isOld ? "OLD" : "NEW") + Text.shortList(badc, 8));
                    }
                }
            }
        }

        JsonObject r = new JsonObject();
        r.addProperty("ok", true);
        r.addProperty("error", "");
        r.add("old", sideResponse(resOld));
        r.add("new", sideResponse(resNew));
        r.add("changes", changes);
        JsonObject as = Backend.obj(ans.result, "assessment");
        r.add("assessment", as != null ? as : new JsonObject());
        r.add("warnings", strArray(warnings));
        r.addProperty("model", job.model);
        r.addProperty("model_id", ans.usage.modelId);
        r.addProperty("effort", job.effort);
        r.addProperty("date", Text.now());
        r.addProperty("a_is_new", aIsNew);
        JsonObject u = new JsonObject();
        u.addProperty("input_tokens", ans.usage.inputTokens);
        u.addProperty("output_tokens", ans.usage.outputTokens);
        u.addProperty("cost_usd", ans.usage.costUsd);
        r.add("usage", u);
        r.addProperty("cached", false);
        Cache.saveDiff(f, aHash, b.key, aIsNew, r);

        double secs = (System.currentTimeMillis() - started) / 1000.0;
        Log.info("%s compared by %s in %.1f s (%d change(s), %d warning(s), %d in / %d out tokens, "
                + "$%.4f at API prices)", aName, ans.usage.modelId.isEmpty() ? job.model : ans.usage.modelId, secs,
            changes.size(), warnings.size(), ans.usage.inputTokens, ans.usage.outputTokens, ans.usage.costUsd);
        for (String w : warnings) {
            Log.info("  warning: %s", w);
        }
        return r.toString();
    }
}
