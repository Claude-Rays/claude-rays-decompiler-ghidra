package org.clauderays.ghidra.program;

import com.google.gson.JsonArray;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.Fixes;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Models;
import org.clauderays.ghidra.core.Prompts;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One decompilation, possibly over several need_more rounds. run() blocks: the plugin calls it from
 * a Ghidra task, whose monitor (or cancel()) stops the query.
 */
public final class Decompilation {

    /** need_more rounds per decompilation */
    public static final int MAX_ROUNDS = 2;

    /** What the view shows while the query runs and when it is over. */
    public interface Listener {
        void status(Program program, Address entry, List<String> lines);

        void result(Program program, Address entry, Cache.Entry entry2, Cache.State state);
    }

    public final Program program;
    public final Address entry;
    public final String funcName;
    public final String model;
    /** "" = the CLI default */
    public final String effort;
    /** Settings.CONTEXT_...: what the context gives of the function */
    public final String context;
    /** Decompile and analyze: the security analysis of the function in the same query */
    public final boolean analyze;
    /** Decompile, analyze and patch: then the fixes of the findings, in a second query */
    public final boolean patch;
    private final Listener listener;

    private int round;
    /** Collected.ghidraNote of the context */
    private String contextNote = "";
    private String basePrompt = "";
    private final StringBuilder requested = new StringBuilder();
    private final Set<String> seen = new HashSet<>();
    private final List<String> ignored = new ArrayList<>();
    private final Backend.Usage usage = new Backend.Usage();
    private volatile Backend.Job job;
    private volatile boolean cancelled;
    private long startedMs;

    public Decompilation(Function f, String model, Listener listener) {
        this(f, model, Settings.get().context, false, listener);
    }

    /** With another context mode than the one of the settings. */
    public Decompilation(Function f, String model, String context, Listener listener) {
        this(f, model, context, false, listener);
    }

    /** ... and maybe the security analysis (Decompile and analyze). */
    public Decompilation(Function f, String model, String context, boolean analyze, Listener listener) {
        this(f, model, context, analyze, false, listener);
    }

    /** ... and maybe the fixes of its findings (Decompile, analyze and patch; it implies 'analyze'). */
    public Decompilation(Function f, String model, String context, boolean analyze, boolean patch,
                         Listener listener) {
        this.program = f.getProgram();
        this.entry = f.getEntryPoint();
        this.funcName = Names.functionName(f);
        this.model = model;
        this.effort = Models.effectiveEffort(model, Settings.get().effort);
        this.context = Settings.contextOf(context);
        this.analyze = analyze || patch;
        this.patch = patch;
        this.listener = listener;
    }

    /** "sonnet, effort medium" (and the context when it is not the listing alone) */
    public String modelText() {
        String s = effort.isEmpty() ? model : model + ", effort " + effort;
        if (!context.equals(Settings.CONTEXT_LISTING)) {
            s += ", " + Settings.contextLabel(context);
        }
        return patch ? s + ", with security analysis and fixes" : analyze ? s + ", with security analysis" : s;
    }

    /** The command: where the result is cached. */
    public Cache.Mode mode() {
        return Cache.Mode.of(analyze, patch);
    }

    public boolean isCancelled() {
        return cancelled;
    }

    /** Thread-safe: stop the query, no more rounds. */
    public void cancel() {
        cancelled = true;
        Backend.Job j = job;
        if (j != null) {
            j.cancel();
        }
    }

    private Function function() {
        return program.getFunctionManager().getFunctionAt(entry);
    }

    private void status(String... lines) {
        listener.status(program, entry, List.of(lines));
    }

    /** Collect, query (with the need_more rounds), validate, cache and show. */
    public void run(TaskMonitor monitor) {
        run(monitor, () -> runRounds(monitor));
    }

    /**
     * Only the fixes of a cached analysis ('patch': of Decompile and analyze, or
     * of a Decompile, analyze and patch whose fixes failed), which is cached as
     * the result of Decompile, analyze and patch and shown with them.
     */
    public void runFix(Cache.Entry cached, Cache.State state, TaskMonitor monitor) {
        run(monitor, () -> {
            Function f = function();
            if (f == null) {
                status("Claude-Rays Decompiler: " + Names.hex(entry) + " is not a function.");
                return;
            }
            fix(f, cached, monitor);
            // nothing to fix: the analysis alone is the result
            if (Fixes.wantedNumbers(cached.findings).isEmpty()) {
                Cache.save(f, mode(), cached);
            }
            listener.result(program, entry, cached, state);
        });
    }

    private interface Step {
        void run() throws CancelledException;
    }

    private void run(TaskMonitor monitor, Step step) {
        CancelledListener cl = this::cancel;
        monitor.addCancelledListener(cl);
        try {
            step.run();
        }
        catch (CancelledException e) {
            cancelled = true;
            status("Claude-Rays Decompiler: the decompilation of " + funcName + " was cancelled.",
                "Claude-Rays Decompiler > Regenerate tries again.");
        }
        catch (Exception e) {
            Log.error("decompiling %s failed: %s", funcName, e);
            status("Claude-Rays Decompiler: decompiling " + funcName + " failed:", String.valueOf(e),
                "Claude-Rays Decompiler > Regenerate tries again.");
        }
        finally {
            monitor.removeCancelledListener(cl);
        }
    }

    private void runRounds(TaskMonitor monitor) throws CancelledException {
        Function f = function();
        if (f == null) {
            status("Claude-Rays Decompiler: " + Names.hex(entry) + " is not a function.");
            return;
        }
        monitor.setMessage("Claude-Rays Decompiler: collecting the context of " + funcName);
        Collector collector = new Collector(program, monitor).context(context);
        Collector.Collected col = collector.collect(f, 0);
        if (!col.error.isEmpty()) {
            Log.error("%s", col.error);
            status("Claude-Rays Decompiler: " + col.error + ".");
            return;
        }
        Log.debugText("input:", col.text);
        basePrompt = col.text;
        contextNote = col.ghidraNote;
        startedMs = System.currentTimeMillis();
        Log.info("decompiling %s (%d instructions, %d chars of context) with %s...", funcName, col.ninsns,
            col.text.length(), modelText());

        Settings s = Settings.get();
        for (; ; ) {
            if (cancelled) {
                throw new CancelledException();
            }
            Backend.Job j = newJob();
            job = j;
            List<String> st = new ArrayList<>();
            st.add("Claude-Rays Decompiler: " + (analyze ? "decompiling and analyzing " : "decompiling ") + funcName
                + " with " + modelText() + "...");
            if (round > 0) {
                st.add(String.format("Asking for more context (round %d/%d).", round, MAX_ROUNDS));
            }
            st.add("It can take a while (it depends on the size of the function, the connection and Claude's own "
                + "processing). Cancel in the task monitor (or Claude-Rays Decompiler > Cancel) stops it.");
            listener.status(program, entry, st);
            monitor.setMessage("Claude is decompiling " + funcName + " (" + modelText() + ")"
                + (round > 0 ? String.format(", round %d/%d", round, MAX_ROUNDS) : ""));
            Backend.run(j);
            if (cancelled || monitor.isCancelled()) {
                throw new CancelledException();
            }

            String err = "";
            Backend.DecompResult res = null;
            Backend.Answer ans = null;
            if (!j.ok) {
                err = j.error;
            }
            else {
                ans = Backend.extractResult(j);
                usage.add(ans.usage);
                if (!ans.ok()) {
                    err = ans.error;
                }
                else {
                    try {
                        res = Backend.decodeResult(ans.result);
                    }
                    catch (IllegalArgumentException e) {
                        err = Backend.safetyError(ans.usage, ans.result,
                            "error unpacking the answer (" + e.getMessage() + ")");
                    }
                }
            }
            if (!err.isEmpty()) {
                Log.error("decompiling %s with '%s' failed: %s", funcName, model, err);
                List<String> lines = new ArrayList<>();
                lines.add("Claude-Rays Decompiler: decompiling " + funcName + " with " + modelText() + " failed:");
                lines.addAll(Text.splitLines(err));
                lines.add("Claude-Rays Decompiler > Regenerate tries again.");
                listener.status(program, entry, lines);
                return;
            }
            f = function();
            if (f == null) {
                Log.error("%s is no longer a function: the answer is dropped", Names.hex(entry));
                return;
            }
            Log.debug("%s round %d: %d uncertain, %d context request(s)", funcName, round, res.uncertain.size(),
                res.needMore.size());
            for (Backend.NeedMore n : res.needMore) {
                Log.debug("  need_more %s %s: %s", n.what(), n.target(), n.reason());
            }

            List<String> missing = new ArrayList<>();
            if (!res.needMore.isEmpty()) {
                if (round < MAX_ROUNDS) {
                    int before = ignored.size();
                    String extra = collector.collectRequested(res.needMore, seen, s.budget / 2, ignored);
                    if (!extra.isEmpty()) {
                        round++;
                        requested.append(extra);
                        Log.info("%s: the model asked for more context (round %d/%d)", funcName, round, MAX_ROUNDS);
                        continue;
                    }
                    missing.addAll(ignored.subList(before, ignored.size()));
                }
                else {
                    for (Backend.NeedMore n : res.needMore) {
                        missing.add(n.what() + " " + n.target() + ": " + n.reason() + " (no rounds left)");
                    }
                }
            }
            finish(f, res, missing, monitor);
            return;
        }
    }

    private Backend.Job newJob() {
        Settings s = Settings.get();
        Backend.Job j = new Backend.Job();
        j.model = model;
        j.effort = effort;
        j.claudePath = s.claudePath;
        j.timeout = s.timeout;
        if (analyze) {
            j.systemPrompt = Prompts.ANALYZE_SYSTEM_PROMPT;
            j.schema = Prompts.ANALYZE_SCHEMA;
        }
        StringBuilder prompt = new StringBuilder(basePrompt);
        if (requested.length() > 0) {
            prompt.append("== Requested context ==\n").append(requested);
        }
        if (!ignored.isEmpty()) {
            prompt.append("== Requests that could not be served ==\n");
            for (String i : ignored) {
                prompt.append("  ").append(i).append('\n');
            }
        }
        if (round > 0) {
            prompt.append(String.format("\nThis is round %d of %d: ", round, MAX_ROUNDS));
            prompt.append(round >= MAX_ROUNDS
                ? "no more context can be requested, give your final answer with need_more empty.\n"
                : "ask for more context only if it is really needed.\n");
            Log.debugText("requested context (round " + round + "):", requested.toString());
        }
        j.prompt = prompt.toString();
        return j;
    }

    private void finish(Function f, Backend.DecompResult res, List<String> missing, TaskMonitor monitor)
        throws CancelledException {
        Cache.Entry e = new Cache.Entry();
        e.bytesHash = Cache.bytesHash(f);
        e.namesHash = Cache.namesHash(f);
        e.model = model;
        e.effort = effort;
        e.modelId = usage.modelId;
        e.date = Text.now();
        e.costUsd = usage.costUsd;
        e.inputTokens = usage.inputTokens;
        e.outputTokens = usage.outputTokens;
        e.safetyStops = usage.safetyStops;
        e.models.addAll(usage.models);
        e.summary = res.summary;
        e.prototype = res.prototype;
        e.code = res.code;
        e.uncertain.addAll(res.uncertain);
        e.warnings.addAll(Validator.validate(f, res, monitor));
        e.analyzed = analyze;
        if (analyze) {
            e.findings.addAll(Validator.anchorFindings(f, res.findings, e.warnings));
        }
        e.missing.addAll(missing);
        e.rounds = round;
        e.context = context;
        e.contextNote = contextNote;
        Cache.save(f, mode(), e);
        double secs = (System.currentTimeMillis() - startedMs) / 1000.0;
        Log.info("%s decompiled by %s in %.1f s (%d extra round(s), %d warning(s), %d uncertain, "
                + "%d in / %d out tokens, $%.4f at API prices)%s", funcName, e.modelUsed(), secs, round,
            e.warnings.size(), e.uncertain.size(), e.inputTokens, e.outputTokens, e.costUsd,
            analyze ? String.format(", %d security finding(s)", e.findings.size()) : "");
        for (String w : e.warnings) {
            Log.info("  warning: %s", w);
        }
        if (e.safetyStops > 0) {
            Log.info("  %s", Backend.safetyNote(e.safetyStops, e.models));
        }
        if (patch) {
            fix(f, e, monitor);
        }
        listener.result(program, entry, e, Cache.State.VALID);
    }

    /**
     * The fixes of the findings of 'e' (the confirmed and possible ones), into
     * e.fix and the cache. Nothing is asked when there is nothing to fix; a
     * failed query leaves e.fix unset and the result is shown without fixes.
     */
    private void fix(Function f, Cache.Entry e, TaskMonitor monitor) throws CancelledException {
        java.util.Set<Integer> asked = Fixes.wantedNumbers(e.findings);
        if (asked.isEmpty()) {
            Log.info("%s: no confirmed or possible finding, nothing to fix", funcName);
            return;
        }
        if (cancelled) {
            throw new CancelledException();
        }
        Settings s = Settings.get();
        Backend.Job j = new Backend.Job();
        j.model = model;
        j.effort = effort;
        j.claudePath = s.claudePath;
        j.timeout = s.timeout;
        j.systemPrompt = Prompts.FIX_SYSTEM_PROMPT;
        j.schema = Prompts.FIX_SCHEMA;
        j.prompt = Fixes.prompt(e.summary, e.prototype, e.code, e.findings);
        job = j;
        Log.debugText("fix input:", j.prompt);
        status("Claude-Rays Decompiler: writing the fixes of " + asked.size() + " finding(s) of " + funcName
            + " with " + j.modelText() + "...", "Cancel in the task monitor (or Claude-Rays Decompiler > Cancel) "
            + "stops it; the decompilation and its analysis are already cached.");
        monitor.setMessage("Claude is fixing " + funcName + " (" + j.modelText() + ")");
        long t0 = System.currentTimeMillis();
        Backend.run(j);
        if (cancelled || monitor.isCancelled()) {
            throw new CancelledException();
        }
        String err = j.ok ? "" : j.error;
        Backend.Answer ans = null;
        if (err.isEmpty()) {
            ans = Backend.extractResult(j);
            err = ans.error;
            // a safety stop can leave the answer without any fix
            JsonArray given = Backend.arr(ans.result, "fixes");
            if (err.isEmpty() && (given == null || given.isEmpty())) {
                err = Backend.safetyError(ans.usage, ans.result, "");
            }
        }
        if (!err.isEmpty()) {
            Log.error("the fixes of %s failed: %s (the result is shown without them; Decompile, analyze and patch "
                + "tries again)", funcName, err);
            e.warnings.add("the fixes could not be made: " + Text.oneLine(err, 300));
            return;
        }
        Fixes.Result r = new Fixes.Result();
        r.model = model;
        r.effort = effort;
        r.modelId = ans.usage.modelId;
        r.date = Text.now();
        r.costUsd = ans.usage.costUsd;
        r.inputTokens = ans.usage.inputTokens;
        r.outputTokens = ans.usage.outputTokens;
        r.safetyStops = ans.usage.safetyStops;
        r.models.addAll(ans.usage.models);
        r.fixes.addAll(Fixes.decode(ans.result, Text.splitLines(e.code), asked, r.warnings));
        e.fix = r;
        Cache.save(f, mode(), e);
        long nFixed = r.fixes.stream().filter(x -> !x.edits().isEmpty()).count();
        Log.info("%s: %d of %d finding(s) fixed by %s in %.1f s (%d edit(s), %d warning(s), %d in / %d out tokens, "
                + "$%.4f at API prices)", funcName, nFixed, asked.size(), r.modelUsed(),
            (System.currentTimeMillis() - t0) / 1000.0, r.edits().size(), r.warnings.size(), r.inputTokens,
            r.outputTokens, r.costUsd);
        for (String w : r.warnings) {
            Log.info("  fix warning: %s", w);
        }
        if (r.safetyStops > 0) {
            Log.info("  %s", Backend.safetyNote(r.safetyStops, r.models));
        }
    }
}
