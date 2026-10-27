package org.clauderays.ghidra.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Query backend: runs the Claude Code CLI ("claude -p") as a
 * child process with the decompiler system prompt and schema, and extracts
 * the validated answer.
 */
public final class Backend {

    private Backend() {
    }

    /** One query to the model. */
    public static final class Job {
        // input
        public String model = Settings.DEFAULT_MODEL;
        /** "" = not passed (the CLI default) */
        public String effort = "";
        public String claudePath = Settings.DEFAULT_CLAUDE_PATH;
        public int timeout;
        public String prompt = "";
        /** "" = the decompiler ones; the diff of two versions has its own */
        public String systemPrompt = "";
        public String schema = "";

        // output
        /** the process ran */
        public boolean ok;
        public int exitCode;
        public String response = "";
        public String errout = "";
        public String error = "";

        final ClaudeProcess proc = new ClaudeProcess();

        /** Thread-safe: abort the query in flight. */
        public void cancel() {
            proc.cancel();
        }

        public boolean isCancelled() {
            return proc.isCancelled();
        }

        /** "sonnet, effort medium" */
        public String modelText() {
            return effort.isEmpty() ? model : model + ", effort " + effort;
        }
    }

    /** The command line arguments of a query (without the executable). */
    static List<String> arguments(Job job) {
        List<String> args = new ArrayList<>(List.of(
            "-p",
            "--output-format", "json",
            "--model", job.model,
            "--system-prompt", job.systemPrompt.isEmpty() ? Prompts.SYSTEM_PROMPT : job.systemPrompt,
            "--json-schema", job.schema.isEmpty() ? Prompts.SCHEMA : job.schema,
            "--tools", "",                // no tools: it only answers
            "--strict-mcp-config",        // none of the user's MCP servers
            "--setting-sources", "",      // none of the user's settings / CLAUDE.md
            "--no-session-persistence"));
        if (!job.effort.isEmpty()) {
            args.add("--effort");
            args.add(job.effort);
        }
        return args;
    }

    /** Run the query (blocking), filling the output fields of 'job'. */
    public static void run(Job job) {
        String exe = ClaudeProcess.findExecutable(job.claudePath);
        if (exe == null) {
            job.error = "the Claude Code CLI ('" + job.claudePath + "') was not found. Install it "
                + "(irm https://claude.ai/install.ps1 | iex), log in once with 'claude' + /login, "
                + "or set its full path in Claude-Rays Decompiler > Settings";
            return;
        }
        // a neutral directory, so no project CLAUDE.md is picked up
        File cwd = ClaudeProcess.neutralWorkDir();
        // the prompt goes through stdin: no command line length limit, no quoting
        ClaudeProcess.Result r = job.proc.run(exe, arguments(job), cwd, job.prompt, job.timeout);
        job.ok = r.ok;
        job.exitCode = r.exitCode;
        job.response = r.out;
        job.errout = r.err;
        if (!r.ok) {
            job.error = r.error.equals("cancelled") ? "cancelled" : "running " + exe + ": " + r.error;
        }
    }

    //--------------------------------------------------------------------------
    /** What one query used, as reported by the CLI. */
    public static final class Usage {
        /** the model that answered ("" if not reported) */
        public String modelId = "";
        /** at API prices */
        public double costUsd;
        /** including the cache reads and writes */
        public long inputTokens;
        public long outputTokens;
        /**
         * how many times Claude's safety checks stopped the answer (the CLI's
         * safety_stops); after a stop the CLI may finish it with another model
         */
        public int safetyStops;
        /** every model that took part in the answer, as reported */
        public final List<String> models = new ArrayList<>();

        public void add(Usage u) {
            if (!u.modelId.isEmpty()) {
                modelId = u.modelId;
            }
            costUsd += u.costUsd;
            inputTokens += u.inputTokens;
            outputTokens += u.outputTokens;
            safetyStops += u.safetyStops;
            for (String m : u.models) {
                if (!models.contains(m)) {
                    models.add(m);
                }
            }
        }
    }

    /**
     * The note of an answer completed after a safety stop ("" if none): the
     * analysis of a function that looks like an exploit target can trip
     * Claude's safety checks, and the CLI then finishes with another model.
     */
    public static String safetyNote(int stops, List<String> models) {
        if (stops <= 0) {
            return "";
        }
        return String.format("Claude's safety checks stopped this answer %d time(s); it was completed by %s. A "
            + "fallback model may be less precise.", stops, models.isEmpty() ? "the CLI" : String.join(" + ", models));
    }

    /**
     * The error of an answer that a safety stop left without its content, with
     * the explanation the model gave (its 'summary'), or 'err' unchanged when
     * there was no stop. It is not retried: Regenerate asks again.
     */
    public static String safetyError(Usage u, JsonObject result, String err) {
        if (u.safetyStops <= 0) {
            return err;
        }
        String why = Text.oneLine(str(result, "summary"), 400);
        return String.format("Claude's safety checks stopped this answer (%d safety stop(s)) and it came back "
                + "without its content%s. This can happen with the security review of code that looks like an "
                + "exploit target. It is not retried automatically; Regenerate asks again in a new query.",
            u.safetyStops, why.isEmpty() ? "" : ": \"" + why + "\"");
    }

    /** The answer of the CLI: the model's JSON object or an error. */
    public static final class Answer {
        public JsonObject result;
        public String error = "";
        public final Usage usage = new Usage();

        public boolean ok() {
            return result != null && error.isEmpty();
        }
    }

    /** The answer as text may come wrapped in a ```json fence. */
    static String stripFence(String text) {
        String t = Text.trim(text);
        if (!t.startsWith("```")) {
            return t;
        }
        int nl = t.indexOf('\n');
        int end = t.lastIndexOf("```");
        if (nl < 0 || end <= nl) {
            return t;
        }
        return Text.trim(t.substring(nl + 1, end));
    }

    static String errorHint(String text) {
        String low = text.toLowerCase(Locale.ROOT);
        if (low.contains("login") || low.contains("log in") || low.contains("authenticat") || low.contains("api key")) {
            return "\nRun 'claude' in a terminal and log in with /login (Claude Pro/Max account).";
        }
        if (low.contains("usage limit") || low.contains("rate limit") || low.contains("limit reached")) {
            return "\nThe usage limit of your plan was reached: wait for it to reset.";
        }
        return "";
    }

    /** The numeric value of a member, 0 if missing. */
    static double num(JsonObject j, String key) {
        if (j == null) {
            return 0;
        }
        JsonElement v = j.get(key);
        try {
            return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber() ? v.getAsDouble() : 0;
        }
        catch (NumberFormatException e) {
            return 0;
        }
    }

    /** The text of a member ("" if missing or null); numbers and booleans as text. */
    public static String str(JsonObject j, String key) {
        if (j == null) {
            return "";
        }
        JsonElement v = j.get(key);
        if (v == null || v.isJsonNull()) {
            return "";
        }
        return v.isJsonPrimitive() ? v.getAsString() : v.toString();
    }

    public static JsonObject obj(JsonObject j, String key) {
        JsonElement v = j != null ? j.get(key) : null;
        return v != null && v.isJsonObject() ? v.getAsJsonObject() : null;
    }

    public static JsonArray arr(JsonObject j, String key) {
        JsonElement v = j != null ? j.get(key) : null;
        return v != null && v.isJsonArray() ? v.getAsJsonArray() : null;
    }

    public static boolean bool(JsonObject j, String key) {
        JsonElement v = j != null ? j.get(key) : null;
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isBoolean() && v.getAsBoolean();
    }

    /** The strings of an array member (other items as their JSON text). */
    public static List<String> strList(JsonObject j, String key) {
        List<String> out = new ArrayList<>();
        JsonArray a = arr(j, key);
        if (a != null) {
            for (JsonElement x : a) {
                out.add(x.isJsonPrimitive() ? x.getAsString() : x.toString());
            }
        }
        return out;
    }

    /** null if 'text' is not a JSON object. */
    public static JsonObject parseObject(String text) {
        try {
            JsonElement e = JsonParser.parseString(text);
            return e.isJsonObject() ? e.getAsJsonObject() : null;
        }
        catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Cost, tokens and the model that answered; modelUsage is keyed by the full
     * model id (the one that cost the most if the CLI used several).
     */
    static void readUsage(JsonObject outer, Usage u) {
        u.costUsd = num(outer, "total_cost_usd");
        JsonObject usage = obj(outer, "usage");
        u.inputTokens = (long) (num(usage, "input_tokens") + num(usage, "cache_read_input_tokens")
            + num(usage, "cache_creation_input_tokens"));
        u.outputTokens = (long) num(usage, "output_tokens");
        u.safetyStops = (int) num(outer, "safety_stops");
        JsonObject mu = obj(outer, "modelUsage");
        double best = -1;
        if (mu != null) {
            for (Map.Entry<String, JsonElement> kv : mu.entrySet()) {
                u.models.add(kv.getKey());
                double c = kv.getValue().isJsonObject() ? num(kv.getValue().getAsJsonObject(), "costUSD") : 0;
                if (c > best) {
                    best = c;
                    u.modelId = kv.getKey();
                }
            }
        }
    }

    private static String cut(String s, int max) {
        return s.length() > max ? s.substring(0, max) : s;
    }

    /** The model's answer as a JSON object, once the job ran (job.ok). */
    public static Answer extractResult(Job job) {
        Answer a = new Answer();
        String stdout = Text.trim(job.response);
        String stderr = Text.trim(job.errout);
        JsonObject outer = stdout.isEmpty() ? null : parseObject(stdout);
        if (outer == null) {
            String details = !stderr.isEmpty() ? stderr : stdout;
            if (details.isEmpty()) {
                details = "(no output)";
            }
            a.error = String.format("the Claude Code CLI exited with code %d without a valid answer:\n%s%s",
                job.exitCode, cut(details, 2000), errorHint(details));
            return a;
        }
        readUsage(outer, a.usage);

        if (Settings.get().verbose) {
            JsonObject tok = obj(outer, "usage");
            Log.debug("claude-cli: %s, %s turn(s), %s ms, cost %s USD (plan usage), "
                    + "tokens in %s (cache read %s, cache write %s) / out %s",
                str(outer, "subtype"), str(outer, "num_turns"), str(outer, "duration_ms"),
                str(outer, "total_cost_usd"), str(tok, "input_tokens"), str(tok, "cache_read_input_tokens"),
                str(tok, "cache_creation_input_tokens"), str(tok, "output_tokens"));
            if (a.usage.safetyStops > 0) {
                Log.debug("claude-cli: %d safety stop(s)", a.usage.safetyStops);
            }
            JsonObject mu = obj(outer, "modelUsage");
            if (mu != null) {
                for (String k : mu.keySet()) {
                    Log.debug("claude-cli: model used: %s", k);
                }
            }
            if (!stderr.isEmpty()) {
                Log.debugText("claude-cli stderr:", stderr);
            }
            Log.debugText("claude-cli output:", stdout);
        }

        if (bool(outer, "is_error") || job.exitCode != 0) {
            String msg = str(outer, "result");
            if (msg.isEmpty()) {
                msg = !stderr.isEmpty() ? stderr : str(outer, "subtype");
            }
            String api = str(outer, "api_error_status");
            boolean hasApi = !api.isEmpty() && !api.equals("null");
            a.error = String.format("the Claude Code CLI reported an error (exit code %d%s%s): %s%s",
                job.exitCode, hasApi ? ", API status " : "", hasApi ? api : "", cut(msg, 2000), errorHint(msg));
            return a;
        }

        // with --json-schema the validated object comes in structured_output
        JsonObject so = obj(outer, "structured_output");
        if (so != null) {
            a.result = so;
            Log.debugText("model answer:", so.toString());
            return a;
        }
        // fall back to the text answer
        String t = stripFence(str(outer, "result"));
        Log.debugText("model answer:", t);
        a.result = parseObject(t);
        if (a.result == null) {
            a.error = "error unpacking response (not a JSON object)\n" + cut(t, 2000);
        }
        return a;
    }

    //--------------------------------------------------------------------------
    // the decoded answer
    //--------------------------------------------------------------------------
    public record Uncertain(String address, String reason) {
    }

    public record NeedMore(String what, String target, String reason) {
    }

    /** One finding of the security analysis (Decompile and analyze). */
    public record Finding(String level, String bugClass, List<String> addresses, String description,
                          String precondition) {

        public static final String CONFIRMED = "confirmed";
        public static final String POSSIBLE = "possible";
        public static final String THEORETICAL = "theoretical";

        /** 0 confirmed, 1 possible, 2 theoretical: the lower, the more severe */
        public int rank() {
            return switch (level) {
                case CONFIRMED -> 0;
                case POSSIBLE -> 1;
                default -> 2;
            };
        }

        /** "CONFIRMED stack buffer overflow at 0x401020: ... Precondition: ..." */
        public String text() {
            String pre = Text.trim(precondition);
            boolean noPre = pre.isEmpty() || pre.toLowerCase(Locale.ROOT).startsWith("none");
            return String.format("%s %s at %s: %s%s", level.toUpperCase(Locale.ROOT),
                bugClass.isEmpty() ? "finding" : bugClass, String.join(", ", addresses), description,
                noPre ? "" : " Precondition: " + pre);
        }

        /** A known level, theoretical otherwise. */
        public static String levelOf(String s) {
            String l = Text.trim(s).toLowerCase(Locale.ROOT);
            return l.equals(CONFIRMED) || l.equals(POSSIBLE) ? l : THEORETICAL;
        }
    }

    public static final class DecompResult {
        /** header comment, plain text */
        public String summary = "";
        public String prototype = "";
        public String code = "";
        public final List<Uncertain> uncertain = new ArrayList<>();
        public final List<NeedMore> needMore = new ArrayList<>();
        /** the security analysis, when it was asked for */
        public final List<Finding> findings = new ArrayList<>();
    }

    /** The findings of an answer (or of a cached entry), the most severe first. */
    public static List<Finding> decodeFindings(JsonArray a) {
        List<Finding> out = new ArrayList<>();
        if (a == null) {
            return out;
        }
        for (JsonElement x : a) {
            if (!x.isJsonObject()) {
                continue;
            }
            JsonObject o = x.getAsJsonObject();
            List<String> addrs = new ArrayList<>();
            for (String s : strList(o, "addresses")) {
                if (!Text.trim(s).isEmpty()) {
                    addrs.add(Text.trim(s));
                }
            }
            out.add(new Finding(Finding.levelOf(str(o, "level")), Text.trim(str(o, "class")), addrs,
                Text.trim(str(o, "description")), Text.trim(str(o, "precondition"))));
        }
        out.sort(java.util.Comparator.comparingInt(Finding::rank));
        return out;
    }

    public static JsonArray encodeFindings(List<Finding> findings) {
        JsonArray a = new JsonArray();
        for (Finding f : findings) {
            JsonObject o = new JsonObject();
            o.addProperty("level", f.level());
            o.addProperty("class", f.bugClass());
            JsonArray addrs = new JsonArray();
            f.addresses().forEach(addrs::add);
            o.add("addresses", addrs);
            o.addProperty("description", f.description());
            o.addProperty("precondition", f.precondition());
            a.add(o);
        }
        return a;
    }

    /** The answer of a decompilation; throws IllegalArgumentException with a readable message. */
    public static DecompResult decodeResult(JsonObject j) {
        if (j == null) {
            throw new IllegalArgumentException("the answer is not an object");
        }
        DecompResult out = new DecompResult();
        out.summary = Text.trim(str(j, "summary"));
        out.prototype = Text.trim(str(j, "prototype"));
        // normalize the line ends
        out.code = str(j, "code").replace("\r", "");
        if (Text.trim(out.code).isEmpty()) {
            throw new IllegalArgumentException("the answer has no code");
        }
        JsonArray u = arr(j, "uncertain");
        if (u != null) {
            for (JsonElement x : u) {
                if (x.isJsonObject()) {
                    JsonObject o = x.getAsJsonObject();
                    out.uncertain.add(new Uncertain(Text.trim(str(o, "address")), Text.trim(str(o, "reason"))));
                }
            }
        }
        JsonArray n = arr(j, "need_more");
        if (n != null) {
            for (JsonElement x : n) {
                if (x.isJsonObject() && !Text.trim(str(x.getAsJsonObject(), "target")).isEmpty()) {
                    JsonObject o = x.getAsJsonObject();
                    out.needMore.add(new NeedMore(Text.trim(str(o, "what")), Text.trim(str(o, "target")),
                        Text.trim(str(o, "reason"))));
                }
            }
        }
        out.findings.addAll(decodeFindings(arr(j, "findings")));
        return out;
    }
}
