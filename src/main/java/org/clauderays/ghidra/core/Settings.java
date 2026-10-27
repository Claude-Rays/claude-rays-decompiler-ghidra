package org.clauderays.ghidra.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * The settings, kept through a key/value store (Ghidra's user preferences,
 * see ClaudeRaysPlugin), keys prefixed "clauderays.".
 */
public final class Settings {

    public static final String DEFAULT_MODEL = "opus";
    public static final String DEFAULT_CLAUDE_PATH = "claude";

    /** What the context gives of the function: the annotated listing only. */
    public static final String CONTEXT_LISTING = "listing";
    /** The annotated listing, and the C of Ghidra's decompiler as a draft. */
    public static final String CONTEXT_BOTH = "listing+ghidra";
    /** The C of Ghidra's decompiler first, and the listing without facts: smaller, less faithful. */
    public static final String CONTEXT_GHIDRA = "ghidra";
    public static final List<String> CONTEXTS = List.of(CONTEXT_LISTING, CONTEXT_BOTH, CONTEXT_GHIDRA);
    private static final String PREFIX = "clauderays.";

    private static final Settings INSTANCE = new Settings();

    /** Model used by Decompile (opus by default: the most readable results). */
    public String defaultModel = DEFAULT_MODEL;
    /** Model ids typed by the user that are not in the catalog; the menus offer the catalog plus these. */
    public final List<String> models = new ArrayList<>();
    /** "claude --effort": auto (the model's default in the catalog) or a level. */
    public String effort = "auto";
    /** claude.exe: a name looked up in PATH or a full path. */
    public String claudePath = DEFAULT_CLAUDE_PATH;
    /** Timeout for one answer, in seconds (0 = wait forever). */
    public int timeout = 300;
    /** Functions with more instructions are not sent. */
    public int maxInsns = 1500;
    /** Size budget of the collected context, in characters. */
    public int budget = 60000;
    /** Log debug messages (full input and output, section sizes, usage). */
    public boolean verbose = false;
    /** Show the /*0x...*&#47; address annotations in the view (double click still uses them). */
    public boolean showAnnotations = false;
    /**
     * CONTEXT_LISTING, CONTEXT_BOTH or CONTEXT_GHIDRA. CONTEXT_BOTH by default:
     * in the A/B check on real functions it cost the same as the listing alone,
     * with fewer validation warnings.
     */
    public String context = CONTEXT_BOTH;

    public static Settings get() {
        return INSTANCE;
    }

    private static int intOf(String s, int def) {
        try {
            return s == null || s.isBlank() ? def : Integer.parseInt(s.trim());
        }
        catch (NumberFormatException e) {
            return def;
        }
    }

    private static String strOf(String s, String def) {
        return s == null || s.isBlank() ? def : s;
    }

    public void load(Function<String, String> store) {
        setModels(strOf(store.apply(PREFIX + "models"), ""));
        setDefaultModel(strOf(store.apply(PREFIX + "default_model"), ""));
        effort = strOf(store.apply(PREFIX + "effort"), "auto");
        claudePath = strOf(store.apply(PREFIX + "claude_path"), DEFAULT_CLAUDE_PATH);
        timeout = Math.max(intOf(store.apply(PREFIX + "timeout"), 300), 0);
        maxInsns = Math.max(intOf(store.apply(PREFIX + "max_insns"), 1500), 10);
        budget = Math.max(intOf(store.apply(PREFIX + "budget"), 60000), 4000);
        verbose = intOf(store.apply(PREFIX + "verbose"), 0) != 0;
        showAnnotations = intOf(store.apply(PREFIX + "show_annotations"), 0) != 0;
        context = contextOf(strOf(store.apply(PREFIX + "context"), CONTEXT_BOTH));
    }

    /** A known context mode, CONTEXT_LISTING for anything else. */
    public static String contextOf(String s) {
        String c = s == null ? "" : Text.trim(s);
        return CONTEXTS.contains(c) ? c : CONTEXT_LISTING;
    }

    /** "listing", "listing + Ghidra's C", "Ghidra's C + listing" */
    public static String contextLabel(String context) {
        return switch (contextOf(context)) {
            case CONTEXT_BOTH -> "listing + Ghidra's C";
            case CONTEXT_GHIDRA -> "Ghidra's C + plain listing";
            default -> "listing";
        };
    }

    public void save(BiConsumer<String, String> store) {
        store.accept(PREFIX + "models", modelsStr());
        store.accept(PREFIX + "default_model", defaultModel);
        store.accept(PREFIX + "effort", effort);
        store.accept(PREFIX + "claude_path", claudePath);
        store.accept(PREFIX + "timeout", Integer.toString(timeout));
        store.accept(PREFIX + "max_insns", Integer.toString(maxInsns));
        store.accept(PREFIX + "budget", Integer.toString(budget));
        store.accept(PREFIX + "verbose", verbose ? "1" : "0");
        store.accept(PREFIX + "show_annotations", showAnnotations ? "1" : "0");
        store.accept(PREFIX + "context", context);
    }

    public String modelsStr() {
        return String.join(", ", models);
    }

    /** Comma separated list without blanks, duplicates or catalog models. */
    public void setModels(String csv) {
        models.clear();
        for (String part : csv.split(",", -1)) {
            String m = Text.trim(part);
            if (!m.isEmpty() && Models.find(m) == null && !models.contains(m)) {
                models.add(m);
            }
        }
    }

    /** "" selects the default (opus). */
    public void setDefaultModel(String name) {
        defaultModel = Text.trim(name);
        if (defaultModel.isEmpty()) {
            defaultModel = DEFAULT_MODEL;
        }
    }

    /** What the menus offer: the catalog, then the extra models. */
    public List<String> menuModels() {
        List<String> out = new ArrayList<>();
        for (Models.ModelInfo m : Models.catalog()) {
            out.add(m.id());
        }
        out.addAll(models);
        if (!out.contains(defaultModel)) {
            out.add(defaultModel);
        }
        return out;
    }
}
