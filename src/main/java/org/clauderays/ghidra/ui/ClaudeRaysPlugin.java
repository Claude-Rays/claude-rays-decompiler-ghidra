package org.clauderays.ghidra.ui;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import org.clauderays.ghidra.api.ClaudeRaysService;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.Fixes;
import org.clauderays.ghidra.core.Log;
import org.clauderays.ghidra.core.Models;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;
import org.clauderays.ghidra.program.Cache;
import org.clauderays.ghidra.program.Collector;
import org.clauderays.ghidra.program.Decompilation;
import org.clauderays.ghidra.program.Names;
import org.clauderays.ghidra.program.PairDiff;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Claude-Rays Decompiler for Ghidra: decompile the current function
 * with Claude from its disassembly and Ghidra's C. The context is collected and the query
 * runs in a Ghidra task (its dialog has Cancel); the answer is validated,
 * cached in the program and shown in a view per function.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Claude-Rays Decompiler",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Decompile a function with Claude from its disassembly and Ghidra's C",
    description = "Claude-Rays Decompiler for Ghidra " + ClaudeRaysPlugin.VERSION + ": decompiles the current function with "
        + "Claude (Claude Code CLI) working from the disassembly and the C of Ghidra's decompiler, validates the answer against the listing and "
        + "caches it in the program. Also provides the API used by Diaphora-ng to diff the pseudo-code of two "
        + "versions of a function.",
    servicesRequired = {},
    servicesProvided = {ClaudeRaysService.class}
)
public class ClaudeRaysPlugin extends ProgramPlugin implements ClaudeRaysService {

    public static final String VERSION = "0.1.0-beta";
    private static final String AUTHOR = "ClaudeMonkey";
    private static final String REPO = "Claude-Rays/claude-rays-decompiler-ghidra";
    private static final String MENU = "Claude-Rays Decompiler";
    private static final String GROUP = "ClaudeRays";
    private static final String OPEN_VIEWS = "clauderays.open_views";

    private static final String[] LOGO_LINES = {
        "+----------------------------------------------------------------------+",
        "|  Claude-Rays Decompiler for Ghidra - Claude + listing + Ghidra's C   |",
        "+----------------------------------------------------------------------+",
    };

    /** A function and a command: each has its view, its query and its cached result. */
    private record Key(Address entry, Cache.Mode mode) {
    }

    /** The open views, per program, function and command. */
    private final Map<Program, Map<Key, CodeProvider>> views = new HashMap<>();
    /** The open patches (Generate patch), per program and function. */
    private final Map<Program, Map<Address, PatchProvider>> patches = new HashMap<>();
    /** The decompilations in progress, per program, function and command. */
    private final Map<Program, Map<Key, Decompilation>> requests = new HashMap<>();
    private final List<DockingAction> modelActions = new ArrayList<>();
    /** the findings colored in the listing by the result a running query replaces */
    private final Map<Program, Map<Key, List<Backend.Finding>>> replacedFindings = new HashMap<>();

    public ClaudeRaysPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        Settings.get().load(Preferences::getProperty);
        Log.setSinks(this::consoleInfo, this::consoleError);
        for (String line : LOGO_LINES) {
            Log.raw(line);
        }
        Log.raw(String.format("Claude-Rays Decompiler for Ghidra %s by %s (%s)", VERSION, AUTHOR, REPO));
        Settings s = Settings.get();
        Log.info("version %s loaded, default model: %s, models: %s, claude: %s", VERSION, s.defaultModel,
            s.modelsStr(), s.claudePath);
        Log.info("disclaimer: treat the output of this plugin as a hypothesis, not as the truth, "
            + "especially on hostile binaries");
        createActions();
    }

    @Override
    protected void dispose() {
        for (Map<Key, Decompilation> m : requests.values()) {
            for (Decompilation d : m.values()) {
                d.cancel();
            }
        }
        requests.clear();
        for (Map<Key, CodeProvider> m : views.values()) {
            for (CodeProvider v : m.values()) {
                tool.removeComponentProvider(v);
            }
        }
        views.clear();
        for (Map<Address, PatchProvider> m : patches.values()) {
            for (PatchProvider v : m.values()) {
                tool.removeComponentProvider(v);
            }
        }
        patches.clear();
        Log.setSinks(null, null);
        super.dispose();
    }

    private void consoleInfo(String msg) {
        ConsoleService c = tool.getService(ConsoleService.class);
        if (c != null) {
            c.println(msg);
        }
        Msg.info(this, msg);
    }

    private void consoleError(String msg) {
        ConsoleService c = tool.getService(ConsoleService.class);
        if (c != null) {
            c.printlnError(msg);
        }
        Msg.error(this, msg);
    }

    //--------------------------------------------------------------------------
    // actions
    //--------------------------------------------------------------------------
    private interface Body {
        void run(ActionContext context);
    }

    /** A popup action of the code views (listing, decompiler) and / or of our views. */
    private final class PopupAction extends DockingAction {
        private final java.util.function.Predicate<ActionContext> valid;
        private final Body body;

        PopupAction(String name, String[] path, String description, boolean inCode, boolean inView, Body body) {
            this(name, path, description, ctx -> (inView && ctx instanceof CodeProvider.Context)
                || (inCode && ctx instanceof ProgramLocationActionContext), body);
        }

        PopupAction(String name, String[] path, String description, java.util.function.Predicate<ActionContext> valid,
                    Body body) {
            super(name.replace('.', '_'), ClaudeRaysPlugin.this.getName());
            this.valid = valid;
            this.body = body;
            setPopupMenuData(new MenuData(path, null, GROUP));
            setDescription(description);
        }

        @Override
        public boolean isValidContext(ActionContext context) {
            return valid.test(context);
        }

        @Override
        public boolean isAddToPopup(ActionContext context) {
            return isValidContext(context);
        }

        @Override
        public void actionPerformed(ActionContext context) {
            try {
                body.run(context);
            }
            catch (Exception e) {
                Msg.showError(ClaudeRaysPlugin.this, null, MENU, "Claude-Rays Decompiler error: " + e.getMessage(), e);
            }
        }
    }

    private void addMainMenu(String name, String description, Body body, KeyBindingData keys) {
        // the popup actions have the same texts: another action name
        DockingAction a = new DockingAction("Main menu " + name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    body.run(context);
                }
                catch (Exception e) {
                    Msg.showError(ClaudeRaysPlugin.this, null, MENU, "Claude-Rays Decompiler error: " + e.getMessage(), e);
                }
            }
        };
        a.setMenuBarData(new MenuData(new String[]{MENU, name}, null, GROUP));
        a.setDescription(description);
        if (keys != null) {
            a.setKeyBindingData(keys);
        }
        tool.addAction(a);
    }

    private static String[] path(String... items) {
        String[] out = new String[items.length + 1];
        out[0] = MENU;
        System.arraycopy(items, 0, out, 1, items.length);
        return out;
    }

    private void createActions() {
        Settings s = Settings.get();
        // each command has its view and its cached result: one never shows or replaces the result of another
        PopupAction decompile = new PopupAction("Decompile", path("Decompile"),
            "Decompile the current function with Claude (" + s.defaultModel + "), or show its cached result",
            true, true, ctx -> decompile(targetFunction(ctx), Settings.get().defaultModel, true));
        decompile.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F5, InputEvent.CTRL_DOWN_MASK
            | InputEvent.SHIFT_DOWN_MASK));
        tool.addAction(decompile);
        PopupAction analyze = new PopupAction("Decompile and analyze", path("Decompile and analyze"),
            "Decompile the current function and review it for security bugs in the same query (" + s.defaultModel
                + "), or show its cached result", true, true,
            ctx -> decompile(targetFunction(ctx), Settings.get().defaultModel, Settings.get().context, true,
                Cache.Mode.ANALYZE));
        analyze.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F6, InputEvent.CTRL_DOWN_MASK
            | InputEvent.SHIFT_DOWN_MASK));
        tool.addAction(analyze);
        PopupAction patch = new PopupAction("Decompile, analyze and patch", path("Decompile, analyze and patch"),
            "Decompile and analyze the current function, then ask for the fixes of its confirmed and possible "
                + "findings (a second query) and show them side by side; or show its cached result (a cached "
                + "Decompile and analyze only needs the fixes)",
            true, true, ctx -> decompile(targetFunction(ctx), Settings.get().defaultModel, Settings.get().context, true,
                Cache.Mode.PATCH));
        patch.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F7, InputEvent.CTRL_DOWN_MASK
            | InputEvent.SHIFT_DOWN_MASK));
        tool.addAction(patch);
        tool.addAction(new PopupAction("Generate patch", path("Generate patch"),
            "Show the fixes of this function as a unified diff of its decompiled code (nothing is queried)",
            ctx -> ctx instanceof CodeProvider.Context vc && vc.view().patched(),
            ctx -> generatePatch(targetFunction(ctx))));
        tool.addAction(new PopupAction("Regenerate", path("Regenerate"),
            "Run the command of this view again with the default model, ignoring (and replacing) its cached "
                + "result; the results of the other commands stay", false, true,
            ctx -> decompile(targetFunction(ctx), Settings.get().defaultModel, Settings.get().context, false,
                viewMode(ctx))));
        for (String c : Settings.CONTEXTS) {
            String label = Settings.contextLabel(c);
            tool.addAction(new PopupAction("Decompile with context " + c, path("Decompile with context", label),
                "Decompile the current function with the default model from: " + label
                    + ", ignoring the cached result (in a view: its command again)", true, true,
                ctx -> decompile(targetFunction(ctx), Settings.get().defaultModel, c, false, viewMode(ctx))));
        }
        tool.addAction(new PopupAction("Clear security highlights", path("Clear security highlights"),
            "Remove the colors of the security findings of this function from the listing", true, true,
            ctx -> clearFindingColors(targetFunction(ctx))));
        tool.addAction(new PopupAction("Apply summary as function comment", path("Apply summary as function comment"),
            "Write the summary of the result as the function comment in the program", false, true,
            ctx -> applyComment(targetFunction(ctx), viewMode(ctx))));
        tool.addAction(new PopupAction("Copy code", path("Copy code"),
            "Copy the C code (of a patch: the patch) to the clipboard",
            ctx -> ctx instanceof CodeProvider.Context || ctx instanceof PatchProvider.Context, this::copyCode));
        tool.addAction(new PopupAction("Cancel", path("Cancel"),
            "Cancel the decompilation of this view (outside a view: every decompilation of this function)",
            true, true, ctx -> cancel(targetFunction(ctx), ctx instanceof CodeProvider.Context vc ? vc.view().mode
                : null)));
        tool.addAction(new PopupAction("Show collected context", path("Show collected context"),
            "Print the context that would be sent for the current function to the console (nothing is sent)",
            true, false, ctx -> showContext(targetFunction(ctx))));
        tool.addAction(new PopupAction("Settings", path("Settings"),
            "Claude path, models, effort, timeout, limits and verbose logging", true, true, ctx -> editSettings()));

        addMainMenu("Decompile the current function", "Decompile the function at the cursor with Claude",
            ctx -> decompile(currentFunction(), Settings.get().defaultModel, true), null);
        addMainMenu("Decompile and analyze the current function",
            "Decompile the function at the cursor with Claude and review it for security bugs",
            ctx -> decompile(currentFunction(), Settings.get().defaultModel, Settings.get().context, true,
                Cache.Mode.ANALYZE), null);
        addMainMenu("Decompile, analyze and patch the current function",
            "Decompile the function at the cursor with Claude, review it for security bugs and fix them",
            ctx -> decompile(currentFunction(), Settings.get().defaultModel, Settings.get().context, true,
                Cache.Mode.PATCH), null);
        addMainMenu("Show collected context", "Print the context that would be sent for the current function",
            ctx -> showContext(currentFunction()), null);
        addMainMenu("Settings", "Claude path, models, effort, timeout, limits and verbose logging",
            ctx -> editSettings(), null);
        createModelActions();
    }

    /** The other models: decompile again with a stronger (or cheaper) model. */
    private void createModelActions() {
        for (DockingAction a : modelActions) {
            tool.removeAction(a);
        }
        modelActions.clear();
        Settings s = Settings.get();
        for (String m : s.menuModels()) {
            if (m.equals(s.defaultModel)) {
                continue;
            }
            String label = Models.menuLabel(m);
            String desc = m + " (" + Models.description(m) + ")";
            PopupAction other = new PopupAction("Other model " + m, path("Other model", label),
                "Decompile the current function with " + desc + ", ignoring the cached result", true, false,
                ctx -> decompile(targetFunction(ctx), m, false));
            PopupAction regen = new PopupAction("Regenerate with other model " + m,
                path("Regenerate with other model", label),
                "Run the command of this view again with " + desc + ", ignoring its cached result", false, true,
                ctx -> decompile(targetFunction(ctx), m, Settings.get().context, false, viewMode(ctx)));
            modelActions.add(other);
            modelActions.add(regen);
            tool.addAction(other);
            tool.addAction(regen);
        }
    }

    private Function currentFunction() {
        if (currentProgram == null || currentLocation == null) {
            return null;
        }
        return currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
    }

    /** A regeneration from a view runs its command again (outside a view: Decompile). */
    private static Cache.Mode viewMode(ActionContext ctx) {
        return ctx instanceof CodeProvider.Context vc ? vc.view().mode : Cache.Mode.DECOMPILE;
    }

    private Function targetFunction(ActionContext ctx) {
        if (ctx instanceof CodeProvider.Context vc) {
            return vc.view().function();
        }
        if (ctx instanceof ProgramLocationActionContext pc) {
            Program p = pc.getProgram();
            ProgramLocation loc = pc.getLocation();
            Address a = loc != null ? loc.getAddress() : pc.getAddress();
            if (p != null && a != null) {
                return p.getFunctionManager().getFunctionContaining(a);
            }
        }
        return currentFunction();
    }

    //--------------------------------------------------------------------------
    // views
    //--------------------------------------------------------------------------
    private CodeProvider findView(Program p, Key key) {
        Map<Key, CodeProvider> m = views.get(p);
        return m != null ? m.get(key) : null;
    }

    /** The view of the function and command, created (and shown) if needed. */
    private CodeProvider view(Program p, Key key, boolean show) {
        CodeProvider v = findView(p, key);
        if (v == null) {
            v = new CodeProvider(this, p, key.entry(), key.mode());
            views.computeIfAbsent(p, k -> new LinkedHashMap<>()).put(key, v);
            tool.addComponentProvider(v, show);
            saveOpenViews(p);
        }
        else if (show) {
            tool.showComponentProvider(v, true);
            v.toFront();
        }
        return v;
    }

    void viewClosed(CodeProvider v) {
        Map<Key, CodeProvider> m = views.get(v.program);
        Key key = new Key(v.entry, v.mode);
        // a transient provider is removed from the tool by its closeComponent()
        if (m != null && m.get(key) == v) {
            m.remove(key);
            saveOpenViews(v.program);
        }
    }

    /**
     * The open views are saved with the program (its user data), as
     * "address/command", and reopened from the cache.
     */
    private void saveOpenViews(Program p) {
        if (p == null || p.isClosed()) {
            return;
        }
        Map<Key, CodeProvider> m = views.get(p);
        List<String> list = new ArrayList<>();
        if (m != null) {
            for (Key k : m.keySet()) {
                list.add(k.entry() + "/" + k.mode().key);
            }
        }
        try {
            ProgramUserData ud = p.getProgramUserData();
            int tx = ud.startTransaction();
            try {
                ud.setStringProperty(OPEN_VIEWS, String.join(",", list));
            }
            finally {
                ud.endTransaction(tx);
            }
        }
        catch (Exception e) {
            Log.debug("could not save the open views: %s", e);
        }
    }

    @Override
    protected void programOpened(Program p) {
        String saved;
        try {
            saved = p.getProgramUserData().getStringProperty(OPEN_VIEWS, "");
        }
        catch (Exception e) {
            return;
        }
        if (saved == null || saved.isBlank()) {
            return;
        }
        // nothing is queried: a function whose cached result is gone shows a note
        Swing.runLater(() -> {
            if (p.isClosed()) {
                return;
            }
            for (String s : saved.split(",")) {
                s = s.trim();
                int slash = s.lastIndexOf('/');
                Cache.Mode mode = slash >= 0 ? Cache.Mode.parse(s.substring(slash + 1)) : null;
                Address a = p.getAddressFactory().getAddress(slash >= 0 ? s.substring(0, slash) : s);
                Function f = a != null ? p.getFunctionManager().getFunctionAt(a) : null;
                if (f == null) {
                    continue;
                }
                if (mode == null) {
                    // saved by a version with one view per function: the command of its result
                    mode = savedMode(f);
                }
                CodeProvider v = view(p, new Key(a, mode), true);
                Cache.Entry e = new Cache.Entry();
                Cache.State st = Cache.loadOrDerive(f, mode, e);
                if (st != Cache.State.NONE) {
                    v.showResult(e, st);
                }
                else {
                    v.showStatus(List.of("Claude-Rays Decompiler: no cached result for this function (never "
                        + "finished, or its bytes changed).", "Claude-Rays Decompiler > Regenerate decompiles it."));
                }
            }
        });
    }

    /** The most complete command with a cached result for 'f' (Decompile if none). */
    private static Cache.Mode savedMode(Function f) {
        for (Cache.Mode m : new Cache.Mode[]{Cache.Mode.PATCH, Cache.Mode.ANALYZE}) {
            if (Cache.load(f, m, new Cache.Entry()) != Cache.State.NONE) {
                return m;
            }
        }
        return Cache.Mode.DECOMPILE;
    }

    void patchClosed(PatchProvider v) {
        Map<Address, PatchProvider> m = patches.get(v.program);
        if (m != null && m.get(v.entry) == v) {
            m.remove(v.entry);
        }
    }

    @Override
    protected void programClosed(Program p) {
        replacedFindings.remove(p);
        Map<Address, PatchProvider> pm = patches.remove(p);
        if (pm != null) {
            for (PatchProvider v : pm.values()) {
                tool.removeComponentProvider(v);
            }
        }
        Map<Key, Decompilation> r = requests.remove(p);
        if (r != null) {
            for (Decompilation d : r.values()) {
                d.cancel();
            }
        }
        Map<Key, CodeProvider> m = views.remove(p);
        if (m != null) {
            for (CodeProvider v : m.values()) {
                tool.removeComponentProvider(v);
            }
        }
    }

    /** Show the cached result of every open view again (after a display setting changed). */
    private void refreshViews() {
        for (Map<Key, CodeProvider> m : views.values()) {
            for (CodeProvider v : m.values()) {
                Function f = v.function();
                if (f == null || !v.hasResult()) {
                    continue;
                }
                Cache.Entry e = new Cache.Entry();
                Cache.State st = Cache.loadOrDerive(f, v.mode, e);
                if (st != Cache.State.NONE) {
                    v.showResult(e, st);
                }
            }
        }
    }

    void goTo(Program p, Address a) {
        GoToService gs = tool.getService(GoToService.class);
        if (gs != null) {
            gs.goTo(new ProgramLocation(p, a), p);
        }
    }

    /** Double click on a function in a view: its Decompile view, from the cache or with a new query. */
    void openFunction(Function f) {
        Swing.runLater(() -> decompile(f, Settings.get().defaultModel, true));
    }

    /** What a decompilation shows in the view of its function and command (called from the task thread). */
    private Decompilation.Listener listener(Cache.Mode mode) {
        return new Decompilation.Listener() {
            @Override
            public void status(Program p, Address entry, List<String> lines) {
                Swing.runLater(() -> {
                    if (!p.isClosed()) {
                        view(p, new Key(entry, mode), false).showStatus(lines);
                    }
                });
            }

            @Override
            public void result(Program p, Address entry, Cache.Entry e, Cache.State state) {
                Swing.runLater(() -> {
                    if (!p.isClosed()) {
                        showResult(p, new Key(entry, mode), e, state);
                    }
                });
            }
        };
    }

    private void showResult(Program p, Key key, Cache.Entry e, Cache.State state) {
        // a new result: the colors of the one it replaces go (those of the other
        // commands of the function stay), its own come
        Map<Key, List<Backend.Finding>> old = replacedFindings.get(p);
        List<Backend.Finding> gone = old != null ? old.remove(key) : null;
        if (gone != null) {
            colorFindings(p, gone, false);
            Function f = p.getFunctionManager().getFunctionAt(key.entry());
            if (f != null) {
                for (Cache.Mode m : Cache.Mode.values()) {
                    Cache.Entry other = new Cache.Entry();
                    if (m != key.mode() && Cache.load(f, m, other) != Cache.State.NONE) {
                        colorFindings(p, other.findings, true);
                    }
                }
            }
        }
        colorFindings(p, e.findings, true);
        view(p, key, true).showResult(e, state);
    }

    //--------------------------------------------------------------------------
    // the security findings in the listing
    //--------------------------------------------------------------------------
    /** Color (or clear) the instructions of the findings, the most severe color on each. */
    private void colorFindings(Program p, List<Backend.Finding> findings, boolean set) {
        // the service colors the current program of the tool
        ColorizingService cs = tool.getService(ColorizingService.class);
        if (cs == null || findings.isEmpty() || p.isClosed() || p != currentProgram) {
            return;
        }
        Map<Address, Integer> ranks = new LinkedHashMap<>();
        for (Backend.Finding x : findings) {
            for (String s : x.addresses()) {
                Address a = Names.parseAddress(p, s);
                if (a != null) {
                    ranks.merge(a, x.rank(), Math::min);
                }
            }
        }
        int tx = p.startTransaction(set ? "Claude-Rays Decompiler: color security findings"
            : "Claude-Rays Decompiler: clear security findings");
        boolean ok = false;
        try {
            for (Map.Entry<Address, Integer> r : ranks.entrySet()) {
                Instruction insn = p.getListing().getInstructionAt(r.getKey());
                Address end = insn != null ? insn.getMaxAddress() : r.getKey();
                if (set) {
                    // the listing has a light background in the default theme
                    cs.setBackgroundColor(r.getKey(), end, Highlighter.findingColor(r.getValue(), false));
                }
                else {
                    cs.clearBackgroundColor(r.getKey(), end);
                }
            }
            ok = true;
        }
        finally {
            p.endTransaction(tx, ok);
        }
    }

    private void clearFindingColors(Function f) {
        if (f == null) {
            Log.error("the cursor is not in a function");
            return;
        }
        // the findings of every command of the function
        List<Backend.Finding> all = new ArrayList<>();
        for (Cache.Mode m : Cache.Mode.values()) {
            Cache.Entry e = new Cache.Entry();
            if (Cache.load(f, m, e) != Cache.State.NONE) {
                all.addAll(e.findings);
            }
        }
        if (all.isEmpty()) {
            Log.info("%s has no security findings to clear", Names.functionName(f));
            return;
        }
        colorFindings(f.getProgram(), all, false);
        Log.info("security highlights of %s cleared from the listing", Names.functionName(f));
    }

    //--------------------------------------------------------------------------
    // commands
    //--------------------------------------------------------------------------
    private void decompile(Function f, String model, boolean useCache) {
        decompile(f, model, Settings.get().context, useCache, Cache.Mode.DECOMPILE);
    }

    /**
     * Run the command 'mode' on 'f', in its view and with its cached result:
     * the result of another command is never shown nor replaced. Decompile,
     * analyze and patch without a cached result of its own (or with one whose
     * fixes failed) reuses the cached Decompile and analyze: only the fixes are
     * queried.
     */
    private void decompile(Function f, String model, String context, boolean useCache, Cache.Mode mode) {
        if (f == null) {
            Log.error("the cursor is not in a function");
            tool.setStatusInfo("Claude-Rays Decompiler: the cursor is not in a function", true);
            return;
        }
        if (f.isExternal()) {
            Log.error("%s is an import: there is no code to decompile", Names.functionName(f));
            return;
        }
        Program p = f.getProgram();
        Address entry = f.getEntryPoint();
        String name = Names.functionName(f);
        Key key = new Key(entry, mode);
        Map<Key, Decompilation> running = requests.computeIfAbsent(p, k -> new HashMap<>());
        if (running.containsKey(key)) {
            Log.info("%s is already being decompiled by %s (Claude-Rays Decompiler > Cancel to stop it)", name,
                mode.label);
            view(p, key, true);
            return;
        }
        Cache.Entry cached = new Cache.Entry();
        // with the cache, a result of a more complete command does too
        Cache.State cachedState = useCache ? Cache.loadOrDerive(f, mode, cached) : Cache.load(f, mode, cached);
        // the findings colored by the result this query replaces (a result taken from another is not replaced)
        List<Backend.Finding> replaced = cachedState != Cache.State.NONE && cached.derivedFrom == null
            ? cached.findings : List.of();
        // only the fixes are missing (a cached analysis with nothing to fix needs none)
        boolean fixOnly = false;
        if (useCache) {
            boolean needFixes = mode == Cache.Mode.PATCH && cached.fix == null
                && !Fixes.wantedNumbers(cached.findings).isEmpty();
            if (cachedState != Cache.State.NONE && !needFixes) {
                Log.info("%s: cached result of %s (%s, %s)%s%s", name, mode.label, cached.modelUsed(), cached.date,
                    cached.derivedFrom != null ? ", taken from " + cached.derivedFrom.label + ": nothing queried" : "",
                    cachedState == Cache.State.STALE ? ", stale: the callee names changed" : "");
                if (mode == Cache.Mode.PATCH && cached.fix == null) {
                    Log.info("%s: no confirmed or possible finding, nothing to fix", name);
                }
                view(p, key, true).showResult(cached, cachedState);
                return;
            }
            fixOnly = cachedState != Cache.State.NONE;
            if (!fixOnly && mode == Cache.Mode.PATCH) {
                Cache.Entry a = new Cache.Entry();
                Cache.State ast = Cache.load(f, Cache.Mode.ANALYZE, a);
                if (ast != Cache.State.NONE) {
                    Log.info("%s: the cached result of Decompile and analyze (%s, %s) is fixed", name,
                        a.modelUsed(), a.date);
                    cached = a;
                    cachedState = ast;
                    fixOnly = true;
                }
            }
        }
        Decompilation d = new Decompilation(f, model, context, mode != Cache.Mode.DECOMPILE,
            mode == Cache.Mode.PATCH, listener(mode));
        running.put(key, d);
        replacedFindings.computeIfAbsent(p, k -> new HashMap<>()).remove(key);
        if (!replaced.isEmpty()) {
            replacedFindings.get(p).put(key, new ArrayList<>(replaced));
        }
        view(p, key, true).showStatus(List.of(fixOnly
            ? "Claude-Rays Decompiler: the cached analysis of " + name + " is being fixed..."
            : "Claude-Rays Decompiler: collecting the context of " + name + "..."));
        boolean onlyFixes = fixOnly;
        Cache.Entry base = cached;
        Cache.State baseState = cachedState;
        Task task = new Task("Claude-Rays Decompiler: " + name + " (" + d.modelText() + ")", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    if (onlyFixes) {
                        d.runFix(base, baseState, monitor);
                    }
                    else {
                        d.run(monitor);
                    }
                }
                finally {
                    Swing.runLater(() -> {
                        Map<Key, Decompilation> m = requests.get(p);
                        if (m != null && m.get(key) == d) {
                            m.remove(key);
                        }
                    });
                }
            }
        };
        new TaskLauncher(task, tool.getToolFrame(), 0);
    }

    /** Cancel the decompilation of 'mode' (null: of every command) of the function. */
    private void cancel(Function f, Cache.Mode mode) {
        Map<Key, Decompilation> m = f != null ? requests.get(f.getProgram()) : null;
        boolean any = false;
        for (Cache.Mode x : Cache.Mode.values()) {
            Decompilation d = m != null && (mode == null || mode == x) ? m.get(new Key(f.getEntryPoint(), x)) : null;
            if (d != null) {
                d.cancel();
                any = true;
                Log.info("cancelling %s of %s", x.label, d.funcName);
            }
        }
        if (!any) {
            Log.info("nothing to cancel");
        }
    }

    /** The fixes of the function as a unified diff, in its patch view. */
    private void generatePatch(Function f) {
        Cache.Entry e = new Cache.Entry();
        if (f == null || Cache.load(f, Cache.Mode.PATCH, e) == Cache.State.NONE || e.fix == null
            || !e.fix.hasEdits()) {
            Log.info("there is no fix to make a patch of (Claude-Rays Decompiler > Decompile, analyze and patch)");
            return;
        }
        Program p = f.getProgram();
        Address entry = f.getEntryPoint();
        String name = Names.functionName(f);
        List<String> lines = Fixes.patch(name, Names.hex(entry), e.code, e.findings, e.fix);
        PatchProvider v = patches.computeIfAbsent(p, k -> new HashMap<>()).get(entry);
        if (v == null) {
            v = new PatchProvider(this, p, entry);
            patches.get(p).put(entry, v);
            tool.addComponentProvider(v, true);
        }
        else {
            tool.showComponentProvider(v, true);
            v.toFront();
        }
        v.show(name, lines);
    }

    private void copyCode(ActionContext ctx) {
        if (ctx instanceof PatchProvider.Context pc) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(pc.view().text()), null);
            Log.info("patch copied to the clipboard");
            return;
        }
        if (!(ctx instanceof CodeProvider.Context vc) || vc.view().code().isEmpty()) {
            Log.info("there is no code to copy yet");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(vc.view().code()), null);
        Log.info("code copied to the clipboard");
    }

    /** The summary of the result, as the regular function comment (undoable). */
    private void applyComment(Function f, Cache.Mode mode) {
        if (f == null) {
            Log.error("the view is not on a function");
            return;
        }
        Cache.Entry e = new Cache.Entry();
        if (Cache.loadOrDerive(f, mode, e) == Cache.State.NONE || Text.trim(e.summary).isEmpty()) {
            Log.info("there is no summary to apply (Claude-Rays Decompiler > Regenerate makes one)");
            return;
        }
        String summary = Text.trim(e.summary);
        String old = f.getComment();
        if (old != null && !Text.trim(old).isEmpty() && !Text.trim(old).equals(summary)
            && OptionDialog.showYesNoDialog(tool.getToolFrame(), MENU, "The function already has a comment:\n\n"
                + Text.oneLine(old, 400) + "\n\nReplace it with the summary of Claude-Rays Decompiler?")
            != OptionDialog.YES_OPTION) {
            return;
        }
        Program p = f.getProgram();
        int tx = p.startTransaction("Claude-Rays Decompiler: apply summary as function comment");
        boolean ok = false;
        try {
            f.setComment(summary);
            ok = true;
        }
        finally {
            p.endTransaction(tx, ok);
        }
        Log.info("summary applied as the comment of %s", Names.hex(f.getEntryPoint()));
    }

    /** What the collector extracts, without sending it. */
    private void showContext(Function f) {
        if (f == null) {
            Log.error("the cursor is not in a function");
            return;
        }
        Task task = new Task("Claude-Rays Decompiler: collecting the context", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                Collector.Collected col = new Collector(f.getProgram(), monitor).collect(f, 0);
                if (!col.error.isEmpty()) {
                    Log.error("%s", col.error);
                    return;
                }
                Log.info("collected context of %s (%s, %d chars, about %d tokens):", Names.hex(f.getEntryPoint()),
                    Settings.contextLabel(col.context), col.text.length(), col.text.length() / 4);
                if (!col.ghidraNote.isEmpty()) {
                    Log.info("%s", col.ghidraNote);
                }
                for (String line : Text.splitLines(col.text)) {
                    Log.raw(line);
                }
                for (var sz : col.sizes) {
                    Log.info("section %-36s %6d chars", sz.title(), sz.chars());
                }
            }
        };
        new TaskLauncher(task, tool.getToolFrame(), 0);
    }

    private void editSettings() {
        tool.showDialog(new SettingsDialog(this));
    }

    void settingsChanged(boolean menusChanged, boolean annotationsChanged) {
        Settings s = Settings.get();
        s.save(Preferences::setProperty);
        Preferences.store();
        if (annotationsChanged) {
            refreshViews();
        }
        if (menusChanged) {
            createModelActions();
        }
        Log.info("settings saved: claude=%s default model=%s extra models=%s effort=%s timeout=%d max insns=%d "
            + "budget=%d", s.claudePath, s.defaultModel, s.modelsStr(), s.effort, s.timeout, s.maxInsns, s.budget);
    }

    //--------------------------------------------------------------------------
    // ClaudeRaysService (Diaphora-ng)
    //--------------------------------------------------------------------------
    @Override
    public int apiVersion() {
        return API_VERSION;
    }

    @Override
    public String diffFunctions(String requestJson) {
        Program p = currentProgram;
        if (!Swing.isSwingThread()) {
            return PairDiff.diffFunctions(p, requestJson, TaskMonitor.DUMMY);
        }
        String[] out = new String[1];
        Task task = new Task("Claude-Rays Decompiler: Claude diff", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                out[0] = PairDiff.diffFunctions(p, requestJson, monitor);
            }
        };
        // a modal task: blocks until it is over
        new TaskLauncher(task, tool.getToolFrame(), 0);
        return out[0] != null ? out[0] : "{\"ok\":false,\"error\":\"cancelled\"}";
    }

    @Override
    public String diffFunctions(Program program, String requestJson, TaskMonitor monitor) {
        return PairDiff.diffFunctions(program, requestJson, monitor);
    }
}
