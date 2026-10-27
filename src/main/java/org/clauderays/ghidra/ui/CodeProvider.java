package org.clauderays.ghidra.ui;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.WindowPosition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import org.clauderays.ghidra.core.Backend;
import org.clauderays.ghidra.core.CodeNav;
import org.clauderays.ghidra.core.CodeShaper;
import org.clauderays.ghidra.core.Fixes;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;
import org.clauderays.ghidra.program.Cache;
import org.clauderays.ghidra.program.Names;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.JViewport;
import javax.swing.ToolTipManager;
import javax.swing.text.JTextComponent;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Point;
import java.awt.Shape;
import java.awt.geom.Rectangle2D;
import java.awt.event.InputEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The code view of one function and command: "Claude-Rays
 * Decompiler: <function> (<command>)", one per command, read only, with the C code colored by a simple highlighter. Double click on
 * another function opens its view (decompiling it if needed; Shift+double
 * click: the listing), on any other name jumps to it, on any other place of a
 * line to the address of its annotation (or of the closest line above).
 *
 * A result with fixes (Decompile, analyze and patch) is shown side by side:
 * the decompiled code with its findings on the left, the fixed code on the
 * right, row by row, with the number of the finding of each change in the
 * margin of both sides.
 */
public final class CodeProvider extends ComponentProvider {

    static final String TITLE_PREFIX = "Claude-Rays Decompiler: ";
    /** the header notes of the side by side view are cut to this width (its panes do not wrap) */
    private static final int NOTE_WIDTH = 110;

    /** The action context of the view. */
    public static final class Context extends DefaultActionContext {
        Context(CodeProvider p) {
            super(p, p.main.pane);
        }

        public CodeProvider view() {
            return (CodeProvider) getComponentProvider();
        }
    }

    /** One text pane of the view, with what each of its lines is. */
    private final class Side {
        /** the long lines wrap, except side by side, where the rows must stay aligned */
        boolean wrap = true;
        final JTextPane pane = new JTextPane() {
            @Override
            public String getToolTipText(MouseEvent e) {
                int[] lc = lineColumn(Side.this, e);
                return lc != null ? lineTips.get(lc[0]) : null;
            }

            @Override
            public boolean getScrollableTracksViewportWidth() {
                return wrap ? super.getScrollableTracksViewportWidth()
                    : getParent() == null || getUI().getPreferredSize(this).width <= getParent().getWidth();
            }
        };
        final JScrollPane scroll = new JScrollPane(pane);
        /** the text of each line, as shown */
        final List<String> lines = new ArrayList<>();
        /** the address of each line (its first annotation, NO_ADDRESS if none) */
        final List<Long> lineAddrs = new ArrayList<>();
        /** the tooltip of the lines of a security finding or of a fix */
        final Map<Integer, String> lineTips = new HashMap<>();

        Side() {
            pane.setEditable(false);
            pane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
            ToolTipManager.sharedInstance().registerComponent(pane);
            pane.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                        doubleClick(Side.this, e);
                    }
                }
            });
        }
    }

    private final ClaudeRaysPlugin plugin;
    final Program program;
    final Address entry;
    /** the command of the view: each has its own view of the function, and its cached result */
    final Cache.Mode mode;
    private final Side main = new Side();
    /** the fixed code, shown beside 'main' */
    private final Side fixed = new Side();
    private final JPanel root = new JPanel(new BorderLayout());
    private final JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    private boolean sideBySide;
    private boolean syncing;
    /** plain code as shown, for Copy code */
    private String code = "";
    /**
     * what the function refers to, by every name the code may use for it
     * (qualified, without templates, last component; no spaces); null marks a
     * name shared by several addresses
     */
    private final Map<String, Address> names = new HashMap<>();
    private final Set<String> ambiguous = new LinkedHashSet<>();

    CodeProvider(ClaudeRaysPlugin plugin, Program program, Address entry, Cache.Mode mode) {
        super(plugin.getTool(), "Claude-Rays Decompiler", plugin.getName(), Context.class);
        this.plugin = plugin;
        this.program = program;
        this.entry = entry;
        this.mode = mode;
        setTransient();
        setDefaultWindowPosition(WindowPosition.RIGHT);
        setWindowMenuGroup("Claude-Rays Decompiler");
        setTitles();
        root.add(main.scroll, BorderLayout.CENTER);
        split.setResizeWeight(0.5);
        split.setContinuousLayout(true);
        // side by side, both panes scroll together
        syncScroll(main.scroll.getViewport(), fixed.scroll.getViewport());
        syncScroll(fixed.scroll.getViewport(), main.scroll.getViewport());
        collectNames();
    }

    private void syncScroll(JViewport from, JViewport to) {
        from.addChangeListener(ev -> {
            if (!sideBySide || syncing) {
                return;
            }
            syncing = true;
            try {
                Point p = to.getViewPosition();
                to.setViewPosition(new Point(p.x, from.getViewPosition().y));
            }
            finally {
                syncing = false;
            }
        });
    }

    /** One pane, or the two side by side. */
    private void setLayout(boolean twoSides) {
        main.wrap = !twoSides;
        fixed.wrap = !twoSides;
        if (twoSides == sideBySide) {
            return;
        }
        sideBySide = twoSides;
        root.removeAll();
        if (twoSides) {
            split.setLeftComponent(main.scroll);
            split.setRightComponent(fixed.scroll);
            root.add(split, BorderLayout.CENTER);
            split.setDividerLocation(0.5);
        }
        else {
            root.add(main.scroll, BorderLayout.CENTER);
        }
        root.revalidate();
        root.repaint();
    }

    private String functionTitle() {
        Function f = function();
        return f != null ? Names.functionName(f) : Names.hex(entry);
    }

    Function function() {
        return program.isClosed() ? null : program.getFunctionManager().getFunctionAt(entry);
    }

    @Override
    public JComponent getComponent() {
        return root;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return new Context(this);
    }

    @Override
    public void closeComponent() {
        super.closeComponent();
        plugin.viewClosed(this);
    }

    /** The code shown (without the header), "" if none. */
    String code() {
        return code;
    }

    boolean hasResult() {
        return !code.isEmpty();
    }

    /** The result shown has fixes with edits: the view is side by side. */
    boolean patched() {
        return sideBySide;
    }

    private boolean dark() {
        return Highlighter.isDark(main.pane.getBackground());
    }

    //--------------------------------------------------------------------------
    // content
    //--------------------------------------------------------------------------
    /** The lines of a side, each with its address and with the background of some of them. */
    private void setContent(Side side, List<Highlighter.Span[]> content, List<Long> addrs, Map<Integer, Color> backs) {
        side.lines.clear();
        side.lineAddrs.clear();
        side.pane.getHighlighter().removeAllHighlights();
        StyledDocument doc = side.pane.getStyledDocument();
        boolean dark = Highlighter.isDark(side.pane.getBackground());
        try {
            doc.remove(0, doc.getLength());
            for (int i = 0; i < content.size(); i++) {
                StringBuilder text = new StringBuilder();
                for (Highlighter.Span sp : content.get(i)) {
                    SimpleAttributeSet a = new SimpleAttributeSet();
                    Color c = Highlighter.color(sp.kind(), dark);
                    if (c != null) {
                        StyleConstants.setForeground(a, c);
                    }
                    if (sp.kind() == Highlighter.Kind.KEYWORD || sp.kind() == Highlighter.Kind.MARKER) {
                        StyleConstants.setBold(a, true);
                    }
                    doc.insertString(doc.getLength(), sp.text(), a);
                    text.append(sp.text());
                }
                if (i + 1 < content.size()) {
                    doc.insertString(doc.getLength(), "\n", null);
                }
                side.lines.add(text.toString());
                side.lineAddrs.add(i < addrs.size() ? addrs.get(i) : CodeShaper.NO_ADDRESS);
            }
        }
        catch (BadLocationException e) {
            // cannot happen: always at the end
        }
        Element root = doc.getDefaultRootElement();
        for (Map.Entry<Integer, Color> r : backs.entrySet()) {
            if (r.getKey() < root.getElementCount()) {
                int start = root.getElement(r.getKey()).getStartOffset();
                try {
                    side.pane.getHighlighter().addHighlight(start, start, new LinePainter(r.getValue()));
                }
                catch (BadLocationException e) {
                    // the line exists
                }
            }
        }
        side.pane.setCaretPosition(0);
    }

    /** "Claude-Rays Decompiler: main (Decompile and analyze)", tab "main [analyze]" */
    private void setTitles() {
        setTitle(TITLE_PREFIX + functionTitle() + " (" + mode.label + ")");
        setTabText(functionTitle() + " [" + mode.key + "]");
    }

    private static Highlighter.Span[] note(Highlighter.Kind k, String text) {
        return new Highlighter.Span[]{new Highlighter.Span("// " + CodeShaper.cleanLine(text), k)};
    }

    /** A status message, e.g. while the query runs. */
    void showStatus(List<String> status) {
        main.lineTips.clear();
        setLayout(false);
        List<Highlighter.Span[]> content = new ArrayList<>();
        for (String s : status) {
            for (String l : Text.splitLines(s)) {
                content.add(note(Highlighter.Kind.NOTE, l));
            }
        }
        setContent(main, content, List.of(), Map.of());
        code = "";
        setTitles();
    }

    /** The header lines of a side, with the background of some of them. */
    private static final class Header {
        final List<Highlighter.Span[]> content = new ArrayList<>();
        final Map<Integer, Color> backs = new HashMap<>();
        /** 0: the pane wraps the long lines */
        final int width;

        Header(int width) {
            this.width = width;
        }

        void add(Highlighter.Kind k, String text) {
            add(k, text, null);
        }

        void add(Highlighter.Kind k, String text, Color back) {
            for (String l : Text.splitLines(text)) {
                for (String w : width > 0 ? Text.wrap(l, width) : List.of(l)) {
                    if (back != null) {
                        backs.put(content.size(), back);
                    }
                    content.add(note(k, w));
                }
            }
        }
    }

    /** The notes of a result: model, usage, validation, findings (and the fixes that could not be made). */
    private void header(Header h, Cache.Entry e, Cache.State state, boolean dark) {
        String from = switch (Settings.contextOf(e.context)) {
            case Settings.CONTEXT_BOTH -> "from the disassembly and the C of Ghidra's decompiler";
            case Settings.CONTEXT_GHIDRA -> "from the C of Ghidra's decompiler and the plain disassembly";
            default -> "from the disassembly";
        };
        h.add(Highlighter.Kind.NOTE, String.format("Claude-Rays Decompiler: C reconstructed by Claude (%s, %s) "
            + "%s. Plausible, not proven: check it against the listing.", e.modelUsed(), e.date, from));
        if (e.derivedFrom != null) {
            h.add(Highlighter.Kind.NOTE, "Taken from the cached result of " + e.derivedFrom.label
                + ": nothing was queried (Claude-Rays Decompiler > Regenerate makes one of its own).");
        }
        if (e.inputTokens > 0 || e.outputTokens > 0) {
            h.add(Highlighter.Kind.NOTE, String.format("Usage: %d input / %d output tokens, $%.4f at API prices "
                + "(on a subscription it counts against the plan usage).", e.inputTokens, e.outputTokens, e.costUsd));
        }
        if (!e.contextNote.isEmpty()) {
            h.add(Highlighter.Kind.NOTE, e.contextNote + ": made from the listing alone.");
        }
        if (e.rounds > 0) {
            h.add(Highlighter.Kind.NOTE, String.format("Context asked by the model: %d extra round(s).", e.rounds));
        }
        if (e.safetyStops > 0) {
            h.add(Highlighter.Kind.UNCERTAIN, "SAFETY STOP: " + Backend.safetyNote(e.safetyStops, e.models));
        }
        if (state == Cache.State.STALE) {
            h.add(Highlighter.Kind.ERROR, "STALE: the names of the called functions changed since this was "
                + "generated (Claude-Rays Decompiler > Regenerate).");
        }
        for (String w : e.warnings) {
            h.add(Highlighter.Kind.ERROR, "WARNING: " + w);
        }
        for (Backend.Uncertain u : e.uncertain) {
            h.add(Highlighter.Kind.UNCERTAIN, "UNCERTAIN " + u.address() + ": " + u.reason());
        }
        for (String m : e.missing) {
            h.add(Highlighter.Kind.ERROR, "CONTEXT NOT GIVEN: " + m);
        }
        if (e.analyzed) {
            h.add(Highlighter.Kind.NOTE, String.format("SECURITY ANALYSIS of this function alone: %d finding(s). "
                + "Red: confirmed in the code; orange: possible, needs the precondition; yellow: theoretical.",
                e.findings.size()));
            for (int i = 0; i < e.findings.size(); i++) {
                Backend.Finding x = e.findings.get(i);
                h.add(Highlighter.Kind.NOTE, findingText(i + 1, x), Highlighter.findingColor(x.rank(), dark));
            }
        }
        if (e.fix != null && !e.fix.hasEdits()) {
            h.add(Highlighter.Kind.NOTE, String.format("FIXES (%s, %s): none of the findings could be fixed in this "
                + "function.", e.fix.modelUsed(), e.fix.date));
            fixNotes(h, e, dark);
        }
    }

    /** What became of the fix of each finding. */
    private static void fixNotes(Header h, Cache.Entry e, boolean dark) {
        if (e.fix.safetyStops > 0) {
            h.add(Highlighter.Kind.UNCERTAIN, "SAFETY STOP (fixes): "
                + Backend.safetyNote(e.fix.safetyStops, e.fix.models));
        }
        for (String w : e.fix.warnings) {
            h.add(Highlighter.Kind.ERROR, "WARNING: " + w);
        }
        for (int n = 1; n <= e.findings.size(); n++) {
            Backend.Finding x = e.findings.get(n - 1);
            Fixes.Fix fx = e.fix.fixOf(n);
            if (fx == null) {
                h.add(Highlighter.Kind.NOTE, "F" + n + " not fixed: " + x.level() + " finding.");
            }
            else if (!fx.edits().isEmpty()) {
                h.add(Highlighter.Kind.NOTE, "F" + n + " FIXED: " + fx.note(), Highlighter.fixColor(x.rank(), dark));
            }
            else if (fx.fixable()) {
                h.add(Highlighter.Kind.NOTE, "F" + n + " no edits (covered by another fix, or nothing to change): " + fx.note());
            }
            else {
                h.add(Highlighter.Kind.UNCERTAIN, "F" + n + " NOT FIXABLE in this function: " + fx.note());
            }
        }
    }

    /** A result: header notes, summary and code; side by side with its fixes when it has some. */
    void showResult(Cache.Entry e, Cache.State state) {
        main.lineTips.clear();
        fixed.lineTips.clear();
        if (e.fix != null && e.fix.hasEdits()) {
            showPatched(e, state);
            return;
        }
        setLayout(false);
        boolean dark = dark();
        Header h = new Header(0);
        header(h, e, state, dark);
        List<Highlighter.Span[]> content = h.content;
        Map<Integer, Color> backs = new HashMap<>(h.backs);
        content.add(new Highlighter.Span[0]);
        List<Long> addrs = new ArrayList<>();
        for (int i = 0; i < content.size(); i++) {
            addrs.add(CodeShaper.NO_ADDRESS);
        }

        // the header comment written by the model, before the code
        String full = CodeShaper.summaryComment(e.summary) + e.code;
        CodeShaper.Shaped shaped = CodeShaper.shape(full, Settings.get().showAnnotations);
        Highlighter hl = new Highlighter(program);
        StringBuilder shown = new StringBuilder();
        int codeStart = content.size();
        for (int i = 0; i < shaped.lines.size(); i++) {
            String l = CodeShaper.cleanLine(shaped.lines.get(i));
            content.add(hl.line(l).toArray(new Highlighter.Span[0]));
            addrs.add(shaped.addresses.get(i));
            shown.append(shaped.lines.get(i)).append('\n');
        }
        if (e.analyzed) {
            Marks m = markFindings(e.findings, shaped.addresses);
            for (Map.Entry<Integer, Integer> r : m.ranks.entrySet()) {
                backs.put(codeStart + r.getKey(), Highlighter.findingColor(r.getValue(), dark));
            }
            for (Map.Entry<Integer, List<String>> t : m.tips.entrySet()) {
                main.lineTips.put(codeStart + t.getKey(), tip(t.getValue()));
            }
        }
        setContent(main, content, addrs, backs);
        code = shown.toString();
        setTitles();
    }

    /** "F1" or "F1,3": the findings of a line, for the margin. */
    private static String label(Set<Integer> numbers) {
        if (numbers == null || numbers.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder("F");
        for (int n : numbers) {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append(n);
        }
        return sb.toString();
    }

    private static Highlighter.Span[] withMargin(String label, int width, List<Highlighter.Span> line) {
        List<Highlighter.Span> out = new ArrayList<>();
        out.add(new Highlighter.Span(Text.pad(label, width), Highlighter.Kind.MARKER));
        out.addAll(line);
        return out.toArray(new Highlighter.Span[0]);
    }

    /**
     * Side by side: the decompiled code on the left as the analysis shows it,
     * the fixed code on the right, aligned row by row (blank rows fill the
     * side with fewer lines); the changed rows have the number of their
     * finding in the margin of both sides and, on the right, the green of the
     * severity of the finding.
     */
    private void showPatched(Cache.Entry e, Cache.State state) {
        setLayout(true);
        boolean dark = dark();
        Header left = new Header(NOTE_WIDTH);
        header(left, e, state, dark);
        Header right = new Header(NOTE_WIDTH);
        right.add(Highlighter.Kind.NOTE, String.format("Claude-Rays Decompiler: fixes suggested by Claude (%s, %s) for "
            + "the findings: a patch of the decompiled C, not of the binary. Plausible, not proven.",
            e.fix.modelUsed(), e.fix.date));
        if (e.fix.inputTokens > 0 || e.fix.outputTokens > 0) {
            right.add(Highlighter.Kind.NOTE, String.format("Usage of the fixes: %d input / %d output tokens, $%.4f at "
                + "API prices.", e.fix.inputTokens, e.fix.outputTokens, e.fix.costUsd));
        }
        right.add(Highlighter.Kind.NOTE, "Green: the lines of each fix, darker the more severe its finding; F<n> in "
            + "the margin pairs them with the finding on the left. Claude-Rays Decompiler > Generate patch makes a "
            + "unified diff.");
        fixNotes(right, e, dark);

        // both headers as high as the highest one, then a blank row
        int headerRows = Math.max(left.content.size(), right.content.size()) + 1;
        for (Header h : List.of(left, right)) {
            while (h.content.size() < headerRows) {
                h.content.add(new Highlighter.Span[0]);
            }
        }
        List<Long> leftAddrs = new ArrayList<>();
        List<Long> rightAddrs = new ArrayList<>();
        for (int i = 0; i < headerRows; i++) {
            leftAddrs.add(CodeShaper.NO_ADDRESS);
            rightAddrs.add(CodeShaper.NO_ADDRESS);
        }

        List<String> summary = Text.splitLines(CodeShaper.summaryComment(e.summary));
        int nSummary = summary.size();
        List<String> codeLines = Text.splitLines(e.code);
        List<Fixes.Edit> edits = e.fix.edits();
        List<String> patchedLines = Fixes.apply(codeLines, edits);
        boolean keep = Settings.get().showAnnotations;
        List<String> leftLines = new ArrayList<>(summary);
        leftLines.addAll(codeLines);
        List<String> rightLines = new ArrayList<>(summary);
        rightLines.addAll(patchedLines);
        CodeShaper.Shaped sl = CodeShaper.shapeLines(leftLines, keep);
        CodeShaper.Shaped sr = CodeShaper.shapeLines(rightLines, keep);
        // the summary rows, then the rows of the code
        List<Fixes.Row> rows = new ArrayList<>();
        for (int i = 0; i < nSummary; i++) {
            rows.add(new Fixes.Row(i, i, 0));
        }
        for (Fixes.Row r : Fixes.rows(codeLines.size(), edits)) {
            rows.add(new Fixes.Row(r.left() >= 0 ? nSummary + r.left() : -1,
                r.right() >= 0 ? nSummary + r.right() : -1, r.finding()));
        }

        // the findings of the left lines (by address), and the margin of every row
        Marks m = markFindings(e.findings, sl.addresses);
        List<Set<Integer>> leftNums = new ArrayList<>();
        int width = 4;
        for (Fixes.Row r : rows) {
            Set<Integer> nums = new TreeSet<>();
            if (r.left() >= 0 && m.numbers.containsKey(r.left())) {
                nums.addAll(m.numbers.get(r.left()));
            }
            if (r.changed()) {
                nums.add(r.finding());
            }
            leftNums.add(nums);
            width = Math.max(width, label(nums).length() + 1);
        }

        Highlighter hl = new Highlighter(program);
        Highlighter hr = new Highlighter(program);
        StringBuilder shown = new StringBuilder();
        for (int k = 0; k < rows.size(); k++) {
            Fixes.Row r = rows.get(k);
            int row = headerRows + k;
            if (r.left() >= 0) {
                String l = CodeShaper.cleanLine(sl.lines.get(r.left()));
                left.content.add(withMargin(label(leftNums.get(k)), width, hl.line(l)));
                leftAddrs.add(sl.addresses.get(r.left()));
                shown.append(sl.lines.get(r.left())).append('\n');
                if (m.ranks.containsKey(r.left())) {
                    left.backs.put(row, Highlighter.findingColor(m.ranks.get(r.left()), dark));
                }
                List<String> tips = new ArrayList<>(m.tips.getOrDefault(r.left(), List.of()));
                if (r.changed()) {
                    tips.add("Changed by the fix of F" + r.finding() + ": " + fixNote(e, r.finding()));
                }
                if (!tips.isEmpty()) {
                    main.lineTips.put(row, tip(tips));
                }
            }
            else {
                left.content.add(new Highlighter.Span[0]);
                leftAddrs.add(CodeShaper.NO_ADDRESS);
            }
            if (r.right() >= 0) {
                String l = CodeShaper.cleanLine(sr.lines.get(r.right()));
                right.content.add(withMargin(r.changed() ? "F" + r.finding() : "", width, hr.line(l)));
                rightAddrs.add(sr.addresses.get(r.right()));
                if (r.changed()) {
                    Backend.Finding x = e.findings.get(r.finding() - 1);
                    right.backs.put(row, Highlighter.fixColor(x.rank(), dark));
                    fixed.lineTips.put(row, tip(List.of(findingText(r.finding(), x),
                        "FIX: " + fixNote(e, r.finding()))));
                }
            }
            else {
                right.content.add(new Highlighter.Span[0]);
                rightAddrs.add(CodeShaper.NO_ADDRESS);
            }
        }
        setContent(main, left.content, leftAddrs, left.backs);
        setContent(fixed, right.content, rightAddrs, right.backs);
        code = shown.toString();
        setTitles();
    }

    private static String fixNote(Cache.Entry e, int finding) {
        Fixes.Fix fx = e.fix.fixOf(finding);
        return fx != null ? fx.note() : "";
    }

    /** "F1 CONFIRMED stack buffer overflow at 0x401020: ... Precondition: ..." */
    static String findingText(int number, Backend.Finding x) {
        return "F" + number + " " + x.text();
    }

    private static String tip(List<String> texts) {
        List<String> esc = new ArrayList<>();
        for (String x : texts) {
            esc.add(x.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"));
        }
        return "<html>" + String.join("<br>", esc) + "</html>";
    }

    /** The lines of the findings: the most severe rank, the finding numbers and their texts, by line. */
    private record Marks(Map<Integer, Integer> ranks, Map<Integer, Set<Integer>> numbers,
                         Map<Integer, List<String>> tips) {
    }

    /**
     * The code lines of each finding: the statement that holds each of its
     * instructions is the line annotated with that address, or else with the
     * closest address below it (a statement starts at its first instruction).
     */
    private static Marks markFindings(List<Backend.Finding> findings, List<Long> codeAddrs) {
        Marks out = new Marks(new HashMap<>(), new HashMap<>(), new HashMap<>());
        TreeMap<Long, List<Integer>> byAddr = new TreeMap<>();
        for (int i = 0; i < codeAddrs.size(); i++) {
            long a = codeAddrs.get(i);
            if (a != CodeShaper.NO_ADDRESS) {
                byAddr.computeIfAbsent(a, k -> new ArrayList<>()).add(i);
            }
        }
        for (int n = 1; n <= findings.size(); n++) {
            Backend.Finding x = findings.get(n - 1);
            for (String s : x.addresses()) {
                long a;
                try {
                    a = Long.parseUnsignedLong(s.startsWith("0x") ? s.substring(2) : s, 16);
                }
                catch (NumberFormatException ex) {
                    continue;
                }
                Map.Entry<Long, List<Integer>> at = byAddr.floorEntry(a);
                if (at == null) {
                    continue;
                }
                for (int line : at.getValue()) {
                    out.ranks.merge(line, x.rank(), Math::min);
                    out.numbers.computeIfAbsent(line, k -> new TreeSet<>()).add(n);
                    List<String> t = out.tips.computeIfAbsent(line, k -> new ArrayList<>());
                    String text = findingText(n, x);
                    if (!t.contains(text)) {
                        t.add(text);
                    }
                }
            }
        }
        return out;
    }

    /** The background of a whole line, under the text. */
    private static final class LinePainter implements javax.swing.text.Highlighter.HighlightPainter {
        private final Color color;

        LinePainter(Color color) {
            this.color = color;
        }

        @Override
        public void paint(Graphics g, int p0, int p1, Shape bounds, JTextComponent c) {
            try {
                Rectangle2D r = c.modelToView2D(p0);
                if (r != null) {
                    g.setColor(color);
                    g.fillRect(0, (int) r.getY(), c.getWidth(), (int) Math.ceil(r.getHeight()));
                }
            }
            catch (BadLocationException e) {
                // the line is gone
            }
        }
    }

    //--------------------------------------------------------------------------
    // navigation
    //--------------------------------------------------------------------------
    private void addName(String name, Address a) {
        String key = CodeNav.noSpaces(name);
        if (key.isEmpty() || ambiguous.contains(key)) {
            return;
        }
        Address old = names.get(key);
        if (old == null) {
            names.put(key, a);
        }
        else if (!old.equals(a)) {
            names.remove(key);
            ambiguous.add(key);
        }
    }

    /** The functions and data the function refers to, by all their names. */
    private void collectNames() {
        names.clear();
        ambiguous.clear();
        Function f = function();
        if (f == null) {
            return;
        }
        Set<Address> targets = new LinkedHashSet<>();
        InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            for (Reference r : insn.getReferencesFrom()) {
                Address to = r.getToAddress();
                if (r.isStackReference() || r.isRegisterReference() || f.getBody().contains(to)) {
                    continue;
                }
                if (r.getReferenceType().isFlow() && !r.getReferenceType().isCall() && !r.getReferenceType().isJump()) {
                    continue;
                }
                targets.add(to);
            }
        }
        for (Address t : targets) {
            Function g = Names.functionAt(program, t);
            Address dest = g != null && !g.isExternal() ? g.getEntryPoint() : t;
            for (String n : Names.calleeNameVariants(program, t)) {
                addName(n, dest);
            }
            for (String n : Names.qualifiedNames(program, t)) {
                addName(Names.stripTemplates(n), dest);
            }
        }
    }

    /** The line and column under the mouse, null if none. */
    private int[] lineColumn(Side side, MouseEvent e) {
        int pos = side.pane.viewToModel2D(e.getPoint());
        if (pos < 0) {
            return null;
        }
        Element root = side.pane.getDocument().getDefaultRootElement();
        int line = root.getElementIndex(pos);
        if (line < 0 || line >= side.lines.size()) {
            return null;
        }
        int col = pos - root.getElement(line).getStartOffset();
        return new int[]{line, col};
    }

    private void doubleClick(Side side, MouseEvent e) {
        int[] lc = lineColumn(side, e);
        if (lc == null || program.isClosed()) {
            return;
        }
        String line = side.lines.get(lc[0]);
        int x = lc[1];
        boolean shift = (e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0;
        Address target = null;
        boolean isName = false;

        long note = CodeNav.annotationAt(line, x);
        if (note != CodeShaper.NO_ADDRESS) {
            target = Names.toAddress(program, note);
        }
        else {
            // a name the function refers to, possibly qualified
            String q = CodeNav.noSpaces(CodeNav.qualifiedToken(line, x));
            for (String key : new String[]{q, Names.stripTemplates(q)}) {
                if (!key.isEmpty() && names.containsKey(key)) {
                    target = names.get(key);
                    isName = true;
                    break;
                }
            }
            if (target == null) {
                // any other name or a number under the cursor
                String tok = CodeNav.wordAt(line, x);
                if (!tok.isEmpty() && !Highlighter.KEYWORDS.contains(tok)
                    && (!Character.isDigit(tok.charAt(0)) || tok.startsWith("0x"))) {
                    target = Names.parseAddress(program, tok);
                    isName = target != null && !Character.isDigit(tok.charAt(0));
                }
            }
        }
        // another function: its view, like the decompiler does (Shift+double click
        // goes to the listing instead)
        if (isName && target != null && !target.equals(entry) && !shift) {
            Function g = program.getFunctionManager().getFunctionAt(target);
            if (g != null && !g.isThunk() && !g.isExternal()) {
                plugin.openFunction(g);
                return;
            }
        }
        // the address of the line, or of the closest line above
        for (int i = lc[0]; target == null && i >= 0; i--) {
            long a = i < side.lineAddrs.size() ? side.lineAddrs.get(i) : CodeShaper.NO_ADDRESS;
            if (a != CodeShaper.NO_ADDRESS) {
                target = Names.toAddress(program, a);
            }
        }
        if (target != null) {
            plugin.goTo(program, target);
        }
    }
}
