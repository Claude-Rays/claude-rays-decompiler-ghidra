package org.clauderays.ghidra.ui;

import docking.DialogComponentProvider;
import org.clauderays.ghidra.core.Models;
import org.clauderays.ghidra.core.Settings;
import org.clauderays.ghidra.core.Text;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/** Claude-Rays Decompiler Settings. */
final class SettingsDialog extends DialogComponentProvider {

    private final ClaudeRaysPlugin plugin;
    private final JTextField claudePath = new JTextField(50);
    private final JComboBox<String> defaultModel = new JComboBox<>();
    private final JTextField models = new JTextField(50);
    private final JComboBox<String> effort = new JComboBox<>();
    private final JTextField timeout = new JTextField(8);
    private final JTextField maxInsns = new JTextField(8);
    private final JTextField budget = new JTextField(8);
    private final JComboBox<String> context = new JComboBox<>();
    private final JCheckBox verbose =
        new JCheckBox("Verbose logging (full input and output, section sizes, usage, rounds)");
    private final JCheckBox showAnnotations = new JCheckBox("Show the /*0x...*/ address annotations in the code");

    SettingsDialog(ClaudeRaysPlugin plugin) {
        super("Claude-Rays Decompiler Settings", true, false, true, false);
        this.plugin = plugin;
        Settings s = Settings.get();
        claudePath.setText(s.claudePath);
        for (String m : s.menuModels()) {
            defaultModel.addItem(Models.comboItem(m));
        }
        defaultModel.setEditable(true);
        defaultModel.setSelectedItem(Models.comboItem(s.defaultModel));
        models.setText(s.modelsStr());
        effort.addItem("auto (per model)");
        for (String e : Models.EFFORT_LEVELS) {
            effort.addItem(e);
        }
        effort.setSelectedIndex(Math.max(Models.EFFORT_LEVELS.indexOf(s.effort) + 1, 0));
        timeout.setText(Integer.toString(s.timeout));
        maxInsns.setText(Integer.toString(s.maxInsns));
        budget.setText(Integer.toString(s.budget));
        for (String c : Settings.CONTEXTS) {
            context.addItem(Settings.contextLabel(c));
        }
        context.setSelectedIndex(Settings.CONTEXTS.indexOf(s.context));
        verbose.setSelected(s.verbose);
        showAnnotations.setSelected(s.showAnnotations);

        claudePath.setToolTipText("claude.exe, as a name looked up in PATH (and in USERPROFILE\\.local\\bin) "
            + "or a full path");
        defaultModel.setToolTipText("<html>Model used by Decompile. opus by default (sonnet is weaker, haiku falls "
            + "short to decompile).<br>An alias follows the newest version known by the CLI, a full id pins one "
            + "version.<br>Prices are API rates; on a subscription the queries count against the plan usage.");
        models.setToolTipText("Model ids not in the list, comma separated (new models the CLI accepts). "
            + "The Other model menus offer the list plus these");
        effort.setToolTipText("Thinking effort passed to claude (--effort). auto uses the default of each model "
            + "in the catalog: high on Haiku and Sonnet, medium on Opus and Fable");
        timeout.setToolTipText("Seconds to wait for one answer, 0 waits forever");
        maxInsns.setToolTipText("Functions with more instructions are not sent");
        budget.setToolTipText("Size budget of the collected context, in characters (about 4 per token)");
        context.setToolTipText("<html>What Decompile sends of the function:<br>"
            + "<b>listing</b>: the disassembly annotated with exact facts (the most faithful);<br>"
            + "<b>listing + Ghidra's C</b>: the same, plus the C of Ghidra's decompiler as a draft (data flow, "
            + "structure);<br><b>Ghidra's C + plain listing</b>: the draft first and the listing without facts "
            + "(smaller, less faithful).<br>Decompile with context runs one function with another mode.");

        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        int row = 0;
        row = addRow(p, row, "Claude path:", claudePath);
        row = addRow(p, row, "Default model:", defaultModel);
        row = addRow(p, row, "Extra models:", models);
        row = addRow(p, row, "Effort:", effort);
        row = addRow(p, row, "Timeout (s):", timeout);
        row = addRow(p, row, "Max instructions:", maxInsns);
        row = addRow(p, row, "Context budget (chars):", budget);
        row = addRow(p, row, "Context:", context);
        row = addRow(p, row, "", verbose);
        row = addRow(p, row, "", showAnnotations);
        addRow(p, row, "", new JLabel("<html><i>The shortcut of Decompile (Ctrl+Shift+F5) is set in "
            + "Edit &gt; Tool Options &gt; Key Bindings.</i>"));
        addWorkPanel(p);
        addOKButton();
        addCancelButton();
        setRememberSize(false);
    }

    private static int addRow(JPanel p, int row, String label, JComponent c) {
        GridBagConstraints l = new GridBagConstraints();
        l.gridx = 0;
        l.gridy = row;
        l.anchor = GridBagConstraints.WEST;
        l.insets = new Insets(3, 3, 3, 8);
        p.add(new JLabel(label), l);
        GridBagConstraints r = new GridBagConstraints();
        r.gridx = 1;
        r.gridy = row;
        r.anchor = GridBagConstraints.WEST;
        r.fill = GridBagConstraints.HORIZONTAL;
        r.weightx = 1;
        r.insets = new Insets(3, 3, 3, 3);
        p.add(c, r);
        return row + 1;
    }

    private static int intOf(JTextField f, int def) {
        try {
            return Integer.parseInt(Text.trim(f.getText()));
        }
        catch (NumberFormatException e) {
            return def;
        }
    }

    @Override
    protected void okCallback() {
        Settings s = Settings.get();
        String oldMenu = s.defaultModel + "|" + s.modelsStr();
        boolean oldAnnotations = s.showAnnotations;
        s.claudePath = Text.trim(claudePath.getText());
        if (s.claudePath.isEmpty()) {
            s.claudePath = Settings.DEFAULT_CLAUDE_PATH;
        }
        s.setModels(models.getText());
        Object sel = defaultModel.getEditor().getItem();
        s.setDefaultModel(Models.fromComboItem(sel != null ? sel.toString() : ""));
        int ei = effort.getSelectedIndex();
        s.effort = ei >= 1 && ei <= Models.EFFORT_LEVELS.size() ? Models.EFFORT_LEVELS.get(ei - 1) : "auto";
        s.timeout = Math.max(intOf(timeout, 300), 0);
        s.maxInsns = Math.max(intOf(maxInsns, 1500), 10);
        s.budget = Math.max(intOf(budget, 60000), 4000);
        s.context = Settings.CONTEXTS.get(Math.max(context.getSelectedIndex(), 0));
        s.verbose = verbose.isSelected();
        s.showAnnotations = showAnnotations.isSelected();
        close();
        plugin.settingsChanged(!(s.defaultModel + "|" + s.modelsStr()).equals(oldMenu),
            s.showAnnotations != oldAnnotations);
    }
}
