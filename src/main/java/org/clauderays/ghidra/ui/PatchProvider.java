package org.clauderays.ghidra.ui;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.WindowPosition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.MouseEvent;
import java.util.List;

/**
 * Generate patch: the fixes of a function as a unified diff of its decompiled
 * code ("Claude-Rays Decompiler patch: <function>"): removed lines red, added
 * lines green.
 */
public final class PatchProvider extends ComponentProvider {

    /** The action context of the view. */
    public static final class Context extends DefaultActionContext {
        Context(PatchProvider p) {
            super(p, p.pane);
        }

        public PatchProvider view() {
            return (PatchProvider) getComponentProvider();
        }
    }

    private final ClaudeRaysPlugin plugin;
    final Program program;
    final Address entry;
    private final JTextPane pane = new JTextPane() {
        // the lines of a patch do not wrap
        @Override
        public boolean getScrollableTracksViewportWidth() {
            return getParent() == null || getUI().getPreferredSize(this).width <= getParent().getWidth();
        }
    };
    private final JScrollPane scroll = new JScrollPane(pane);
    private String text = "";

    PatchProvider(ClaudeRaysPlugin plugin, Program program, Address entry) {
        super(plugin.getTool(), "Claude-Rays Decompiler patch", plugin.getName(), Context.class);
        this.plugin = plugin;
        this.program = program;
        this.entry = entry;
        setTransient();
        setDefaultWindowPosition(WindowPosition.RIGHT);
        setWindowMenuGroup("Claude-Rays Decompiler");
        pane.setEditable(false);
        pane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
    }

    @Override
    public JComponent getComponent() {
        return scroll;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return new Context(this);
    }

    @Override
    public void closeComponent() {
        super.closeComponent();
        plugin.patchClosed(this);
    }

    /** The patch as text, for Copy code. */
    String text() {
        return text;
    }

    void show(String funcName, List<String> lines) {
        setTitle("Claude-Rays Decompiler patch: " + funcName);
        setTabText("patch: " + funcName);
        boolean dark = Highlighter.isDark(pane.getBackground());
        StyledDocument doc = pane.getStyledDocument();
        boolean inDiff = false;
        try {
            doc.remove(0, doc.getLength());
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i);
                inDiff |= l.startsWith("--- ");
                SimpleAttributeSet a = new SimpleAttributeSet();
                if (!inDiff) {
                    StyleConstants.setForeground(a, Highlighter.color(Highlighter.Kind.NOTE, dark));
                }
                else if (l.startsWith("--- ") || l.startsWith("+++ ")) {
                    StyleConstants.setBold(a, true);
                }
                else if (l.startsWith("@@")) {
                    StyleConstants.setForeground(a, dark ? new Color(0x80, 0xd0, 0xff) : new Color(0x00, 0x60, 0xa0));
                }
                else if (l.startsWith("+")) {
                    StyleConstants.setBackground(a, Highlighter.fixColor(1, dark));
                }
                else if (l.startsWith("-")) {
                    StyleConstants.setBackground(a, Highlighter.findingColor(0, dark));
                }
                doc.insertString(doc.getLength(), l, a);
                if (i + 1 < lines.size()) {
                    doc.insertString(doc.getLength(), "\n", null);
                }
            }
        }
        catch (BadLocationException e) {
            // cannot happen: always at the end
        }
        pane.setCaretPosition(0);
        text = String.join("\n", lines) + "\n";
    }
}
