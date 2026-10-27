package org.clauderays.ghidra.core;

import java.util.ArrayList;
import java.util.List;

/** One labelled section of the context and the size budget. */
public final class Section {

    public String title;
    /** text before the items (never trimmed) */
    public String intro = "";
    /** trimmed from the end */
    public final List<String> items = new ArrayList<>();
    /** 0 = untouchable; the highest goes first */
    public int trimRank;
    public int dropped;

    public Section(String title) {
        this.title = title;
    }

    public Section(String title, int trimRank) {
        this.title = title;
        this.trimRank = trimRank;
    }

    public int size() {
        int n = title.length() + intro.length() + 16;
        for (String i : items) {
            n += i.length() + 1;
        }
        return n;
    }

    public String render() {
        if (intro.isEmpty() && items.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder("== ").append(title).append(" ==\n").append(intro);
        if (!intro.isEmpty() && !intro.endsWith("\n")) {
            out.append('\n');
        }
        for (String i : items) {
            out.append(i);
            if (i.isEmpty() || !i.endsWith("\n")) {
                out.append('\n');
            }
        }
        if (dropped != 0) {
            out.append('(').append(dropped).append(" more left out for size)\n");
        }
        return out.append('\n').toString();
    }

    /** The size of each rendered section, for the verbose log. */
    public record Size(String title, int chars) {
    }

    /**
     * The sections as text within 'budget' characters: the sections with the
     * highest rank are trimmed first, one item at a time.
     */
    public static String assemble(List<Section> sections, int budget, List<Size> sizes) {
        int total = 0;
        for (Section s : sections) {
            total += s.size();
        }
        while (total > budget) {
            Section victim = null;
            for (Section s : sections) {
                if (s.trimRank > 0 && !s.items.isEmpty() && (victim == null || s.trimRank > victim.trimRank)) {
                    victim = s;
                }
            }
            if (victim == null) {
                break;
            }
            String last = victim.items.remove(victim.items.size() - 1);
            victim.dropped++;
            total -= last.length() + 1;
        }
        StringBuilder text = new StringBuilder();
        for (Section s : sections) {
            String r = s.render();
            if (sizes != null) {
                sizes.add(new Size(s.title, r.length()));
            }
            text.append(r);
        }
        return text.toString();
    }
}
