package org.clauderays.ghidra.core;

import java.util.List;

/**
 * Built-in catalog of Claude models: the models offered in
 * Settings and in the "Other model" menus, with their context window and API
 * prices. Update CATALOG when new models reach the Claude Code CLI.
 */
public final class Models {

    private Models() {
    }

    /**
     * One model.
     *
     * @param id       what goes to "claude --model"
     * @param name     display name
     * @param aliasOf  aliases: the family resolved by the CLI, else null
     * @param contextK context window, in thousands of tokens
     * @param inPrice  USD per million input tokens
     * @param outPrice USD per million output tokens
     * @param note     extra pricing remark or null
     * @param effort   "claude --effort" when the setting is auto, never below
     *                 medium (reverse engineering needs precision); null = not passed
     */
    public record ModelInfo(String id, String name, String aliasOf, int contextK, double inPrice,
                            double outPrice, String note, String effort) {
    }

    // Prices are the Anthropic API rates (what the CLI reports as total_cost_usd);
    // on a Claude subscription the queries count against the plan usage instead.
    // Source: Anthropic model table of 2026-10-06. Keep the aliases first.
    // Effort: reverse engineering needs precision, so never below medium: high on
    // Haiku and Sonnet, medium on Opus and Fable (the Opus default of Claude Code).
    // Haiku 4.5 has no effort control (null: --effort is not passed).
    private static final List<ModelInfo> CATALOG = List.of(
        new ModelInfo("opus", "Latest Opus", "Opus", 0, 0, 0, null, "medium"),
        new ModelInfo("sonnet", "Latest Sonnet", "Sonnet", 0, 0, 0, null, "high"),
        new ModelInfo("haiku", "Latest Haiku", "Haiku", 0, 0, 0, null, "high"),
        new ModelInfo("claude-fable-5-1", "Fable 5.1", null, 1000, 10.00, 50.00, null, "medium"),
        new ModelInfo("claude-opus-5-5", "Opus 5.5", null, 1000, 4.00, 20.00, null, "medium"),
        new ModelInfo("claude-opus-5", "Opus 5", null, 1000, 5.00, 25.00, null, "medium"),
        new ModelInfo("claude-opus-4-8", "Opus 4.8", null, 1000, 5.00, 25.00, null, "medium"),
        new ModelInfo("claude-sonnet-5-5", "Sonnet 5.5", null, 1000, 2.00, 10.00, null, "high"),
        new ModelInfo("claude-sonnet-5", "Sonnet 5", null, 1000, 2.00, 10.00, null, "high"),
        new ModelInfo("claude-sonnet-4-6", "Sonnet 4.6", null, 1000, 3.00, 15.00, null, "high"),
        new ModelInfo("claude-haiku-5-5", "Haiku 5.5", null, 1000, 0.10, 0.50, "up to 100K input tokens", "high"),
        new ModelInfo("claude-haiku-4-5", "Haiku 4.5", null, 200, 1.00, 5.00, null, null));

    /** The effort levels of "claude --effort". */
    public static final List<String> EFFORT_LEVELS = List.of("low", "medium", "high", "xhigh", "max");

    public static List<ModelInfo> catalog() {
        return CATALOG;
    }

    /** null if 'id' is not in the catalog. */
    public static ModelInfo find(String id) {
        for (ModelInfo m : CATALOG) {
            if (m.id().equals(id)) {
                return m;
            }
        }
        return null;
    }

    /**
     * The effort to pass for 'model': 'setting' unless it is "auto" (or empty),
     * then the catalog default; "" = do not pass --effort.
     */
    public static String effectiveEffort(String model, String setting) {
        if (setting != null && !setting.isEmpty() && !setting.equals("auto")) {
            return setting;
        }
        ModelInfo m = find(model);
        return m != null && m.effort() != null ? m.effort() : "";
    }

    /** "$4", "$0.10" */
    private static String price(double usd) {
        if (usd < 1.0) {
            return String.format("$%.2f", usd);
        }
        return usd == Math.rint(usd) ? String.format("$%d", (long) usd) : String.format("$%s", usd);
    }

    private static String prices(ModelInfo m) {
        String s = price(m.inPrice()) + " in, " + price(m.outPrice()) + " out per MTok";
        return m.note() != null ? s + " (" + m.note() + ")" : s;
    }

    private static String context(ModelInfo m) {
        if (m.contextK() >= 1000 && m.contextK() % 1000 == 0) {
            return (m.contextK() / 1000) + "M context";
        }
        return m.contextK() + "K context";
    }

    /** Short menu label: "Opus 5.5 ($4 in, $20 out per MTok)"; the id if unknown. */
    public static String menuLabel(String id) {
        ModelInfo m = find(id);
        if (m == null) {
            return id;
        }
        if (m.aliasOf() != null) {
            return m.name() + " (" + m.id() + ")";
        }
        return m.name() + " (" + price(m.inPrice()) + " in, " + price(m.outPrice()) + " out per MTok)";
    }

    /** Longer description: "Opus 5.5, 1M context, $4 in, $20 out per MTok, auto effort medium". */
    public static String description(String id) {
        ModelInfo m = find(id);
        if (m == null) {
            return id;
        }
        String effort = m.effort() != null ? ", auto effort " + m.effort() : ", no effort control";
        if (m.aliasOf() != null) {
            return "alias, the newest " + m.aliasOf() + " known by the installed CLI" + effort;
        }
        return m.name() + ", " + context(m) + ", " + prices(m) + effort;
    }

    /** Settings combobox item: "claude-opus-5-5      Opus 5.5, 1M context, ...". */
    public static String comboItem(String id) {
        if (find(id) == null) {
            return id;
        }
        return Text.pad(id, 20) + " " + description(id);
    }

    /** The model id at the start of a combobox item (its first word). */
    public static String fromComboItem(String item) {
        String t = Text.trim(item);
        int e = 0;
        while (e < t.length() && t.charAt(e) != ' ' && t.charAt(e) != '\t') {
            e++;
        }
        return t.substring(0, e);
    }
}
