package org.clauderays.ghidra.core;

import java.util.function.Consumer;

/**
 * Logging. The plugin points
 * the sink to the Ghidra console; without it the messages go to stdout.
 */
public final class Log {

    private static final String PREFIX = "Claude-Rays Decompiler: ";
    private static volatile Consumer<String> sink = System.out::println;
    private static volatile Consumer<String> errorSink = System.err::println;

    private Log() {
    }

    public static void setSinks(Consumer<String> info, Consumer<String> error) {
        sink = info != null ? info : System.out::println;
        errorSink = error != null ? error : System.err::println;
    }

    public static void info(String fmt, Object... args) {
        sink.accept(PREFIX + format(fmt, args));
    }

    public static void error(String fmt, Object... args) {
        errorSink.accept(PREFIX + "ERROR: " + format(fmt, args));
    }

    public static void debug(String fmt, Object... args) {
        if (Settings.get().verbose) {
            sink.accept(PREFIX + "[debug] " + format(fmt, args));
        }
    }

    /** Multi line text, printed only in verbose mode. */
    public static void debugText(String title, String text) {
        if (!Settings.get().verbose) {
            return;
        }
        sink.accept(PREFIX + "[debug] " + title);
        for (String line : Text.splitLines(text)) {
            sink.accept(line);
        }
    }

    /** Raw lines, without the prefix. */
    public static void raw(String line) {
        sink.accept(line);
    }

    private static String format(String fmt, Object... args) {
        return args.length == 0 ? fmt : String.format(fmt, args);
    }
}
