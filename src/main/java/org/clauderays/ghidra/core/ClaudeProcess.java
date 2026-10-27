package org.clauderays.ghidra.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * One synchronous run of a console program that may be aborted from another
 * thread. cancel() kills the child together with its own children.
 */
public final class ClaudeProcess {

    private static final boolean WINDOWS =
        System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");

    private final Object lock = new Object();
    private Process process;
    private boolean cancelled;

    /** What a run produced. */
    public static final class Result {
        /** false: the process could not be started, timed out or was cancelled (see error). */
        public boolean ok;
        public int exitCode = -1;
        public String out = "";
        public String err = "";
        public String error = "";
    }

    /**
     * Run 'exe' with 'args' in the directory 'cwd' (null = inherit), write
     * 'stdinData' to its stdin then close it, and collect stdout / stderr until
     * the process ends. timeoutS == 0 means no timeout.
     */
    public Result run(String exe, List<String> args, File cwd, String stdinData, int timeoutS) {
        Result r = new Result();
        List<String> cmd = new ArrayList<>();
        cmd.add(WINDOWS ? quoteWindows(exe) : exe);
        for (String a : args) {
            cmd.add(WINDOWS ? quoteWindows(a) : a);
        }
        if (WINDOWS && String.join(" ", cmd).length() >= 32767) {
            r.error = "the command line is too long";
            return r;
        }
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (cwd != null) {
            pb.directory(cwd);
        }
        Process p;
        synchronized (lock) {
            if (cancelled) {
                r.error = "cancelled";
                return r;
            }
            try {
                p = pb.start();
            }
            catch (IOException e) {
                r.error = "starting '" + exe + "' failed: " + e.getMessage();
                return r;
            }
            process = p;
        }

        // stdin, stdout and stderr in parallel so a full pipe never blocks the child
        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        Thread writer = new Thread(() -> {
            try (OutputStream os = p.getOutputStream()) {
                os.write(stdinData.getBytes(StandardCharsets.UTF_8));
            }
            catch (IOException e) {
                // the child closed its stdin or was killed
            }
        }, "clauderays-stdin");
        Thread rdOut = pump(p.getInputStream(), outBuf, "clauderays-stdout");
        Thread rdErr = pump(p.getErrorStream(), errBuf, "clauderays-stderr");
        writer.setDaemon(true);
        writer.start();

        boolean finished;
        try {
            if (timeoutS > 0) {
                finished = p.waitFor(timeoutS, TimeUnit.SECONDS);
            }
            else {
                p.waitFor();
                finished = true;
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            finished = false;
            r.error = "interrupted";
        }
        r.ok = finished;
        if (!finished && r.error.isEmpty()) {
            r.error = "timed out after " + timeoutS + " s";
        }
        // kill the process if it is still running and whatever it left behind:
        // the pipes only reach EOF once every holder is gone
        killTree(p);
        join(writer);
        join(rdOut);
        join(rdErr);
        if (!p.isAlive()) {
            r.exitCode = p.exitValue();
        }
        r.out = outBuf.toString(StandardCharsets.UTF_8);
        r.err = errBuf.toString(StandardCharsets.UTF_8);
        synchronized (lock) {
            process = null;
            if (cancelled) {
                r.error = "cancelled";
                r.ok = false;
            }
        }
        return r;
    }

    /** Thread-safe: kill the process in flight (and any later run). */
    public void cancel() {
        synchronized (lock) {
            cancelled = true;
            if (process != null) {
                killTree(process);
            }
        }
    }

    public boolean isCancelled() {
        synchronized (lock) {
            return cancelled;
        }
    }

    private static void killTree(Process p) {
        try {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
        }
        catch (Exception e) {
            // not supported or already gone
        }
        p.destroyForcibly();
        try {
            p.waitFor(5, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Thread pump(InputStream in, ByteArrayOutputStream out, String name) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[16 * 1024];
            try (in) {
                for (int n; (n = in.read(buf)) > 0; ) {
                    synchronized (out) {
                        out.write(buf, 0, n);
                    }
                }
            }
            catch (IOException e) {
                // the process was killed
            }
        }, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void join(Thread t) {
        try {
            t.join(10000);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * One argument quoted the way CommandLineToArgvW / the MS C runtime parse
     * it. Always within quotes: java.lang.ProcessImpl passes an argument that
     * is already quoted as it is, so embedded quotes (the schema, the prompt)
     * and empty arguments ("--tools", "") reach the child intact.
     */
    public static String quoteWindows(String arg) {
        StringBuilder cmd = new StringBuilder("\"");
        int i = 0;
        for (; ; i++) {
            int nbs = 0;
            while (i < arg.length() && arg.charAt(i) == '\\') {
                i++;
                nbs++;
            }
            if (i == arg.length()) {
                // double the trailing backslashes: the closing quote follows
                cmd.append("\\".repeat(nbs * 2));
                break;
            }
            if (arg.charAt(i) == '"') {
                cmd.append("\\".repeat(nbs * 2 + 1)).append('"');
            }
            else {
                cmd.append("\\".repeat(nbs)).append(arg.charAt(i));
            }
        }
        return cmd.append('"').toString();
    }

    //--------------------------------------------------------------------------
    private static String expandEnv(String s) {
        if (!WINDOWS) {
            if (s.startsWith("~/")) {
                return System.getProperty("user.home") + s.substring(1);
            }
            return s;
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        Map<String, String> env = System.getenv();
        while (i < s.length()) {
            int p = s.indexOf('%', i);
            int q = p >= 0 ? s.indexOf('%', p + 1) : -1;
            if (p < 0 || q < 0) {
                out.append(s, i, s.length());
                break;
            }
            out.append(s, i, p);
            String name = s.substring(p + 1, q);
            String value = null;
            for (Map.Entry<String, String> e : env.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    value = e.getValue();
                }
            }
            out.append(value != null ? value : s.substring(p, q + 1));
            i = q + 1;
        }
        return out.toString();
    }

    private static boolean isFile(File f) {
        return f.isFile();
    }

    /**
     * Resolve a program name: environment variables are expanded, a path is
     * used as is (".exe" is appended if needed), a bare name is looked up in
     * PATH and then in %USERPROFILE%\.local\bin (where the Claude Code
     * installer puts it). Returns null if not found.
     */
    public static String findExecutable(String name) {
        String w = expandEnv(Text.trim(name));
        if (w.isEmpty()) {
            return null;
        }
        boolean hasExt = w.toLowerCase(Locale.ROOT).endsWith(".exe");
        String ext = WINDOWS && !hasExt ? ".exe" : "";
        if (w.contains("\\") || w.contains("/") || w.contains(":")) {
            File f = new File(w);
            if (isFile(f)) {
                return f.getAbsolutePath();
            }
            File g = new File(w + ext);
            return !ext.isEmpty() && isFile(g) ? g.getAbsolutePath() : null;
        }
        String path = System.getenv("PATH");
        if (path == null) {
            path = System.getenv("Path");
        }
        if (path != null) {
            for (String dir : path.split(File.pathSeparator)) {
                if (dir.isBlank()) {
                    continue;
                }
                File f = new File(dir.replace("\"", ""), w + ext);
                if (isFile(f)) {
                    return f.getAbsolutePath();
                }
            }
        }
        // Ghidra may have been started before the installer added this folder to PATH
        File local = new File(new File(System.getProperty("user.home"), ".local" + File.separator + "bin"), w + ext);
        return isFile(local) ? local.getAbsolutePath() : null;
    }

    /** A neutral, empty working directory (%TEMP%\clauderays), created on demand; null on failure. */
    public static File neutralWorkDir() {
        File dir = new File(System.getProperty("java.io.tmpdir"), "clauderays");
        if (!dir.isDirectory() && !dir.mkdirs()) {
            return null;
        }
        return dir;
    }
}
