package org.clauderays.ghidra.api;

import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * The API of Claude-Rays Decompiler for other plugins (Diaphora-ng).
 *
 * <p>The ClaudeRaysPlugin provides it as a Ghidra service. Diaphora-ng finds
 * it at run time, so neither extension needs the other to build:
 *
 * <pre>
 * Class&lt;?&gt; c = Class.forName("org.clauderays.ghidra.api.ClaudeRaysService");
 * Object svc = tool.getService(c);                       // null: not installed / enabled
 * int v = (Integer) c.getMethod("apiVersion").invoke(svc);
 * String resp = (String) c.getMethod("diffFunctions", String.class).invoke(svc, requestJson);
 * </pre>
 *
 * Request and response are UTF-8 JSON, so no Java type
 * crosses the boundary and new optional fields keep the version. The format
 * is in the README (section "API for Diaphora-ng").
 */
@ServiceInfo(defaultProvider = org.clauderays.ghidra.ui.ClaudeRaysPlugin.class,
    description = "Claude-Rays Decompiler: decompile and diff functions with Claude")
public interface ClaudeRaysService {

    /** The version of this API. */
    int API_VERSION = 1;

    /** {@link #API_VERSION} of the installed plugin. */
    int apiVersion();

    /**
     * The diff of two versions of a function, with the current program of the
     * tool as version A. From the Swing thread it shows a modal task dialog
     * (with Cancel) and blocks until the answer; from another thread it runs
     * there. The result is always a JSON object ("ok": false and "error" on
     * failure or when cancelled).
     */
    String diffFunctions(String requestJson);

    /** The same, with an explicit program and monitor (any thread, no dialog). */
    String diffFunctions(Program program, String requestJson, TaskMonitor monitor);
}
