package org.clauderays.ghidra.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The control flow graph of a function: its basic
 * blocks by address, their successors and predecessors, the block kinds and
 * the loops (dominators, Cooper / Harvey / Kennedy).
 */
public final class Cfg {

    /** One basic block; its number is its position by address. */
    public static final class Block {
        public final int number;
        public final Address start;
        /** the last address of the block (inclusive) */
        public final Address end;
        public final AddressSetView body;
        /** successor blocks inside the function */
        public final List<Integer> succ = new ArrayList<>();
        /** successors outside the function (tail jumps, chunks Ghidra did not add) */
        public final List<Address> outside = new ArrayList<>();
        public final List<Integer> pred = new ArrayList<>();
        public final List<Instruction> insns = new ArrayList<>();

        Block(int number, CodeBlock cb) {
            this.number = number;
            this.start = cb.getMinAddress();
            this.end = cb.getMaxAddress();
            this.body = cb;
        }

        public boolean contains(Address a) {
            return body.contains(a);
        }

        public Instruction last() {
            return insns.isEmpty() ? null : insns.get(insns.size() - 1);
        }
    }

    public final Program program;
    public final Function function;
    public final List<Block> blocks = new ArrayList<>();
    private final int[] idom;
    private final boolean[] reachable;
    private final List<List<Integer>> backEdgesFrom = new ArrayList<>();   // per header
    private final List<List<Integer>> loopsOf = new ArrayList<>();         // headers containing a block

    public Cfg(Function function, TaskMonitor monitor) throws CancelledException {
        this.function = function;
        this.program = function.getProgram();
        AddressSetView body = function.getBody();
        BasicBlockModel model = new BasicBlockModel(program);
        List<CodeBlock> cbs = new ArrayList<>();
        CodeBlockIterator it = model.getCodeBlocksContaining(body, monitor);
        while (it.hasNext()) {
            CodeBlock cb = it.next();
            if (body.contains(cb.getMinAddress())) {
                cbs.add(cb);
            }
        }
        cbs.sort(Comparator.comparing(CodeBlock::getMinAddress));
        Listing listing = program.getListing();
        for (int i = 0; i < cbs.size(); i++) {
            Block b = new Block(i, cbs.get(i));
            InstructionIterator ii = listing.getInstructions(cbs.get(i), true);
            while (ii.hasNext()) {
                b.insns.add(ii.next());
            }
            blocks.add(b);
        }
        for (int i = 0; i < cbs.size(); i++) {
            Block b = blocks.get(i);
            CodeBlockReferenceIterator ri = cbs.get(i).getDestinations(monitor);
            while (ri.hasNext()) {
                CodeBlockReference r = ri.next();
                FlowType ft = r.getFlowType();
                if (ft.isCall()) {
                    continue;
                }
                Address dst = r.getDestinationAddress();
                int s = blockIndex(dst);
                if (s >= 0) {
                    if (!b.succ.contains(s)) {
                        b.succ.add(s);
                    }
                }
                else if (dst != null && dst.isMemoryAddress() && !b.outside.contains(dst)) {
                    b.outside.add(dst);
                }
            }
        }
        for (Block b : blocks) {
            for (int s : b.succ) {
                List<Integer> p = blocks.get(s).pred;
                if (!p.contains(b.number)) {
                    p.add(b.number);
                }
            }
        }
        int n = blocks.size();
        idom = new int[n];
        reachable = new boolean[n];
        for (int i = 0; i < n; i++) {
            backEdgesFrom.add(new ArrayList<>());
            loopsOf.add(new ArrayList<>());
        }
        computeLoops(function.getEntryPoint());
    }

    /** The block containing 'a', -1 if none. */
    public int blockIndex(Address a) {
        if (a == null) {
            return -1;
        }
        int lo = 0;
        int hi = blocks.size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            Block b = blocks.get(mid);
            if (a.compareTo(b.start) < 0) {
                hi = mid - 1;
            }
            else if (a.compareTo(b.end) > 0) {
                lo = mid + 1;
            }
            else {
                return b.contains(a) ? mid : -1;
            }
        }
        // overlapping ranges are not expected, but be safe
        for (Block b : blocks) {
            if (b.contains(a)) {
                return b.number;
            }
        }
        return -1;
    }

    public int size() {
        return blocks.size();
    }

    public boolean isReachable(int b) {
        return reachable[b];
    }

    private void computeLoops(Address entryEa) {
        int n = blocks.size();
        java.util.Arrays.fill(idom, -1);
        int entry = blockIndex(entryEa);
        if (entry < 0) {
            return;
        }
        // reverse post order from the entry
        List<Integer> post = new ArrayList<>();
        int[] state = new int[n];
        List<int[]> stack = new ArrayList<>();
        stack.add(new int[]{entry, 0});
        state[entry] = 1;
        while (!stack.isEmpty()) {
            int[] top = stack.get(stack.size() - 1);
            Block b = blocks.get(top[0]);
            if (top[1] < b.succ.size()) {
                int s = b.succ.get(top[1]++);
                if (state[s] == 0) {
                    state[s] = 1;
                    stack.add(new int[]{s, 0});
                }
                continue;
            }
            post.add(top[0]);
            stack.remove(stack.size() - 1);
        }
        List<Integer> rpo = new ArrayList<>(post);
        Collections.reverse(rpo);
        int[] rpoNum = new int[n];
        java.util.Arrays.fill(rpoNum, -1);
        for (int i = 0; i < rpo.size(); i++) {
            rpoNum[rpo.get(i)] = i;
            reachable[rpo.get(i)] = true;
        }

        idom[entry] = entry;
        for (boolean changed = true; changed; ) {
            changed = false;
            for (int i = 1; i < rpo.size(); i++) {
                int b = rpo.get(i);
                int newIdom = -1;
                for (int p : blocks.get(b).pred) {
                    if (idom[p] < 0) {
                        continue;
                    }
                    newIdom = newIdom < 0 ? p : intersect(p, newIdom, rpoNum);
                }
                if (newIdom >= 0 && idom[b] != newIdom) {
                    idom[b] = newIdom;
                    changed = true;
                }
            }
        }

        // back edges u -> h where h dominates u, and the natural loop of each
        for (int u : rpo) {
            for (int h : blocks.get(u).succ) {
                if (!reachable[h] || !dominates(h, u)) {
                    continue;
                }
                backEdgesFrom.get(h).add(u);
                Set<Integer> body = new HashSet<>();
                body.add(h);
                List<Integer> work = new ArrayList<>();
                if (body.add(u)) {
                    work.add(u);
                }
                while (!work.isEmpty()) {
                    int x = work.remove(work.size() - 1);
                    for (int p : blocks.get(x).pred) {
                        if (reachable[p] && body.add(p)) {
                            work.add(p);
                        }
                    }
                }
                List<Integer> sorted = new ArrayList<>(body);
                Collections.sort(sorted);
                for (int x : sorted) {
                    if (!loopsOf.get(x).contains(h)) {
                        loopsOf.get(x).add(h);
                    }
                }
            }
        }
    }

    private int intersect(int a, int b, int[] rpoNum) {
        while (a != b) {
            while (rpoNum[a] > rpoNum[b]) {
                a = idom[a];
            }
            while (rpoNum[b] > rpoNum[a]) {
                b = idom[b];
            }
        }
        return a;
    }

    public boolean dominates(int a, int b) {
        for (int guard = 0; guard < blocks.size() + 1; guard++) {
            if (b == a) {
                return true;
            }
            if (b < 0 || idom[b] == b || idom[b] < 0) {
                return false;
            }
            b = idom[b];
        }
        return false;
    }

    /** The block header of the listing: "LAB_401020:    ; block 3, return, -> 4, 5". */
    public String blockHeader(int bi) {
        Block blk = blocks.get(bi);
        String label = Names.labelAt(program, blk.start);
        if (label.isEmpty()) {
            label = "block_" + blk.start.toString(false);
        }
        StringBuilder info = new StringBuilder("block ").append(bi);
        String kind = blockKind(blk);
        if (!kind.isEmpty()) {
            info.append(", ").append(kind);
        }
        if (!reachable[bi]) {
            info.append(", unreachable from the entry");
        }
        List<Integer> back = backEdgesFrom.get(bi);
        if (!back.isEmpty()) {
            info.append(", loop header (back edge from ");
            for (int i = 0; i < back.size(); i++) {
                // the address of the jump that closes the loop
                Block src = blocks.get(back.get(i));
                Instruction last = src.last();
                info.append(i == 0 ? "" : ", ").append(Names.hex(last != null ? last.getAddress() : src.start));
            }
            info.append(")");
        }
        StringBuilder inLoops = new StringBuilder();
        for (int h : loopsOf.get(bi)) {
            if (h != bi) {
                inLoops.append(inLoops.length() == 0 ? "" : ", ").append(Names.hex(blocks.get(h).start));
            }
        }
        if (inLoops.length() > 0) {
            info.append(", in loop ").append(inLoops);
        }
        StringBuilder succ = new StringBuilder();
        for (int s : blk.succ) {
            succ.append(succ.length() == 0 ? "" : ", ").append(s);
        }
        for (Address o : blk.outside) {
            succ.append(succ.length() == 0 ? "" : ", ").append("outside ").append(Names.hex(o));
        }
        if (succ.length() > 0) {
            info.append(", -> ").append(succ);
        }
        String line = label + ":";
        return org.clauderays.ghidra.core.Text.pad(line, 36) + " ; " + info;
    }

    /** "return", "noreturn", "indirect jump"... (calc_block_type), "" for a plain block. */
    public String blockKind(Block blk) {
        Instruction last = blk.last();
        if (last == null) {
            return "";
        }
        FlowType ft = last.getFlowType();
        if (ft.isTerminal()) {
            return ft.isConditional() ? "conditional return" : "return";
        }
        if (ft.isComputed() && ft.isJump()) {
            return "indirect jump";
        }
        if (blk.succ.isEmpty() && blk.outside.isEmpty()) {
            if (ft.isCall() || last.getFallThrough() == null) {
                return "noreturn";
            }
            return "runs past the function end";
        }
        return "";
    }
}
