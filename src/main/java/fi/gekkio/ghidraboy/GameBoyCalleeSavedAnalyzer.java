// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class GameBoyCalleeSavedAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy Callee-Saved Registers";
    static final String CONVENTION = "__asm_saved";

    private static final int PREFIX_LIMIT = 8;
    private static final Set<String> REPLACEABLE = Set.of(Function.UNKNOWN_CALLING_CONVENTION_STRING, Function.DEFAULT_CALLING_CONVENTION_STRING, "__asm");
    private static final String[] SAVED = {"B", "C", "D", "E", "H", "L", "SP"};

    public GameBoyCalleeSavedAnalyzer() {
        super(NAME, "Applies __asm_saved to functions that push BC, DE and HL on entry and pop them before every return", AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "SM83".equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        for (var function : program.getFunctionManager().getFunctions(set, true)) {
            monitor.checkCancelled();
            if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS) || function.hasCustomVariableStorage()
                    || !REPLACEABLE.contains(function.getCallingConventionName()) || !savesBcDeHl(program, function)) {
                continue;
            }
            // convention only: an uncommitted signature keeps parameters and return inferred
            try {
                function.setCallingConvention(CONVENTION);
            } catch (InvalidInputException e) {
                log.appendMsg(NAME, "Could not set " + CONVENTION + " on " + function.getName() + ": " + e.getMessage());
            }
        }
        return true;
    }

    static boolean savesBcDeHl(Program program, Function function) {
        var matched = new HashSet<Address>();
        var pushes = entryPushes(program, function, matched);
        if (pushes == null || !pushes.contains(0xc5) || !pushes.contains(0xd5) || !pushes.contains(0xe5)) {
            return false;
        }
        var body = function.getBody();
        for (var instr : program.getListing().getInstructions(body, true)) {
            var flow = instr.getFlowType();
            var next = instr.getFallThrough();
            // tail calls (CALL_RETURN JPs) leave without the pops
            if (flow.isComputed() || (next != null && !body.contains(next)) || (flow.isTerminal() && !isReturn(opcode(instr)))) {
                return false;
            }
            if (flow.isJump()) {
                for (var target : instr.getFlows()) {
                    if (!body.contains(target)) {
                        return false;
                    }
                }
            }
            if (isReturn(opcode(instr)) && !popsBefore(program, instr, pushes, matched)) {
                return false;
            }
        }
        return balancedStack(program, function, matched);
    }

    // inner PUSH/POP pairs balance on every path and the saved registers are popped at the entry depth
    private static boolean balancedStack(Program program, Function function, Set<Address> matched) {
        var listing = program.getListing();
        var depths = new HashMap<Address, Integer>();
        var work = new ArrayDeque<Address>();
        depths.put(function.getEntryPoint(), 0);
        work.add(function.getEntryPoint());
        while (!work.isEmpty()) {
            var address = work.poll();
            var instr = listing.getInstructionAt(address);
            if (instr == null) {
                return false;
            }
            int depth = depths.get(address);
            var op = opcode(instr);
            if (matched.contains(address)) {
                if ((op & 0xcf) == 0xc1 && depth != 0) {
                    return false;
                }
            } else if ((op & 0xcf) == 0xc5) {
                depth += 2;
            } else if ((op & 0xcf) == 0xc1) {
                depth -= 2;
                if (depth < 0) {
                    return false;
                }
            } else if (changesStack(op)) {
                return false;
            }
            var successors = new ArrayList<Address>();
            if (instr.getFallThrough() != null) {
                successors.add(instr.getFallThrough());
            }
            if (instr.getFlowType().isJump()) {
                successors.addAll(List.of(instr.getFlows()));
            }
            for (var next : successors) {
                // re-entering pushes the registers again after a return path popped them
                if (next.equals(function.getEntryPoint())) {
                    return false;
                }
                var known = depths.putIfAbsent(next, depth);
                if (known == null) {
                    work.add(next);
                } else if (known != depth) {
                    return false;
                }
            }
        }
        // stack changes the walk from the entry never reached
        for (var instr : listing.getInstructions(function.getBody(), true)) {
            if (!depths.containsKey(instr.getAddress()) && changesStack(opcode(instr))) {
                return false;
            }
        }
        return true;
    }

    // PUSH opcodes in execution order; null when BC, DE, HL or SP change before them
    private static List<Integer> entryPushes(Program program, Function function, Set<Address> matched) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var pushes = new ArrayList<Integer>();
        var cur = listing.getInstructionAt(function.getEntryPoint());
        for (int i = 0; cur != null && i < PREFIX_LIMIT + 4; i++) {
            if (i > 0 && refs.hasReferencesTo(cur.getAddress())) {
                return pushes.isEmpty() ? null : pushes;
            }
            var op = opcode(cur);
            if ((op & 0xcf) == 0xc5 && pushes.containsAll(List.of(0xc5, 0xd5, 0xe5))) {
                // pushes after the saved registers are inner pushes
                return pushes;
            } else if ((op & 0xcf) == 0xc5) {
                if (pushes.contains(op)) {
                    return null;
                }
                pushes.add(op);
                matched.add(cur.getAddress());
            } else if (!pushes.isEmpty()) {
                return pushes;
            } else if (i >= PREFIX_LIMIT || cur.getFlows().length != 0 || !cur.getFlowType().isFallthrough() || writesSaved(program, cur)) {
                return null;
            }
            cur = cur.getFallThrough() == null ? null : listing.getInstructionAt(cur.getFallThrough());
        }
        return pushes.isEmpty() ? null : pushes;
    }

    // POPs matching pushes in reverse order fall through into ret
    private static boolean popsBefore(Program program, Instruction ret, List<Integer> pushes, Set<Address> matched) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var cur = ret;
        for (int k = 0; k < pushes.size(); k++) {
            var prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) || opcode(prev) != pushes.get(k) - 4) {
                return false;
            }
            if (k < pushes.size() - 1 && refs.hasReferencesTo(prev.getAddress())) {
                return false;
            }
            matched.add(prev.getAddress());
            cur = prev;
        }
        return true;
    }

    // PUSH/POP rr, LD SP,nn, INC/DEC SP, ADD SP,e, LD HL,SP+e, LD SP,HL, ADD HL,SP, LD (nn),SP
    private static boolean changesStack(int op) {
        return (op & 0xcb) == 0xc1 || op == 0x31 || op == 0x33 || op == 0x3b || op == 0xe8 || op == 0xf8 || op == 0xf9 || op == 0x39 || op == 0x08;
    }

    private static boolean isReturn(int op) {
        return op == 0xc9 || op == 0xd9 || (op & 0xe7) == 0xc0;
    }

    private static boolean writesSaved(Program program, Instruction instr) {
        for (var op : instr.getPcode()) {
            var out = op.getOutput();
            if (out == null || !out.isRegister()) {
                continue;
            }
            for (var name : SAVED) {
                var register = program.getRegister(name);
                var start = register.getAddress().getOffset();
                if (out.getOffset() < start + register.getMinimumByteSize() && start < out.getOffset() + out.getSize()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static int opcode(Instruction instr) {
        try {
            return instr.getByte(0) & 0xff;
        } catch (MemoryAccessException e) {
            return -1;
        }
    }
}
