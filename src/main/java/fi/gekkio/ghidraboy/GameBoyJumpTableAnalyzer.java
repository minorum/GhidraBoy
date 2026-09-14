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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

public class GameBoyJumpTableAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy JP (HL) Jump Tables";

    static final String INLINE_TABLE_FIXUP = "sm83_inline_jump_table";

    private static final int SCAN_LIMIT = 16;
    private static final int MAX_INSTRUCTION_LENGTH = 3;
    // LD A,(HL+); LD H,(HL); LD L,A
    private static final byte[] LOAD_POINTER = {0x2a, 0x66, 0x6f};
    // ADD L; LD L,A; JR NC,+1; INC H  and  ADD L; LD L,A; ADC H; SUB L; LD H,A
    private static final byte[][] CARRY_INTO_H = {
            {(byte) 0x85, 0x6f, 0x30, 0x01, 0x24},
            {(byte) 0x85, 0x6f, (byte) 0x8c, (byte) 0x95, 0x67},
    };

    public GameBoyJumpTableAnalyzer() {
        super(NAME, "Recovers word jump tables dispatched with LD HL,table ... LD A,(HL+) / LD H,(HL) / LD L,A / JP HL", AnalyzerType.INSTRUCTION_ANALYZER);
        // after decompiler switch recovery, before constant propagation
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before().before());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "SM83".equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        var tables = new LinkedHashMap<Address, List<Address>>();
        var disassemble = new AddressSet();
        for (var instr : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            var dispatcherAddress = inlineTableDispatcher(program, instr);
            if (dispatcherAddress != null) {
                // the bank analyzer's cases; recomputing disagrees once a case jumps back to the call
                var targets = markedTargets(program, instr.getAddress());
                var dispatcher = program.getFunctionManager().getFunctionAt(dispatcherAddress);
                if (!targets.isEmpty() && dispatcher != null) {
                    dispatcher.setCallFixup(INLINE_TABLE_FIXUP);
                    tables.put(instr.getAddress(), targets);
                }
                continue;
            }
            if (!instr.getFlowType().isComputed() || !"JP".equals(instr.getMnemonicString())) {
                continue;
            }
            var table = findTable(program, instr);
            if (table == null) {
                continue;
            }
            var targets = GameBoyBankAnalyzer.tableTargets(program, instr.getAddress(), table);
            if (targets.isEmpty() || !needsRecovery(program, instr.getAddress(), targets)) {
                continue;
            }
            removeComputedReferences(program, instr.getAddress());
            clearByteData(program, table, table.add(2L * targets.size() - 1));
            for (var target : targets) {
                clearByteData(program, target, target.add(MAX_INSTRUCTION_LENGTH - 1));
            }
            GameBoyBankAnalyzer.markTable(program, instr.getAddress(), table, targets, disassemble, monitor, log);
            tables.put(instr.getAddress(), targets);
        }
        if (!disassemble.isEmpty()) {
            new DisassembleCommand(disassemble, null, true).applyTo(program, monitor);
        }
        for (var entry : tables.entrySet()) {
            var function = program.getFunctionManager().getFunctionContaining(entry.getKey());
            if (function == null) {
                continue;
            }
            try {
                new JumpTable(entry.getKey(), new ArrayList<>(entry.getValue()), true, 0).writeOverride(function);
            } catch (InvalidInputException e) {
                log.appendMsg(NAME, "Could not override jump table at " + entry.getKey() + ": " + e.getMessage());
            }
            CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
        }
        return true;
    }

    static List<Address> markedTargets(Program program, Address from) {
        var targets = new ArrayList<Address>();
        for (var ref : program.getReferenceManager().getReferencesFrom(from)) {
            if (ref.getReferenceType() == RefType.COMPUTED_JUMP && ref.getSource() == SourceType.ANALYSIS) {
                targets.add(ref.getToAddress());
            }
        }
        return targets;
    }

    // called dispatcher of a call the bank analyzer marked with its table targets
    private static Address inlineTableDispatcher(Program program, Instruction instr) {
        if (!instr.getFlowType().isCall() || instr.getFlowOverride() != FlowOverride.CALL_RETURN) {
            return null;
        }
        Address dispatcher = null;
        var marked = false;
        for (var ref : program.getReferenceManager().getReferencesFrom(instr.getAddress())) {
            if (ref.getReferenceType().isCall()) {
                dispatcher = ref.getToAddress();
            }
            marked |= ref.getReferenceType() == RefType.COMPUTED_JUMP && ref.getSource() == SourceType.ANALYSIS;
        }
        return marked ? dispatcher : null;
    }

    // unresolved, or resolved by other analyzers past the end of the table
    private static boolean needsRecovery(Program program, Address from, List<Address> targets) {
        var found = false;
        var stale = false;
        for (var ref : program.getReferenceManager().getReferencesFrom(from)) {
            if (!ref.getReferenceType().isComputed()) {
                continue;
            }
            if (ref.getSource() != SourceType.ANALYSIS) {
                return false;
            }
            stale |= !targets.contains(ref.getToAddress());
            found = true;
        }
        return stale || !found;
    }

    private static void removeComputedReferences(Program program, Address from) {
        var refs = program.getReferenceManager();
        for (var ref : refs.getReferencesFrom(from)) {
            if (ref.getReferenceType().isComputed()) {
                refs.delete(ref);
            }
        }
    }

    // decompiler switch recovery types table entries and targets as bytes; keep code and other data
    private static void clearByteData(Program program, Address start, Address end) {
        var listing = program.getListing();
        var bytes = new ArrayList<Data>();
        for (var data : listing.getDefinedData(new AddressSet(start, end), true)) {
            if (data.getDataType() instanceof ByteDataType) {
                bytes.add(data);
            }
        }
        for (var data : bytes) {
            listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false);
        }
    }

    // ponytail: only the LD A,(HL+) / LD H,(HL) / LD L,A load, other pointer loads need their own patterns
    private static Address findTable(Program program, Instruction jump) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var hl = program.getRegister("HL");
        var cur = jump;
        for (int i = 0; i < SCAN_LIMIT; i++) {
            if (i == LOAD_POINTER.length) {
                var add = carryIntoH(program, cur);
                if (add != null) {
                    cur = add;
                }
            }
            // another path may reach cur with a different HL
            if (refs.hasReferencesTo(cur.getAddress())) {
                return null;
            }
            var prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) || prev.getFlowType().isCall()) {
                return null;
            }
            byte[] bytes;
            try {
                bytes = prev.getBytes();
            } catch (MemoryAccessException e) {
                return null;
            }
            if (i < LOAD_POINTER.length) {
                if (bytes.length != 1 || bytes[0] != LOAD_POINTER[LOAD_POINTER.length - 1 - i]) {
                    return null;
                }
            } else if (bytes[0] == 0x21) {
                return GameBoyBankAnalyzer.sameBankAddress(program, jump.getAddress(), (bytes[1] & 0xff) | ((bytes[2] & 0xff) << 8));
            } else if ((bytes[0] & 0xcf) != 0x09 && writes(prev, hl)) {
                // only ADD HL,rr may change HL after the table load
                return null;
            }
            cur = prev;
        }
        return null;
    }

    // ADD L instruction of an 8-bit index add carried into H just before the pointer load
    private static Instruction carryIntoH(Program program, Instruction load) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        Address start;
        var bytes = new byte[5];
        try {
            start = load.getAddress().subtractNoWrap(bytes.length);
            if (program.getMemory().getBytes(start, bytes) != bytes.length) {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
        var pattern = Arrays.stream(CARRY_INTO_H).filter(p -> Arrays.equals(p, bytes)).findFirst().orElse(null);
        var add = listing.getInstructionAt(start);
        if (pattern == null || add == null || listing.getInstructionAt(start.add(4)) == null) {
            return null;
        }
        for (int i = 1; i < bytes.length; i++) {
            if (refs.hasReferencesTo(start.add(i))) {
                return null;
            }
        }
        // only JR NC may branch to the load
        for (var ref : refs.getReferencesTo(load.getAddress())) {
            if (pattern[2] != 0x30 || !ref.getFromAddress().equals(start.add(2))) {
                return null;
            }
        }
        return add;
    }

    static boolean writes(Instruction instr, Register register) {
        var start = register.getAddress().getOffset();
        var end = start + register.getMinimumByteSize();
        for (var op : instr.getPcode()) {
            var out = op.getOutput();
            if (out != null && out.isRegister() && out.getOffset() < end && start < out.getOffset() + out.getSize()) {
                return true;
            }
        }
        return false;
    }
}
