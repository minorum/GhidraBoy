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

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class GameBoyBankAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy Bank Switching";
    static final String OPT_TRACK_WRITES = "Track bank register writes";
    static final String OPT_FAR_CALLS = "Inline far call dispatchers";
    static final String OPT_JUMP_TABLES = "Inline jump table dispatchers";

    private static final int SCAN_LIMIT = 16;
    private static final int MAX_TABLE_ENTRIES = 256;

    private boolean trackWrites = true;
    private Set<Long> farCallDispatchers = Set.of();
    private Set<Long> jumpTableDispatchers = Set.of();

    public GameBoyBankAnalyzer() {
        super(NAME, "Resolves calls into banked ROM after constant bank register writes and through configured inline dispatchers", AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.DISASSEMBLY.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "SM83".equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_TRACK_WRITES, trackWrites, null, "Resolve CALL/JP into 0x4000-0x7FFF preceded by LD A,n and a write to the ROM bank register");
        options.registerOption(OPT_FAR_CALLS, "", null, "Hex addresses of routines called as CALL addr followed by db low, high, bank");
        options.registerOption(OPT_JUMP_TABLES, "", null, "Hex addresses of routines called as CALL/RST addr followed by a word table indexed by A");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        trackWrites = options.getBoolean(OPT_TRACK_WRITES, trackWrites);
        farCallDispatchers = parseAddresses(options.getString(OPT_FAR_CALLS, ""));
        jumpTableDispatchers = parseAddresses(options.getString(OPT_JUMP_TABLES, ""));
    }

    static Set<Long> parseAddresses(String text) {
        var result = new HashSet<Long>();
        for (var token : text.split("[,\\s]+")) {
            var hex = token.trim().replaceFirst("^(0[xX]|\\$)", "");
            try {
                result.add(Long.parseLong(hex, 16));
            } catch (NumberFormatException ignored) {
            }
        }
        return result;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        var register = BankRegister.of(program);
        var candidates = new ArrayList<Address>();
        for (var instr : program.getListing().getInstructions(set, true)) {
            var flowType = instr.getFlowType();
            if ((flowType.isCall() || flowType.isJump()) && instr.getFlows().length == 1) {
                candidates.add(instr.getAddress());
            }
        }

        var disassemble = new AddressSet();
        var functions = new AddressSet();
        for (var address : candidates) {
            monitor.checkCancelled();
            // earlier fixups may have cleared it
            var instr = program.getListing().getInstructionAt(address);
            if (instr == null || instr.getFlows().length != 1 || hasOwnReference(program, address)) {
                continue;
            }
            var isCall = instr.getFlowType().isCall();
            var target = instr.getFlows()[0].getOffset();
            if (isCall && farCallDispatchers.contains(target)) {
                farCall(program, instr, disassemble, functions, monitor, log);
            } else if (isCall && jumpTableDispatchers.contains(target)) {
                jumpTable(program, instr, disassemble, monitor, log);
            } else if (trackWrites && register != null && target >= 0x4000 && target < 0x8000) {
                bankSwitch(program, instr, register, disassemble, functions);
            }
        }

        var manager = AutoAnalysisManager.getAnalysisManager(program);
        if (!disassemble.isEmpty()) {
            manager.disassemble(disassemble);
        }
        if (!functions.isEmpty()) {
            manager.createFunction(functions, false);
        }
        return true;
    }

    private static boolean hasOwnReference(Program program, Address from) {
        for (var ref : program.getReferenceManager().getReferencesFrom(from)) {
            if (ref.getSource() == SourceType.ANALYSIS && (ref.getReferenceType().isOverride() || ref.getReferenceType() == RefType.COMPUTED_JUMP)) {
                return true;
            }
        }
        return false;
    }

    private static void bankSwitch(Program program, Instruction instr, BankRegister register, AddressSet disassemble, AddressSet functions) {
        if (instr.getAddress().getAddressSpace().isOverlaySpace()) {
            return;
        }
        var bank = findBank(program, instr, register);
        if (bank == null) {
            return;
        }
        var target = romAddress(program, instr.getAddress(), bank, (int) instr.getFlows()[0].getOffset());
        if (target == null) {
            return;
        }
        var isCall = instr.getFlowType().isCall();
        addPrimaryReference(program, instr.getAddress(), target, isCall ? RefType.CALL_OVERRIDE_UNCONDITIONAL : RefType.JUMP_OVERRIDE_UNCONDITIONAL);
        disassemble.add(target);
        if (isCall) {
            functions.add(target);
        }
    }

    // ponytail: backward scan of the fall-through chain only, SymbolicPropogator if bank values come from memory or other blocks
    private static Integer findBank(Program program, Instruction instr, BankRegister register) {
        var a = program.getRegister("A");
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var cur = instr;
        var writeFound = false;
        for (int i = 0; i < SCAN_LIMIT; i++) {
            // another path may reach cur with a different bank or A
            if (refs.hasReferencesTo(cur.getAddress())) {
                return null;
            }
            var prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) || prev.getFlowType().isCall()) {
                return null;
            }
            for (var op : prev.getPcode()) {
                if (!writeFound) {
                    var written = addressWrittenFrom(op, a);
                    if (written != null && register.contains(written)) {
                        writeFound = true;
                    }
                } else if (op.getOutput() != null && overlaps(op.getOutput(), a)) {
                    if (op.getOpcode() == PcodeOp.COPY && op.getInput(0).isConstant()) {
                        return register.bank((int) op.getInput(0).getOffset());
                    }
                    return null;
                }
            }
            cur = prev;
        }
        return null;
    }

    // LD (nn),A is a STORE through a constant or a COPY into a memory varnode
    private static Long addressWrittenFrom(PcodeOp op, ghidra.program.model.lang.Register register) {
        if (op.getOpcode() == PcodeOp.STORE && op.getInput(1).isConstant() && isRegister(op.getInput(2), register)) {
            return op.getInput(1).getOffset();
        }
        if (op.getOpcode() == PcodeOp.COPY && op.getOutput() != null && op.getOutput().isAddress() && isRegister(op.getInput(0), register)) {
            return op.getOutput().getOffset();
        }
        return null;
    }

    private static boolean isRegister(Varnode varnode, ghidra.program.model.lang.Register register) {
        return varnode.isRegister() && varnode.getAddress().equals(register.getAddress()) && varnode.getSize() == register.getMinimumByteSize();
    }

    private static boolean overlaps(Varnode varnode, ghidra.program.model.lang.Register register) {
        var start = varnode.getAddress();
        var reg = register.getAddress();
        return varnode.isRegister() && start.getAddressSpace().equals(reg.getAddressSpace())
                && start.getOffset() <= reg.getOffset() && reg.getOffset() < start.getOffset() + varnode.getSize();
    }

    private static void farCall(Program program, Instruction instr, AddressSet disassemble, AddressSet functions, TaskMonitor monitor, MessageLog log) {
        var data = instr.getMaxAddress().next();
        var bytes = new byte[3];
        try {
            if (data == null || program.getMemory().getBytes(data, bytes) != 3) {
                return;
            }
        } catch (MemoryAccessException e) {
            return;
        }
        var resume = data.add(3);
        instr.setFallThrough(resume);
        new ClearFlowAndRepairCmd(data, false, false, true).applyTo(program, monitor);
        createData(program, data, WordDataType.dataType, log);
        createData(program, data.add(2), ByteDataType.dataType, log);
        disassemble.add(resume);

        var target = romAddress(program, instr.getAddress(), bytes[2] & 0xff, (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8));
        if (target != null) {
            addPrimaryReference(program, instr.getAddress(), target, RefType.CALL_OVERRIDE_UNCONDITIONAL);
            disassemble.add(target);
            functions.add(target);
        }
    }

    private static void jumpTable(Program program, Instruction instr, AddressSet disassemble, TaskMonitor monitor, MessageLog log) {
        var table = instr.getMaxAddress().next();
        if (table == null) {
            return;
        }
        var targets = tableTargets(program, instr.getAddress(), table);
        if (targets.isEmpty()) {
            return;
        }
        instr.setFlowOverride(FlowOverride.CALL_RETURN);
        markTable(program, instr.getAddress(), table, targets, disassemble, monitor, log);
    }

    static List<Address> tableTargets(Program program, Address from, Address table) {
        var memory = program.getMemory();
        var refs = program.getReferenceManager();
        var targets = new ArrayList<Address>();
        var tableEnd = Long.MAX_VALUE;
        for (int i = 0; i < MAX_TABLE_ENTRIES; i++) {
            Address entry;
            int word;
            try {
                entry = table.addNoWrap(2L * i);
                word = memory.getShort(entry) & 0xffff;
            } catch (Exception e) {
                break;
            }
            // stop at code a previous entry points into, or at referenced addresses
            if (entry.getOffset() + 1 >= tableEnd || (i > 0 && refs.hasReferencesTo(entry))) {
                break;
            }
            var target = sameBankAddress(program, from, word);
            if (target == null) {
                break;
            }
            if (target.getAddressSpace().equals(table.getAddressSpace()) && target.getOffset() > table.getOffset()) {
                tableEnd = Math.min(tableEnd, target.getOffset());
            }
            targets.add(target);
        }
        return targets;
    }

    static void markTable(Program program, Address from, Address table, List<Address> targets, AddressSet disassemble, TaskMonitor monitor, MessageLog log) {
        var refs = program.getReferenceManager();
        new ClearFlowAndRepairCmd(table, false, false, true).applyTo(program, monitor);
        for (int i = 0; i < targets.size(); i++) {
            createData(program, table.add(2L * i), WordDataType.dataType, log);
            refs.addMemoryReference(from, targets.get(i), RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
            disassemble.add(targets.get(i));
        }
    }

    private static void createData(Program program, Address address, DataType type, MessageLog log) {
        try {
            DataUtilities.createData(program, address, type, -1, false, DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        } catch (CodeUnitInsertionException e) {
            log.appendMsg(NAME, "Could not create data at " + address + ": " + e.getMessage());
        }
    }

    private static void addPrimaryReference(Program program, Address from, Address to, RefType type) {
        var refs = program.getReferenceManager();
        Reference ref = refs.addMemoryReference(from, to, type, SourceType.ANALYSIS, 0);
        refs.setPrimary(ref, true);
    }

    // offset in the caller's bank: home area in the default space, banked area in the caller's overlay
    static Address sameBankAddress(Program program, Address from, int offset) {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        if (offset < 0x4000) {
            return space.getAddress(offset);
        }
        if (offset >= 0x8000) {
            return null;
        }
        var fromSpace = from.getAddressSpace();
        if (fromSpace.isOverlaySpace()) {
            return fromSpace.getAddress(offset);
        }
        // unbanked ROM maps 0x4000-0x7FFF in the default space
        var address = space.getAddress(offset);
        return program.getMemory().contains(address) ? address : null;
    }

    private static Address romAddress(Program program, Address from, int bank, int offset) {
        if (offset < 0x4000 || offset >= 0x8000) {
            return sameBankAddress(program, from, offset);
        }
        var block = program.getMemory().getBlock("rom" + bank);
        if (block == null || !block.isOverlay()) {
            return null;
        }
        return block.getStart().getAddressSpace().getAddress(offset);
    }
}
