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
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongPredicate;

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
        var banks = BankRegister.romBanks(program);
        var candidates = new ArrayList<Address>();
        var disassemble = new AddressSet();
        var functions = new AddressSet();
        for (var instr : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            codeCopy(program, instr, disassemble, functions, log);
            var flowType = instr.getFlowType();
            if ((flowType.isCall() || flowType.isJump()) && instr.getFlows().length == 1) {
                candidates.add(instr.getAddress());
            }
        }

        for (var address : candidates) {
            monitor.checkCancelled();
            // earlier fixups may have cleared it
            var instr = program.getListing().getInstructionAt(address);
            if (instr == null || instr.getFlows().length != 1 || hasOwnReference(program, address)) {
                continue;
            }
            var isCall = instr.getFlowType().isCall();
            var target = instr.getFlows()[0].getOffset();
            var copy = target >= 0xc000 ? copiedCode(program, target) : null;
            // branches inside a copied routine stay ordinary flow
            if (copy != null && copy.getAddressSpace().equals(instr.getAddress().getAddressSpace())) {
                continue;
            }
            if (isCall && farCallDispatchers.contains(target)) {
                farCall(program, instr, banks, disassemble, functions, monitor, log);
            } else if (isCall && jumpTableDispatchers.contains(target)) {
                jumpTable(program, instr, disassemble, monitor, log);
            } else if (trackWrites && register != null && target >= 0x4000 && target < 0x8000) {
                bankSwitch(program, instr, register, banks, disassemble, functions);
            } else if (copy != null) {
                callInto(program, instr, copy, disassemble, functions);
            } else if (!isCall && inUninitializedCode(program, instr.getFlows()[0])) {
                // routines copied to RAM at runtime: the decompiler cannot branch into memory without instructions
                instr.setFlowOverride(FlowOverride.CALL_RETURN);
                functions.add(instr.getFlows()[0]);
            }
        }

        if (!disassemble.isEmpty()) {
            retryConflicts(program, disassemble);
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

    // targets that failed to disassemble over code a later fixup cleared
    private static void retryConflicts(Program program, AddressSet disassemble) {
        var bookmarks = program.getBookmarkManager();
        var listing = program.getListing();
        var stale = new ArrayList<Bookmark>();
        for (var it = bookmarks.getBookmarksIterator(BookmarkType.ERROR); it.hasNext();) {
            var bookmark = it.next();
            var at = bookmark.getAddress();
            if ("Bad Instruction".equals(bookmark.getCategory()) && listing.isUndefined(at, at) && hasOwnReferenceTo(program, at)) {
                stale.add(bookmark);
                disassemble.add(at);
            }
        }
        stale.forEach(bookmarks::removeBookmark);
    }

    private static boolean hasOwnReferenceTo(Program program, Address to) {
        for (var ref : program.getReferenceManager().getReferencesTo(to)) {
            if (ref.getSource() == SourceType.ANALYSIS && (ref.getReferenceType().isOverride() || ref.getReferenceType() == RefType.COMPUTED_JUMP)) {
                return true;
            }
        }
        return false;
    }

    private static boolean inUninitializedCode(Program program, Address address) {
        var block = program.getMemory().getBlock(address);
        return block != null && block.isExecute() && !block.isInitialized();
    }

    private static boolean hasOwnReference(Program program, Address from) {
        for (var ref : program.getReferenceManager().getReferencesFrom(from)) {
            if (ref.getSource() == SourceType.ANALYSIS && (ref.getReferenceType().isOverride() || ref.getReferenceType() == RefType.COMPUTED_JUMP)) {
                return true;
            }
        }
        return false;
    }

    private static void bankSwitch(Program program, Instruction instr, BankRegister register, int banks, AddressSet disassemble, AddressSet functions) {
        if (instr.getAddress().getAddressSpace().isOverlaySpace()) {
            return;
        }
        var bank = findBank(program, instr, register, banks);
        if (bank == null) {
            return;
        }
        var target = romAddress(program, instr.getAddress(), bank, (int) instr.getFlows()[0].getOffset(), banks);
        if (target == null) {
            return;
        }
        callInto(program, instr, target, disassemble, functions);
    }

    private static void callInto(Program program, Instruction instr, Address target, AddressSet disassemble, AddressSet functions) {
        // a far JP is a tail call: the decompiler cannot branch into another address space
        if (!instr.getFlowType().isCall()) {
            instr.setFlowOverride(FlowOverride.CALL_RETURN);
        }
        addPrimaryReference(program, instr.getAddress(), target, RefType.CALL_OVERRIDE_UNCONDITIONAL);
        // the default-space flow error no longer applies
        var bookmarks = program.getBookmarkManager();
        for (var bookmark : bookmarks.getBookmarks(instr.getAddress())) {
            if (bookmark.getComment().contains("non-existing memory")) {
                bookmarks.removeBookmark(bookmark);
            }
        }
        disassemble.add(target);
        functions.add(target);
    }

    // LD A,(HL+); LD (DE),A; INC DE; then DEC C; JR NZ or DEC BC; LD A,C/B; OR B/C; JR NZ
    private static final byte[] COPY_BODY = {0x2a, 0x12, 0x13};
    private static final byte[] COUNT_C = {0x0d, 0x20, (byte) 0xfa};
    private static final byte[][] COUNT_BC = {{0x0b, 0x79, (byte) 0xb0, 0x20, (byte) 0xf8}, {0x0b, 0x78, (byte) 0xb1, 0x20, (byte) 0xf8}};

    // ROM routines copied to WRAM or HRAM by a constant HL -> DE loop, inline or called
    private static void codeCopy(Program program, Instruction instr, AddressSet disassemble, AddressSet functions, MessageLog log) {
        var flowType = instr.getFlowType();
        var isCall = flowType.isCall() && !flowType.isConditional() && instr.getFlows().length == 1;
        var loop = isCall ? instr.getFlows()[0] : instr.getAddress();
        var bytes = new byte[8];
        try {
            if (program.getMemory().getBytes(loop, bytes) < 6) {
                return;
            }
        } catch (MemoryAccessException e) {
            return;
        }
        if (!Arrays.equals(bytes, 0, 3, COPY_BODY, 0, 3)) {
            return;
        }
        var byC = Arrays.equals(bytes, 3, 6, COUNT_C, 0, 3);
        if (!byC && !Arrays.equals(bytes, 3, 8, COUNT_BC[0], 0, 5) && !Arrays.equals(bytes, 3, 8, COUNT_BC[1], 0, 5)) {
            return;
        }
        var values = loads(program, instr, loop, loop.add(byC ? 5 : 7));
        var hl = values.get("HL");
        var de = values.get("DE");
        var b = values.get("B");
        var c = values.get("C");
        if (hl == null || de == null || c == null || (!byC && b == null)) {
            return;
        }
        var length = byC ? (c == 0 ? 0x100 : c) : b << 8 | c;
        var hram = de >= 0xff80 && de + length <= 0xffff;
        if (length == 0 || !hram && !(de >= 0xc000 && de + length <= 0xe000) || hl + length > (hl < 0x4000 ? 0x4000 : 0x8000)) {
            return;
        }
        var source = sameBankAddress(program, instr.getAddress(), hl);
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(de);
        var memory = program.getMemory();
        var sourceBlock = source == null ? null : memory.getBlock(source);
        if (sourceBlock == null || !sourceBlock.isInitialized() || sourceBlock.getName().contains("_code_") || overlapsCopiedCode(program, de, length)) {
            return;
        }
        try {
            var block = memory.createByteMappedBlock((hram ? "hram" : "wram") + "_code_" + Integer.toHexString(de), start, source, length, true);
            block.setPermissions(true, false, true);
            block.setComment("Code copied from " + source);
        } catch (LockException | MemoryConflictException | AddressOverflowException | IllegalArgumentException e) {
            log.appendMsg(NAME, "Could not map code copied to " + start + ": " + e.getMessage());
            return;
        }
        // calls and jumps seen before the copy
        var refs = program.getReferenceManager();
        var sites = new ArrayList<Address>();
        for (var to : refs.getReferenceDestinationIterator(new AddressSet(start, start.add(length - 1)), true)) {
            for (var ref : refs.getReferencesTo(to)) {
                if (ref.getReferenceType().isFlow()) {
                    sites.add(ref.getFromAddress());
                }
            }
        }
        for (var site : sites) {
            var from = program.getListing().getInstructionAt(site);
            if (from != null && from.getFlows().length == 1 && !hasOwnReference(program, site)) {
                callInto(program, from, copiedCode(program, from.getFlows()[0].getOffset()), disassemble, functions);
            }
        }
    }

    // constant HL, DE, B and C loaded before start in its fall-through chain; null when written otherwise
    private static Map<String, Integer> loads(Program program, Instruction start, Address loopStart, Address loopEnd) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var values = new HashMap<String, Integer>();
        var cur = start;
        for (int i = 0; i < SCAN_LIMIT && values.size() < 4; i++) {
            // another path may reach cur with other values
            for (var ref : refs.getReferencesTo(cur.getAddress())) {
                var from = ref.getFromAddress();
                if (!from.getAddressSpace().equals(loopStart.getAddressSpace()) || from.compareTo(loopStart) < 0 || from.compareTo(loopEnd) > 0) {
                    return values;
                }
            }
            var prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) || prev.getFlowType().isCall()) {
                return values;
            }
            int op;
            int word;
            try {
                op = prev.getByte(0) & 0xff;
                word = prev.getLength() == 3 ? (prev.getByte(1) & 0xff) | (prev.getByte(2) & 0xff) << 8 : prev.getLength() == 2 ? prev.getByte(1) & 0xff : 0;
            } catch (MemoryAccessException e) {
                return values;
            }
            for (var name : List.of("HL", "DE", "B", "C")) {
                if (values.containsKey(name) || !GameBoyJumpTableAnalyzer.writes(prev, program.getRegister(name))) {
                    continue;
                }
                values.put(name, switch (name) {
                    case "HL" -> op == 0x21 ? word : null;
                    case "DE" -> op == 0x11 ? word : null;
                    case "B" -> op == 0x01 ? word >> 8 : op == 0x06 ? word : null;
                    default -> op == 0x01 ? word & 0xff : op == 0x0e ? word : null;
                });
            }
            cur = prev;
        }
        return values;
    }

    // any copied routine mapped over [offset, offset + length)
    private static boolean overlapsCopiedCode(Program program, long offset, int length) {
        for (var block : program.getMemory().getBlocks()) {
            if (block.isOverlay() && block.isMapped() && block.getName().contains("_code_")
                    && block.getStart().getOffset() < offset + length && offset <= block.getEnd().getOffset()) {
                return true;
            }
        }
        return false;
    }

    // overlay address of a copied routine covering a default-space RAM offset
    private static Address copiedCode(Program program, long offset) {
        for (var block : program.getMemory().getBlocks()) {
            if (block.isOverlay() && block.isMapped() && block.getName().contains("_code_")
                    && block.getStart().getOffset() <= offset && offset <= block.getEnd().getOffset()) {
                return block.getStart().getAddressSpace().getAddress(offset);
            }
        }
        return null;
    }

    private static Integer findBank(Program program, Instruction instr, BankRegister register, int banks) {
        var low = lastWrite(program, instr, address -> register.contains(address) && !register.containsHigh(address));
        if (low == null || low.value() == null) {
            return null;
        }
        var bank = register.apply(0, low.address(), low.value());
        // upper bits wrap away on ROMs the low register covers
        if (banks > register.mask() + 1) {
            var high = lastWrite(program, instr, register::containsHigh);
            if (high != null) {
                if (high.value() == null) {
                    return null;
                }
                bank = register.apply(bank, high.address(), high.value());
            }
        }
        // unseen upper bits stay 0
        return bank;
    }

    // value is null when A is not a constant
    record Write(long address, Integer value) {
    }

    // ponytail: backward scan of the fall-through chain only, SymbolicPropogator if values come from memory or other blocks
    static Write lastWrite(Program program, Instruction instr, LongPredicate target) {
        var a = program.getRegister("A");
        var sp = program.getRegister("SP");
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var cur = instr;
        Long pending = null;
        for (int i = 0; i < SCAN_LIMIT; i++) {
            // another path may reach cur with a different A
            if (refs.hasReferencesTo(cur.getAddress())) {
                break;
            }
            var prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !cur.getAddress().equals(prev.getFallThrough())) {
                break;
            }
            if (prev.getFlowType().isCall()) {
                var helper = pending == null ? helperWrite(program, prev, target) : null;
                if (helper == null) {
                    break;
                }
                if (helper == HelperWrite.NONE) {
                    cur = prev;
                    continue;
                }
                if (!helper.entryA()) {
                    return new Write(helper.address(), helper.value());
                }
                pending = helper.address();
                cur = prev;
                continue;
            }
            var constants = new HashMap<Varnode, Long>();
            var copiesOfA = new HashSet<Varnode>();
            for (var op : prev.getPcode()) {
                if (pending == null) {
                    // ponytail: indirect stores end the scan, track HL/C constants if games switch banks through them
                    if (op.getOpcode() == PcodeOp.STORE && constant(op.getInput(1), constants) == null && !isRegister(op.getInput(1), sp)) {
                        return new Write(-1, null);
                    }
                    var written = addressWrittenFrom(program, op, a, constants, copiesOfA);
                    if (written != null && target.test(written)) {
                        pending = written;
                    }
                } else if (op.getOutput() != null && overlaps(op.getOutput(), a)) {
                    var constant = op.getOpcode() == PcodeOp.COPY && op.getInput(0).isConstant();
                    return new Write(pending, constant ? (int) op.getInput(0).getOffset() : null);
                }
                fold(op, constants, copiesOfA, a);
            }
            cur = prev;
        }
        return pending == null ? null : new Write(pending, null);
    }

    // last register write a called helper makes; entryA when it writes the caller's A
    record HelperWrite(long address, Integer value, boolean entryA) {
        // helper returns without writing the register
        static final HelperWrite NONE = new HelperWrite(-1, null, false);
    }

    // ponytail: straight-line helpers only, no calls or conditional branches inside
    private static HelperWrite helperWrite(Program program, Instruction call, LongPredicate target) {
        if (call.getFlows().length != 1) {
            return null;
        }
        var a = program.getRegister("A");
        var sp = program.getRegister("SP");
        var listing = program.getListing();
        var cur = listing.getInstructionAt(call.getFlows()[0]);
        Integer value = null;
        var entryA = true;
        HelperWrite result = null;
        for (int i = 0; cur != null && i < SCAN_LIMIT; i++) {
            var flow = cur.getFlowType();
            if (flow.isCall() || flow.isConditional() || flow.isComputed()) {
                return null;
            }
            var constants = new HashMap<Varnode, Long>();
            var copiesOfA = new HashSet<Varnode>();
            for (var op : cur.getPcode()) {
                if (op.getOpcode() == PcodeOp.STORE && constant(op.getInput(1), constants) == null && !isRegister(op.getInput(1), sp)) {
                    return null;
                }
                var written = addressWrittenFrom(program, op, a, constants, copiesOfA);
                if (written != null && target.test(written)) {
                    result = new HelperWrite(written, value, entryA);
                }
                if (op.getOutput() != null && overlaps(op.getOutput(), a)) {
                    entryA = false;
                    value = op.getOpcode() == PcodeOp.COPY && op.getInput(0).isConstant() ? Integer.valueOf((int) op.getInput(0).getOffset()) : null;
                }
                fold(op, constants, copiesOfA, a);
            }
            if (flow.isTerminal()) {
                return result != null ? result : HelperWrite.NONE;
            }
            var next = flow.isJump() ? cur.getFlows()[0] : cur.getFallThrough();
            if (next == null) {
                return null;
            }
            cur = listing.getInstructionAt(next);
        }
        return null;
    }

    // constant temporaries such as LDH's 0xff00 | zext(n), and copies of A
    private static void fold(PcodeOp op, Map<Varnode, Long> constants, Set<Varnode> copiesOfA, ghidra.program.model.lang.Register a) {
        var out = op.getOutput();
        if (out == null || !out.isUnique()) {
            return;
        }
        constants.remove(out);
        copiesOfA.remove(out);
        if (op.getOpcode() == PcodeOp.COPY && isRegister(op.getInput(0), a)) {
            copiesOfA.add(out);
            return;
        }
        var inputs = new long[op.getNumInputs()];
        for (int i = 0; i < inputs.length; i++) {
            var value = constant(op.getInput(i), constants);
            if (value == null) {
                return;
            }
            inputs[i] = value;
        }
        switch (op.getOpcode()) {
            case PcodeOp.COPY, PcodeOp.INT_ZEXT -> constants.put(out, inputs[0]);
            case PcodeOp.INT_OR -> constants.put(out, inputs[0] | inputs[1]);
            case PcodeOp.INT_ADD -> constants.put(out, inputs[0] + inputs[1]);
            default -> {
            }
        }
    }

    private static Long constant(Varnode varnode, Map<Varnode, Long> constants) {
        return varnode.isConstant() ? Long.valueOf(varnode.getOffset()) : constants.get(varnode);
    }

    // LD (nn),A and LDH (n),A are a STORE through a constant, a COPY into a memory varnode, or mbc_write(nn, A)
    private static Long addressWrittenFrom(Program program, PcodeOp op, ghidra.program.model.lang.Register register, Map<Varnode, Long> constants, Set<Varnode> copiesOfA) {
        if (op.getOpcode() == PcodeOp.STORE && (isRegister(op.getInput(2), register) || copiesOfA.contains(op.getInput(2)))) {
            return constant(op.getInput(1), constants);
        }
        if (op.getOpcode() == PcodeOp.CALLOTHER && op.getNumInputs() == 3
                && "mbc_write".equals(program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset()))
                && (isRegister(op.getInput(2), register) || copiesOfA.contains(op.getInput(2)))) {
            return constant(op.getInput(1), constants);
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

    private static void farCall(Program program, Instruction instr, int banks, AddressSet disassemble, AddressSet functions, TaskMonitor monitor, MessageLog log) {
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

        var target = romAddress(program, instr.getAddress(), bytes[2] & 0xff, (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8), banks);
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
        var targets = tableTargets(program, instr.getAddress(), table, indexBound(program, instr));
        if (targets.isEmpty()) {
            return;
        }
        instr.setFlowOverride(FlowOverride.CALL_RETURN);
        markTable(program, instr.getAddress(), table, targets, disassemble, monitor, log);
    }

    // entries allowed by AND n (n + 1 a power of two) or CP n; RET/JR/JP NC falling through into the dispatcher call
    static int indexBound(Program program, Instruction call) {
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var a = program.getRegister("A");
        var cur = call;
        try {
            for (int i = 0; i < SCAN_LIMIT; i++) {
                if (refs.hasReferencesTo(cur.getAddress())) {
                    break;
                }
                var prev = listing.getInstructionBefore(cur.getAddress());
                if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) || prev.getFlowType().isCall()) {
                    break;
                }
                var op = prev.getByte(0) & 0xff;
                if (op == 0xe6) {
                    var n = prev.getByte(1) & 0xff;
                    return Integer.bitCount(n + 1) == 1 ? n + 1 : MAX_TABLE_ENTRIES;
                }
                if (op == 0xd0 || op == 0x30 || op == 0xd2) {
                    var cp = listing.getInstructionBefore(prev.getAddress());
                    if (cp != null && prev.getAddress().equals(cp.getFallThrough()) && !refs.hasReferencesTo(prev.getAddress())
                            && (cp.getByte(0) & 0xff) == 0xfe && cp.getByte(1) != 0) {
                        return cp.getByte(1) & 0xff;
                    }
                }
                for (var pcode : prev.getPcode()) {
                    if (pcode.getOutput() != null && overlaps(pcode.getOutput(), a)) {
                        return MAX_TABLE_ENTRIES;
                    }
                }
                cur = prev;
            }
        } catch (MemoryAccessException e) {
            return MAX_TABLE_ENTRIES;
        }
        return MAX_TABLE_ENTRIES;
    }

    static List<Address> tableTargets(Program program, Address from, Address table) {
        return tableTargets(program, from, table, MAX_TABLE_ENTRIES);
    }

    static List<Address> tableTargets(Program program, Address from, Address table, int limit) {
        var memory = program.getMemory();
        var refs = program.getReferenceManager();
        var targets = new ArrayList<Address>();
        var overlaps = new ArrayList<Long>();
        var tableEnd = Long.MAX_VALUE;
        for (int i = 0; i < limit; i++) {
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
            // tables end before words into the middle of known code
            var code = program.getListing().getInstructionContaining(target);
            Long overlap = null;
            if (code != null && !code.getAddress().equals(target)) {
                if (!inFallThrough(program, from, code.getAddress())) {
                    break;
                }
                overlap = code.getAddress().getOffset();
            }
            if (target.getAddressSpace().equals(table.getAddressSpace()) && target.getOffset() > table.getOffset()) {
                tableEnd = Math.min(tableEnd, target.getOffset());
            }
            targets.add(target);
            overlaps.add(overlap);
        }
        // unless the index bound confirms every entry, fall-through code under a target must start inside the table
        for (int i = 0; i < targets.size() && targets.size() < limit; i++) {
            var start = overlaps.get(i);
            if (start != null && start >= table.getOffset() + 2L * targets.size()) {
                targets.subList(i, targets.size()).clear();
                i = -1;
            }
        }
        return targets;
    }

    // a dispatcher call's fall-through may be its own table decoded as code
    private static boolean inFallThrough(Program program, Address from, Address code) {
        var listing = program.getListing();
        var cur = listing.getInstructionAt(from);
        for (int i = 0; cur != null && i < 2 * MAX_TABLE_ENTRIES; i++) {
            var next = cur.getFallThrough();
            if (next == null || !next.getAddressSpace().equals(code.getAddressSpace()) || next.compareTo(code) > 0) {
                return false;
            }
            if (next.equals(code)) {
                return true;
            }
            cur = listing.getInstructionAt(next);
        }
        return false;
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

    private static Address romAddress(Program program, Address from, int bank, int offset, int banks) {
        if (offset < 0x4000 || offset >= 0x8000) {
            return sameBankAddress(program, from, offset);
        }
        // MBC wraps bank numbers past the ROM size
        var block = program.getMemory().getBlock("rom" + bank % banks);
        if (block == null || !block.isOverlay()) {
            return null;
        }
        return block.getStart().getAddressSpace().getAddress(offset);
    }
}
