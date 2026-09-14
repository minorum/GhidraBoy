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

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class GameBoyUnownedCodeAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy Unowned Code";

    private static final int MAX_PASSES = 10;

    public GameBoyUnownedCodeAnalyzer() {
        super(NAME, "Extends function bodies to code added later outside any function but entered from them", AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "SM83".equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        var functions = program.getFunctionManager();
        var unowned = new ArrayList<Instruction>();
        for (var instr : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            if (functions.getFunctionContaining(instr.getAddress()) == null) {
                unowned.add(instr);
            }
        }
        // code entered only from other unowned code joins once its entry does
        for (int pass = 0; pass < MAX_PASSES && !unowned.isEmpty(); pass++) {
            var owners = new LinkedHashSet<Function>();
            for (var instr : unowned) {
                owners.addAll(enteringFunctions(program, instr.getAddress()));
            }
            fixupBodies(program, owners, monitor);
            var before = unowned.size();
            unowned.removeIf(instr -> functions.getFunctionContaining(instr.getAddress()) != null);
            if (unowned.size() == before) {
                break;
            }
        }
        for (var instr : unowned) {
            monitor.checkCancelled();
            if (functions.getFunctionContaining(instr.getAddress()) == null) {
                bankedTailEntry(program, instr.getAddress(), monitor);
            }
        }
        return true;
    }

    // home code entered only by jumps from banked functions: those jumps are tail calls
    private static void bankedTailEntry(Program program, Address address, TaskMonitor monitor) throws CancelledException {
        var listing = program.getListing();
        var functions = program.getFunctionManager();
        var prev = listing.getInstructionBefore(address);
        if (address.getAddressSpace().isOverlaySpace() || (prev != null && address.equals(prev.getFallThrough()))) {
            return;
        }
        var jumps = new ArrayList<Instruction>();
        for (var ref : program.getReferenceManager().getReferencesTo(address)) {
            var from = listing.getInstructionAt(ref.getFromAddress());
            var type = ref.getReferenceType();
            // direct jumps only: an override on a computed jump would drop its other cases
            if (from == null || !type.isJump() || type.isComputed() || !from.getAddress().getAddressSpace().isOverlaySpace()
                    || functions.getFunctionContaining(from.getAddress()) == null) {
                return;
            }
            jumps.add(from);
        }
        if (jumps.isEmpty()) {
            return;
        }
        var body = ownBody(program, address, null, monitor);
        try {
            functions.createFunction(null, address, body, SourceType.ANALYSIS);
        } catch (InvalidInputException | OverlappingFunctionException e) {
            return;
        }
        jumps.forEach(jump -> jump.setFlowOverride(FlowOverride.CALL_RETURN));
    }

    // flow body from entry without code other functions own
    private static AddressSet ownBody(Program program, Address entry, Function function, TaskMonitor monitor) throws CancelledException {
        var body = new AddressSet(CreateFunctionCmd.getFunctionBody(program, entry, false, monitor));
        for (var it = program.getFunctionManager().getFunctionsOverlapping(body); it.hasNext();) {
            var other = it.next();
            if (!other.equals(function)) {
                body.delete(other.getBody());
            }
        }
        return body;
    }

    // functions reaching address by a jump or fall-through
    static Set<Function> enteringFunctions(Program program, Address address) {
        var functions = program.getFunctionManager();
        var result = new LinkedHashSet<Function>();
        for (var ref : program.getReferenceManager().getReferencesTo(address)) {
            var type = ref.getReferenceType();
            var from = functions.getFunctionContaining(ref.getFromAddress());
            if (type.isFlow() && !type.isCall() && from != null) {
                result.add(from);
            }
        }
        var prev = program.getListing().getInstructionBefore(address);
        if (prev != null && address.equals(prev.getFallThrough())) {
            var from = functions.getFunctionContaining(prev.getAddress());
            if (from != null) {
                result.add(from);
            }
        }
        return result;
    }

    // recomputed bodies never take code from other functions
    static void fixupBodies(Program program, Iterable<Function> functions, TaskMonitor monitor) throws CancelledException {
        for (var function : functions) {
            monitor.checkCancelled();
            var body = ownBody(program, function.getEntryPoint(), function, monitor);
            if (!body.contains(function.getEntryPoint()) || body.equals(function.getBody())) {
                continue;
            }
            try {
                function.setBody(body);
            } catch (OverlappingFunctionException e) {
                // keep the old body
            }
        }
    }
}
