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
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class GameBoyInterruptAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy Interrupt Handlers";
    static final String CONVENTION = "__interrupt";

    public GameBoyInterruptAnalyzer() {
        super(NAME, "Applies the __interrupt calling convention to interrupt vectors and the handlers they jump to", AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
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
            if (function.getSignatureSource() == SourceType.USER_DEFINED || !isHandler(program, function.getEntryPoint())) {
                continue;
            }
            try {
                function.updateFunction(CONVENTION, new ReturnParameterImpl(VoidDataType.dataType, program), List.of(),
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
            } catch (InvalidInputException | DuplicateNameException e) {
                log.appendMsg(NAME, "Could not set " + CONVENTION + " on " + function.getName() + ": " + e.getMessage());
            }
        }
        return true;
    }

    // an interrupt vector, or the target of a jump at one
    private static boolean isHandler(Program program, Address entry) {
        if (!entry.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
            return false;
        }
        if (isVector(entry)) {
            return true;
        }
        for (var ref : program.getReferenceManager().getReferencesTo(entry)) {
            if (ref.getReferenceType().isJump() && isVector(ref.getFromAddress())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isVector(Address address) {
        var offset = address.getOffset();
        return address.getAddressSpace().equals(address.getAddressSpace().getPhysicalSpace())
                && offset >= 0x40 && offset <= 0x60 && offset % 8 == 0;
    }
}
