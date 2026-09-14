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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GameBoyRamBankAnalyzer extends AbstractAnalyzer {
    static final String NAME = "Game Boy RAM Banks";

    public GameBoyRamBankAnalyzer() {
        super(NAME, "Moves GBC VRAM/WRAM references into the bank selected by a preceding LD A,n and VBK/SVBK write", AnalyzerType.INSTRUCTION_ANALYZER);
        // after constant propagation, which adds default-space references
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        var memory = program.getMemory();
        return "SM83".equals(program.getLanguage().getProcessor().toString())
                && (memory.getBlock("wram2") != null || memory.getBlock("vram1") != null);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        // constant propagation revisits whole function bodies
        var scope = new AddressSet(set);
        var functions = program.getFunctionManager().getFunctionsOverlapping(set);
        while (functions.hasNext()) {
            scope.add(functions.next().getBody());
        }
        for (var instr : program.getListing().getInstructions(scope, true)) {
            monitor.checkCancelled();
            retarget(program, instr);
        }
        return true;
    }

    // SVBK selects WRAM bank 1-7 at 0xD000, VBK selects VRAM bank 0-1
    private static void retarget(Program program, Instruction instr) {
        var refs = program.getReferenceManager();
        var ram = program.getAddressFactory().getDefaultAddressSpace();
        for (var ref : refs.getReferencesFrom(instr.getAddress())) {
            var from = instr.getAddress().getAddressSpace();
            var to = ref.getToAddress().getAddressSpace();
            // code inside a banked overlay references its own bank; other overlays such as copied code are not RAM banks
            if (!ref.isMemoryReference() || ref.getSource() == SourceType.USER_DEFINED || (from.isOverlaySpace() && from.equals(to))
                    || (to.isOverlaySpace() && !to.getName().matches("[vw]ram\\d"))) {
                continue;
            }
            var offset = ref.getToAddress().getOffset();
            String name = null;
            if (offset >= 0xd000 && offset < 0xe000) {
                var svbk = GameBoyBankAnalyzer.lastWrite(program, instr, address -> address == 0xff70);
                if (svbk != null && svbk.value() != null) {
                    name = "wram" + Math.max(svbk.value() & 7, 1);
                }
            } else if (offset >= 0x8000 && offset < 0xa000) {
                var vbk = GameBoyBankAnalyzer.lastWrite(program, instr, address -> address == 0xff4f);
                if (vbk != null && vbk.value() != null) {
                    name = "vram" + (vbk.value() & 1);
                }
            } else {
                continue;
            }
            // WRAM bank 1, VRAM bank 0 and unknown banks are in the default space
            var block = name == null ? null : program.getMemory().getBlock(name);
            var target = block != null && block.isOverlay() ? block.getStart().getAddressSpace().getAddress(offset) : ram.getAddress(offset);
            if (target.equals(ref.getToAddress())) {
                continue;
            }
            refs.delete(ref);
            var bankRef = refs.addMemoryReference(ref.getFromAddress(), target, ref.getReferenceType(), SourceType.ANALYSIS, ref.getOperandIndex());
            if (ref.isPrimary()) {
                refs.setPrimary(bankRef, true);
            }
        }
    }
}
