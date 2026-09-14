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

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.framework.main.AppInfo;
import ghidra.pcode.emu.ComposedPcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.InternalPcodeTraceDataAccess;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

public class GameBoyEmulatorFactory implements EmulatorFactory {
    @Override
    public String getTitle() {
        return "Game Boy (SM83) Emulator";
    }

    @Override
    @SuppressWarnings("unchecked")
    public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
        PcodeEmulationCallbacks<byte[]> callbacks = writer.callbacks();
        if (access.getDataForSharedState() instanceof InternalPcodeTraceDataAccess data) {
            var program = findProgram(data.getPlatform().getTrace(), data.getSnap());
            var register = program != null ? BankRegister.of(program) : null;
            if (register != null) {
                callbacks = new ComposedPcodeEmulationCallbacks<>(callbacks, new GameBoyEmulation.BankSwitching(register, bank -> GameBoyEmulation.bankBytes(program, bank)));
            }
        }
        return new GameBoyEmulation.Emulator(access.getLanguage(), callbacks);
    }

    // the banked program the trace was launched from, through any running tool's mappings
    private static Program findProgram(Trace trace, long snap) {
        var project = AppInfo.getActiveProject();
        if (project == null) {
            return null;
        }
        for (var tool : project.getToolManager().getRunningTools()) {
            var mappings = tool.getService(DebuggerStaticMappingService.class);
            if (mappings == null) {
                continue;
            }
            for (var program : mappings.getOpenMappedProgramsAtSnap(trace, snap)) {
                if (program.getMemory().getBlock("rom1") != null) {
                    return program;
                }
            }
        }
        return null;
    }
}
