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
package fi.gekkio.ghidraboy.emu

import ghidra.pcode.emu.PcodeEmulationCallbacks
import ghidra.pcode.emu.PcodeThread
import ghidra.pcode.exec.PcodeExecutorStatePiece
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.pcode.exec.PcodeFrame
import ghidra.pcode.exec.PcodeUseropLibrary
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.pcode.PcodeOp
import org.junit.jupiter.api.Assertions

class EmulatorCallbacks(
    private val ignoredUserops: Map<String, IgnorePCode>,
) : PcodeEmulationCallbacks<ByteArray> {
    override fun <A, U> readUninitialized(
        thread: PcodeThread<ByteArray>?,
        piece: PcodeExecutorStatePiece<A, U>,
        set: AddressSetView,
        reason: Reason,
    ): AddressSetView {
        // decoder reads ahead; unique temporaries are scratch
        if (reason == Reason.EXECUTE_DECODE || reason == Reason.RE_INIT || set.isEmpty) {
            return set
        }
        val address = set.minAddress
        if (!address.isMemoryAddress && !address.isRegisterAddress) {
            return set
        }
        val size = set.firstRange.length.toInt()
        val pc = thread?.counter
        piece.language.getRegister(address, size)?.let {
            Assertions.fail<Unit>("Uninitialized register read at $pc: $it")
        }
        Assertions.fail<Unit>("Uninitialized memory read at $pc: ${address.toString(true)}:$size")
        return set
    }

    override fun handleMissingUserop(
        thread: PcodeThread<ByteArray>,
        op: PcodeOp,
        frame: PcodeFrame,
        opName: String,
        library: PcodeUseropLibrary<ByteArray>,
    ): Boolean {
        val callback = ignoredUserops[opName] ?: return false
        callback.triggered = true
        return true
    }
}
