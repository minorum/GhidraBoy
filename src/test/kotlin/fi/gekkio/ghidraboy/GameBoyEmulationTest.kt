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
package fi.gekkio.ghidraboy

import ghidra.pcode.emu.PcodeEmulationCallbacks
import ghidra.pcode.emu.PcodeThread
import ghidra.pcode.exec.PcodeArithmetic.Purpose
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class GameBoyEmulationTest : IntegrationTest() {
    private fun GameBoyEmulation.Emulator.load(vararg code: Int): PcodeThread<ByteArray> {
        sharedState.setVar(address(0), code.size, true, code.map { it.toByte() }.toByteArray())
        return newThread().apply { overrideCounter(address(0)) }
    }

    private fun PcodeThread<ByteArray>.register(name: String): Long =
        arithmetic.toLong(state.getVar(language.getRegister(name), Reason.INSPECT), Purpose.INSPECT)

    @Test
    fun `SM83 userops execute`() {
        val emulator = GameBoyEmulation.Emulator(language, PcodeEmulationCallbacks.none())
        // DI, EI, HALT, STOP
        val thread = emulator.load(0xf3, 0xfb, 0x76, 0x10, 0x00)
        repeat(4) { thread.stepInstruction() }
        assertEquals(address(5), thread.counter)
    }

    @Test
    fun `bank register writes swap the ROM window`() {
        val banks = mutableListOf<Int>()
        val switching =
            GameBoyEmulation.BankSwitching(BankRegister.of(0x19)) { bank ->
                banks += bank
                ByteArray(0x4000) { bank.toByte() }
            }
        val emulator = GameBoyEmulation.Emulator(language, switching)
        // LD A,(0x4000); LD B,A; LD A,3; LD (0x2000),A; LD A,(0x4000)
        val thread = emulator.load(0xfa, 0x00, 0x40, 0x47, 0x3e, 0x03, 0xea, 0x00, 0x20, 0xfa, 0x00, 0x40)
        repeat(5) { thread.stepInstruction() }
        assertEquals(1L, thread.register("B"))
        assertEquals(3L, thread.register("A"))
        assertEquals(listOf(1, 3), banks)
    }

    @Test
    fun `bank register decoding`() {
        val mbc1 = BankRegister.of(0x01)
        assertEquals(1, mbc1.bank(0x00))
        assertEquals(0x1f, mbc1.bank(0xff))
        assertTrue(mbc1.contains(0x3fff))
        val mbc2 = BankRegister.of(0x05)
        assertTrue(mbc2.contains(0x2100))
        assertFalse(mbc2.contains(0x2000))
        assertEquals(0, BankRegister.of(0x19).bank(0x00))
        assertFalse(BankRegister.of(0x19).contains(0x3000))
        assertNull(BankRegister.of(0x00))
    }
}
