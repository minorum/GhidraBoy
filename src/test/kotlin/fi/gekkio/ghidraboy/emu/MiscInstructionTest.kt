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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MiscInstructionTest : EmuTest() {
    private fun assertStepFails(message: String) {
        val e = assertThrows<Throwable> { emulator.step() }
        assertTrue(generateSequence(e) { it.cause }.any { it.message?.contains(message) == true }, e.toString())
    }

    @Test
    fun `uninitialized register read fails`() {
        emulator.write(0x0000u, 0x3cu)
        assertStepFails("Uninitialized register read")
    }

    @Test
    fun `unregistered userop fails`() {
        emulator.write(0x0000u, 0xf3u)
        assertStepFails("IME")
    }

    @Test
    fun `NOP`() {
        emulator.write(0x0000u, 0x00u)
        emulator.step()
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `DI`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("IME", ignore)
        emulator.write(0x0000u, 0xf3u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `EI`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("IME", ignore)
        emulator.write(0x0000u, 0xfbu)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `HALT`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("halt", ignore)
        emulator.write(0x0000u, 0x76u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `STOP`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("stop", ignore)
        emulator.write(0x0000u, 0x10u, 0x00u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0002u)
    }

    @Test
    fun `DAA`() {
        emulator.write(0x0000u, 0x27u)
        for (a in 0..0xff) {
            for (flagsIn in 0..0xf) {
                val n = (flagsIn and 0x4) != 0
                val h = (flagsIn and 0x2) != 0
                val c = (flagsIn and 0x1) != 0
                var offset = 0
                var carry = c
                val result =
                    if (!n) {
                        if (c || a > 0x99) {
                            offset = 0x60
                            carry = true
                        }
                        if (h || (a and 0xf) > 0x9) offset = offset or 0x06
                        (a + offset) and 0xff
                    } else {
                        if (c) offset = 0x60
                        if (h) offset = offset or 0x06
                        (a - offset) and 0xff
                    }
                val flagsOut = (if (result == 0) 0x80 else 0) or (if (n) 0x40 else 0) or (if (carry) 0x10 else 0)
                emulator.writePC(0x0000u)
                emulator.writeA(a.toUByte())
                emulator.writeF((flagsIn shl 4).toUByte())
                emulator.step()
                val message = "A=%02x F=%02x".format(a, flagsIn shl 4)
                assertEquals(result.toUByte(), emulator.readA(), message)
                assertEquals(flagsOut.toUByte(), emulator.readF(), message)
            }
        }
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `CCF when C=1`() {
        emulator.writeF(0b1111_0000u)
        emulator.write(0x0000u, 0x3fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1000_0000u)
    }

    @Test
    fun `CCF when C=0`() {
        emulator.writeF(0b1110_0000u)
        emulator.write(0x0000u, 0x3fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1001_0000u)
    }

    @Test
    fun `SCF`() {
        emulator.writeF(0b1110_0000u)
        emulator.write(0x0000u, 0x37u)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1001_0000u)
    }

    @Test
    fun `CPL`() {
        emulator.writeF(0b1001_0000u)
        emulator.writeA(0x55u)
        emulator.write(0x0000u, 0x2fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1111_0000u)
        emulator.assertA(0xaau)
    }
}
