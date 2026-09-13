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

import fi.gekkio.ghidraboy.IntegrationTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

// reg0_3/reg3_3 encoding, index 6 is (HL)
private val REGISTERS = listOf("B", "C", "D", "E", "H", "L", null, "A")
private val PAIRS = listOf("BC", "DE", "HL", "SP")
private val STACK_PAIRS = listOf("BC", "DE", "HL", "AF")
private const val FLAGS = 0xb0L

// HL = 0xc123, BC = 0x2233, DE = 0x4455
private val INITIAL =
    mapOf("A" to 0x11L, "B" to 0x22L, "C" to 0x33L, "D" to 0x44L, "E" to 0x55L, "H" to 0xc1L, "L" to 0x23L, "SP" to 0xdffeL)

private fun pairValue(
    pair: String,
    value: Long,
): Map<String, Long> =
    when (pair) {
        "SP" -> mapOf("SP" to value)
        "AF" -> mapOf("A" to (value shr 8), "F" to (value and 0xff))
        else -> mapOf(pair.substring(0, 1) to (value shr 8), pair.substring(1, 2) to (value and 0xff))
    }

class LoadInstructionTest : IntegrationTest() {
    private fun emulator(vararg code: Int): TestEmulator =
        TestEmulator(language).apply {
            write(0x0000u, *code.map { it.toUByte() }.toUByteArray())
            INITIAL.forEach { (name, value) -> writeRegister(name, value) }
            writeRegister("F", FLAGS)
        }

    private fun TestEmulator.assertRegisters(
        pc: Long,
        changes: Map<String, Long> = emptyMap(),
    ) {
        assertEquals(pc, readRegister("PC"), "PC")
        for ((name, value) in INITIAL + mapOf("F" to FLAGS) + changes) {
            assertEquals(value, readRegister(name), name)
        }
    }

    private fun TestEmulator.assertMemory(
        address: Int,
        vararg bytes: Int,
    ) = assertEquals(bytes.map { it.toUByte() }, read(address.toUShort(), bytes.size).toList(), "memory at %04x".format(address))

    @Test
    fun `LD r, r'`() {
        for ((dst, d) in REGISTERS.withIndex()) {
            for ((src, s) in REGISTERS.withIndex()) {
                if (d == null || s == null) continue
                val emulator = emulator(0x40 or (dst shl 3) or src)
                emulator.step()
                emulator.assertRegisters(1, mapOf(d to INITIAL.getValue(s)))
            }
        }
    }

    @Test
    fun `LD r, n`() {
        for ((index, r) in REGISTERS.withIndex()) {
            if (r == null) continue
            val emulator = emulator(0x06 or (index shl 3), 0x9a)
            emulator.step()
            emulator.assertRegisters(2, mapOf(r to 0x9aL))
        }
    }

    @Test
    fun `LD r, (HL)`() {
        for ((index, r) in REGISTERS.withIndex()) {
            if (r == null) continue
            val emulator = emulator(0x46 or (index shl 3))
            emulator.write(0xc123u, 0x9au)
            emulator.step()
            emulator.assertRegisters(1, mapOf(r to 0x9aL))
        }
    }

    @Test
    fun `LD (HL), r`() {
        for ((index, r) in REGISTERS.withIndex()) {
            if (r == null) continue
            val emulator = emulator(0x70 or index)
            emulator.step()
            emulator.assertRegisters(1)
            emulator.assertMemory(0xc123, INITIAL.getValue(r).toInt())
        }
    }

    @Test
    fun `LD (HL), n`() {
        val emulator = emulator(0x36, 0x9a)
        emulator.step()
        emulator.assertRegisters(2)
        emulator.assertMemory(0xc123, 0x9a)
    }

    @Test
    fun `LD A, indirect`() {
        // opcode, operand bytes, address read
        val cases =
            listOf(
                Triple(listOf(0x0a), 0x2233, 1L),
                Triple(listOf(0x1a), 0x4455, 1L),
                Triple(listOf(0xf2), 0xff33, 1L),
                Triple(listOf(0xf0, 0x80), 0xff80, 2L),
                Triple(listOf(0xfa, 0x34, 0x12), 0x1234, 3L),
            )
        for ((code, address, pc) in cases) {
            val emulator = emulator(*code.toIntArray())
            emulator.write(address.toUShort(), 0x9au)
            emulator.step()
            emulator.assertRegisters(pc, mapOf("A" to 0x9aL))
        }
    }

    @Test
    fun `LD indirect, A`() {
        val cases =
            listOf(
                Triple(listOf(0x02), 0x2233, 1L),
                Triple(listOf(0x12), 0x4455, 1L),
                Triple(listOf(0xe2), 0xff33, 1L),
                Triple(listOf(0xe0, 0x80), 0xff80, 2L),
                Triple(listOf(0xea, 0x34, 0x12), 0x1234, 3L),
            )
        for ((code, address, pc) in cases) {
            val emulator = emulator(*code.toIntArray())
            emulator.step()
            emulator.assertRegisters(pc)
            emulator.assertMemory(address, 0x11)
        }
    }

    @Test
    fun `LD with HL increment and decrement`() {
        for ((opcode, l) in listOf(0x2a to 0x24L, 0x3a to 0x22L)) {
            val emulator = emulator(opcode)
            emulator.write(0xc123u, 0x9au)
            emulator.step()
            emulator.assertRegisters(1, mapOf("A" to 0x9aL, "L" to l))
        }
        for ((opcode, l) in listOf(0x22 to 0x24L, 0x32 to 0x22L)) {
            val emulator = emulator(opcode)
            emulator.step()
            emulator.assertRegisters(1, mapOf("L" to l))
            emulator.assertMemory(0xc123, 0x11)
        }
    }

    @Test
    fun `LD rr, nn`() {
        for ((index, pair) in PAIRS.withIndex()) {
            val emulator = emulator(0x01 or (index shl 4), 0xbc, 0x9a)
            emulator.step()
            emulator.assertRegisters(3, pairValue(pair, 0x9abc))
        }
    }

    @Test
    fun `LD (nn), SP`() {
        val emulator = emulator(0x08, 0x34, 0x12)
        emulator.step()
        emulator.assertRegisters(3)
        emulator.assertMemory(0x1234, 0xfe, 0xdf)
    }

    @Test
    fun `LD SP, HL`() {
        val emulator = emulator(0xf9)
        emulator.step()
        emulator.assertRegisters(1, mapOf("SP" to 0xc123L))
    }

    @Test
    fun `INC rr and DEC rr wrap around`() {
        for ((index, pair) in PAIRS.withIndex()) {
            for ((opcode, values) in listOf(
                (0x03 or (index shl 4)) to (0xffffL to 0x0000L),
                (0x0b or (index shl 4)) to (0x0000L to 0xffffL),
            )) {
                val emulator = emulator(opcode)
                emulator.writeRegister(pair, values.first)
                emulator.step()
                emulator.assertRegisters(1, pairValue(pair, values.second))
            }
        }
    }

    @Test
    fun `PUSH rr`() {
        for ((index, pair) in STACK_PAIRS.withIndex()) {
            val emulator = emulator(0xc5 or (index shl 4))
            emulator.step()
            emulator.assertRegisters(1, mapOf("SP" to 0xdffcL))
            val value = emulator.readRegister(pair)
            emulator.assertMemory(0xdffc, (value and 0xff).toInt(), (value shr 8).toInt())
        }
    }

    @Test
    fun `POP rr`() {
        for ((index, pair) in STACK_PAIRS.withIndex()) {
            val emulator = emulator(0xc1 or (index shl 4))
            emulator.write(0xdffeu, 0xffu, 0x9au)
            emulator.step()
            // POP AF clears the low nibble of F
            val popped = if (pair == "AF") 0x9af0L else 0x9affL
            emulator.assertRegisters(1, mapOf("SP" to 0xe000L) + pairValue(pair, popped))
        }
    }
}
