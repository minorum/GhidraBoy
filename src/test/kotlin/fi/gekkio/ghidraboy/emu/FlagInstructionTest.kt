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
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource

private const val Z_FLAG = 0x80
private const val N_FLAG = 0x40
private const val H_FLAG = 0x20
private const val C_FLAG = 0x10
private const val MEM_ADDRESS: UShort = 0xc000u

private fun flags(
    z: Boolean,
    n: Boolean,
    h: Boolean,
    c: Boolean,
): UByte =
    (
        (if (z) Z_FLAG else 0) or (if (n) N_FLAG else 0) or (if (h) H_FLAG else 0) or
            (if (c) C_FLAG else 0)
    ).toUByte()

// expected (result, carry out) for input value and carry in
typealias ByteOp = (value: Int, carry: Int) -> Pair<Int, Int>

enum class RotateAOp(
    val opcode: UByte,
    val op: ByteOp,
) {
    RLCA(0x07u, { a, _ -> (((a shl 1) or (a shr 7)) and 0xff) to (a shr 7) }),
    RLA(0x17u, { a, c -> (((a shl 1) or c) and 0xff) to (a shr 7) }),
    RRCA(0x0fu, { a, _ -> (((a shr 1) or (a shl 7)) and 0xff) to (a and 1) }),
    RRA(0x1fu, { a, c -> ((a shr 1) or (c shl 7)) to (a and 1) }),
}

enum class ShiftOp(
    val base: Int,
    val op: ByteOp,
) {
    RLC(0x00, { a, _ -> (((a shl 1) or (a shr 7)) and 0xff) to (a shr 7) }),
    RRC(0x08, { a, _ -> (((a shr 1) or (a shl 7)) and 0xff) to (a and 1) }),
    RL(0x10, { a, c -> (((a shl 1) or c) and 0xff) to (a shr 7) }),
    RR(0x18, { a, c -> ((a shr 1) or (c shl 7)) to (a and 1) }),
    SLA(0x20, { a, _ -> ((a shl 1) and 0xff) to (a shr 7) }),
    SRA(0x28, { a, _ -> ((a shr 1) or (a and 0x80)) to (a and 1) }),
    SWAP(0x30, { a, _ -> (((a shl 4) or (a shr 4)) and 0xff) to 0 }),
    SRL(0x38, { a, _ -> (a shr 1) to (a and 1) }),
}

enum class BitOp(
    val base: Int,
) {
    BIT(0x40),
    RES(0x80),
    SET(0xc0),
}

enum class CbOperand(
    val index: Int,
) {
    B(0),
    HL_MEM(6),
}

enum class SpOffsetOp(
    val opcode: UByte,
) {
    LD_HL_SP_E(0xf8u),
    ADD_SP_E(0xe8u),
}

enum class AddHlOp(
    val opcode: UByte,
) {
    BC(0x09u),
    DE(0x19u),
    HL(0x29u),
    SP(0x39u),
}

// expected (A, F) for A, operand and carry in
typealias AluModel = (a: Int, x: Int, c: Int) -> Pair<Int, UByte>

private fun sub(
    a: Int,
    x: Int,
    c: Int,
): Pair<Int, UByte> {
    val result = (a - x - c) and 0xff
    return result to flags(z = result == 0, n = true, h = (a and 0xf) < (x and 0xf) + c, c = a < x + c)
}

enum class AluOp(
    val opcode: UByte,
    val usesCarry: Boolean,
    val model: AluModel,
) {
    ADD(0x80u, false, { a, x, _ ->
        val result = (a + x) and 0xff
        result to flags(z = result == 0, n = false, h = (a and 0xf) + (x and 0xf) > 0xf, c = a + x > 0xff)
    }),
    ADC(0x88u, true, { a, x, c ->
        val result = (a + x + c) and 0xff
        result to flags(z = result == 0, n = false, h = (a and 0xf) + (x and 0xf) + c > 0xf, c = a + x + c > 0xff)
    }),
    SUB(0x90u, false, { a, x, _ -> sub(a, x, 0) }),
    SBC(0x98u, true, { a, x, c -> sub(a, x, c) }),
    AND(0xa0u, false, { a, x, _ -> (a and x) to flags(z = (a and x) == 0, n = false, h = true, c = false) }),
    XOR(0xa8u, false, { a, x, _ -> (a xor x) to flags(z = (a xor x) == 0, n = false, h = false, c = false) }),
    OR(0xb0u, false, { a, x, _ -> (a or x) to flags(z = (a or x) == 0, n = false, h = false, c = false) }),
    CP(0xb8u, false, { a, x, _ -> a to sub(a, x, 0).second }),
}

enum class IncDecOp(
    val opcode: UByte,
) {
    INC_B(0x04u),
    DEC_B(0x05u),
}

private val EDGE_BYTES =
    listOf(0x00, 0x01, 0x06, 0x09, 0x0f, 0x10, 0x55, 0x60, 0x7f, 0x80, 0x8f, 0x99, 0xaa, 0xf0, 0xfe, 0xff)

private val WORD_VALUES =
    listOf(0x0000, 0x0001, 0x00ff, 0x0100, 0x0fff, 0x1000, 0x7fff, 0x8000, 0x8fff, 0xf000, 0xf001, 0xffff, 0x1234, 0xedcb)

class FlagInstructionTest : IntegrationTest() {
    private fun TestEmulator.writeOperand(
        operand: CbOperand,
        value: UByte,
    ) = when (operand) {
        CbOperand.B -> writeB(value)
        CbOperand.HL_MEM -> {
            writeHL(MEM_ADDRESS)
            write(MEM_ADDRESS, value)
        }
    }

    private fun TestEmulator.readOperand(operand: CbOperand): UByte =
        when (operand) {
            CbOperand.B -> readB()
            CbOperand.HL_MEM -> read(MEM_ADDRESS)
        }

    @ParameterizedTest
    @EnumSource
    fun `rotate A`(op: RotateAOp) {
        val emulator = TestEmulator(language)
        emulator.write(0x0000u, op.opcode)
        for (a in 0..0xff) {
            for (c in 0..1) {
                emulator.writePC(0x0000u)
                emulator.writeA(a.toUByte())
                emulator.writeF((Z_FLAG or N_FLAG or H_FLAG or (c shl 4)).toUByte())
                emulator.step()
                val (result, carry) = op.op(a, c)
                val message = "A=%02x C=%d".format(a, c)
                assertEquals(result.toUByte(), emulator.readA(), message)
                assertEquals(flags(z = false, n = false, h = false, c = carry == 1), emulator.readF(), message)
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `CB shift and rotate`(op: ShiftOp) {
        for (operand in CbOperand.entries) {
            val emulator = TestEmulator(language)
            emulator.write(0x0000u, 0xcbu, (op.base or operand.index).toUByte())
            for (value in 0..0xff) {
                for (c in 0..1) {
                    emulator.writePC(0x0000u)
                    emulator.writeOperand(operand, value.toUByte())
                    emulator.writeF((Z_FLAG or N_FLAG or H_FLAG or (c shl 4)).toUByte())
                    emulator.step()
                    val (result, carry) = op.op(value, c)
                    val message = "$operand=%02x C=%d".format(value, c)
                    assertEquals(result.toUByte(), emulator.readOperand(operand), message)
                    assertEquals(flags(z = result == 0, n = false, h = false, c = carry == 1), emulator.readF(), message)
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `CB bit operations`(op: BitOp) {
        for (operand in CbOperand.entries) {
            for (bit in 0..7) {
                val emulator = TestEmulator(language)
                emulator.write(0x0000u, 0xcbu, (op.base or (bit shl 3) or operand.index).toUByte())
                for (value in 0..0xff) {
                    for (flagsIn in listOf(0x00, 0xf0)) {
                        emulator.writePC(0x0000u)
                        emulator.writeOperand(operand, value.toUByte())
                        emulator.writeF(flagsIn.toUByte())
                        emulator.step()
                        val mask = 1 shl bit
                        val message = "bit=$bit $operand=%02x F=%02x".format(value, flagsIn)
                        val (result, flagsOut) =
                            when (op) {
                                BitOp.BIT ->
                                    value to
                                        flags(z = (value and mask) == 0, n = false, h = true, c = (flagsIn and C_FLAG) != 0)
                                BitOp.RES -> (value and mask.inv()) to flagsIn.toUByte()
                                BitOp.SET -> (value or mask) to flagsIn.toUByte()
                            }
                        assertEquals(result.toUByte(), emulator.readOperand(operand), message)
                        assertEquals(flagsOut, emulator.readF(), message)
                    }
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `SP plus signed offset`(op: SpOffsetOp) {
        for (e in 0..0xff) {
            val emulator = TestEmulator(language)
            emulator.write(0x0000u, op.opcode, e.toUByte())
            for (low in 0..0xff) {
                val sp = (((low * 7) and 0xff) shl 8) or low
                emulator.writePC(0x0000u)
                emulator.writeSP(sp.toUShort())
                emulator.writeF(0xf0u)
                emulator.step()
                val result = (sp + e.toByte()) and 0xffff
                val message = "SP=%04x e=%02x".format(sp, e)
                val h = (sp and 0xf) + (e and 0xf) > 0xf
                val c = (sp and 0xff) + e > 0xff
                assertEquals(flags(z = false, n = false, h = h, c = c), emulator.readF(), message)
                when (op) {
                    SpOffsetOp.LD_HL_SP_E -> {
                        assertEquals(result.toUShort(), emulator.readHL(), message)
                        assertEquals(sp.toUShort(), emulator.readSP(), message)
                    }
                    SpOffsetOp.ADD_SP_E -> assertEquals(result.toUShort(), emulator.readSP(), message)
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `ADD HL, rr`(op: AddHlOp) {
        val emulator = TestEmulator(language)
        emulator.write(0x0000u, op.opcode)
        for (hl in WORD_VALUES) {
            for (rr in if (op == AddHlOp.HL) listOf(hl) else WORD_VALUES) {
                for (flagsIn in listOf(0x00, 0xf0)) {
                    emulator.writePC(0x0000u)
                    emulator.writeHL(hl.toUShort())
                    if (op != AddHlOp.HL) {
                        emulator.writeRegister(op.name, rr.toLong())
                    }
                    emulator.writeF(flagsIn.toUByte())
                    emulator.step()
                    val message = "HL=%04x %s=%04x F=%02x".format(hl, op.name, rr, flagsIn)
                    val h = (hl and 0xfff) + (rr and 0xfff) > 0xfff
                    val c = hl + rr > 0xffff
                    assertEquals(((hl + rr) and 0xffff).toUShort(), emulator.readHL(), message)
                    assertEquals(flags(z = (flagsIn and Z_FLAG) != 0, n = false, h = h, c = c), emulator.readF(), message)
                    if (op != AddHlOp.HL) {
                        assertEquals(rr.toLong(), emulator.readRegister(op.name), message)
                    }
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `8-bit arithmetic and logic`(op: AluOp) {
        val emulator = TestEmulator(language)
        emulator.write(0x0000u, op.opcode)
        for (a in 0..0xff) {
            for (x in 0..0xff) {
                for (c in if (op.usesCarry) 0..1 else 0..0) {
                    // vary the flags that must be overwritten
                    val flagsIn = (if (((a xor x) and 1) == 1) Z_FLAG or N_FLAG or H_FLAG else 0) or (c shl 4)
                    emulator.writePC(0x0000u)
                    emulator.writeA(a.toUByte())
                    emulator.writeB(x.toUByte())
                    emulator.writeF(flagsIn.toUByte())
                    emulator.step()
                    val (result, flagsOut) = op.model(a, x, c)
                    val message = "A=%02x B=%02x C=%d".format(a, x, c)
                    assertEquals(result.toUByte(), emulator.readA(), message)
                    assertEquals(flagsOut, emulator.readF(), message)
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `INC and DEC`(op: IncDecOp) {
        val emulator = TestEmulator(language)
        emulator.write(0x0000u, op.opcode)
        for (value in 0..0xff) {
            for (flagsIn in listOf(0x00, 0xf0)) {
                emulator.writePC(0x0000u)
                emulator.writeB(value.toUByte())
                emulator.writeF(flagsIn.toUByte())
                emulator.step()
                val carry = (flagsIn and C_FLAG) != 0
                val (result, flagsOut) =
                    when (op) {
                        IncDecOp.INC_B -> {
                            val r = (value + 1) and 0xff
                            r to flags(z = r == 0, n = false, h = (value and 0xf) == 0xf, c = carry)
                        }
                        IncDecOp.DEC_B -> {
                            val r = (value - 1) and 0xff
                            r to flags(z = r == 0, n = true, h = (value and 0xf) == 0, c = carry)
                        }
                    }
                val message = "B=%02x F=%02x".format(value, flagsIn)
                assertEquals(result.toUByte(), emulator.readB(), message)
                assertEquals(flagsOut, emulator.readF(), message)
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    fun `8-bit arithmetic and logic with (HL) and immediate operands`(op: AluOp) {
        val hlEmulator = TestEmulator(language)
        hlEmulator.write(0x0000u, (op.opcode.toInt() + 0x06).toUByte())
        for (x in EDGE_BYTES) {
            val immEmulator = TestEmulator(language)
            immEmulator.write(0x0000u, (op.opcode.toInt() + 0x46).toUByte(), x.toUByte())
            for (a in EDGE_BYTES) {
                for (c in 0..1) {
                    val (result, flagsOut) = op.model(a, x, if (op.usesCarry) c else 0)
                    for ((emulator, form) in listOf(hlEmulator to "(HL)", immEmulator to "n")) {
                        emulator.writePC(0x0000u)
                        emulator.writeA(a.toUByte())
                        emulator.writeHL(MEM_ADDRESS)
                        emulator.write(MEM_ADDRESS, x.toUByte())
                        emulator.writeF((c shl 4).toUByte())
                        emulator.step()
                        val message = "$form A=%02x x=%02x C=%d".format(a, x, c)
                        assertEquals(result.toUByte(), emulator.readA(), message)
                        assertEquals(flagsOut, emulator.readF(), message)
                    }
                }
            }
        }
    }

    @Test
    fun `INC and DEC (HL)`() {
        for ((opcode, delta) in listOf(0x34 to 1, 0x35 to -1)) {
            val emulator = TestEmulator(language)
            emulator.write(0x0000u, opcode.toUByte())
            for (value in 0..0xff) {
                emulator.writePC(0x0000u)
                emulator.writeHL(MEM_ADDRESS)
                emulator.write(MEM_ADDRESS, value.toUByte())
                emulator.writeF(0x10u)
                emulator.step()
                val result = (value + delta) and 0xff
                val h = if (delta > 0) (value and 0xf) == 0xf else (value and 0xf) == 0
                val message = "opcode=%02x (HL)=%02x".format(opcode, value)
                assertEquals(result.toUByte(), emulator.read(MEM_ADDRESS), message)
                assertEquals(flags(z = result == 0, n = delta < 0, h = h, c = true), emulator.readF(), message)
            }
        }
    }
}
