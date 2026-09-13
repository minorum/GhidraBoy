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

import ghidra.pcode.emu.PcodeEmulator
import ghidra.pcode.exec.PcodeArithmetic.Purpose
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Language
import org.junit.jupiter.api.Assertions.assertEquals

class TestEmulator(
    val language: Language,
) {
    private val ignoredUserops = mutableMapOf<String, IgnorePCode>()
    private val machine = PcodeEmulator(language, EmulatorCallbacks(ignoredUserops))
    private val thread = machine.newThread()

    fun registerCallOtherCallback(
        name: String,
        callback: IgnorePCode,
    ) {
        ignoredUserops[name] = callback
    }

    fun step() = thread.stepInstruction()

    fun readRegister(name: String): Long {
        val register = language.getRegister(name)
        return machine.arithmetic.toLong(thread.state.getVar(register, Reason.INSPECT), Purpose.INSPECT)
    }

    fun writeRegister(
        name: String,
        value: Long,
    ) {
        val register = language.getRegister(name)
        if (register == language.programCounter) {
            thread.overrideCounter(address(value))
        } else {
            thread.state.setVar(register, machine.arithmetic.fromConst(value, register.minimumByteSize))
        }
    }

    fun writeMemory(
        address: Address,
        bytes: ByteArray,
    ) = machine.sharedState.setVar(address, bytes.size, true, bytes)

    fun readMemory(
        address: Address,
        length: Int,
    ): ByteArray = machine.sharedState.getVar(address, length, true, Reason.INSPECT)

    private fun address(offset: Long): Address = language.addressFactory.defaultAddressSpace.getAddress(offset)
}

fun TestEmulator.write(
    address: UShort,
    vararg bytes: UByte,
) = writeMemory(
    language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
    bytes.map { it.toByte() }.toByteArray(),
)

fun TestEmulator.read(address: UShort): UByte =
    readMemory(
        language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
        1,
    )[0].toUByte()

fun TestEmulator.read(
    address: UShort,
    length: Int,
): UByteArray =
    readMemory(
        language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
        length,
    ).map { it.toUByte() }.toUByteArray()

fun TestEmulator.assertA(a: UByte) = assertEquals(a, readA())

fun TestEmulator.assertF(f: UByte) = assertEquals(f, readF())

fun TestEmulator.assertB(b: UByte) = assertEquals(b, readB())

fun TestEmulator.assertC(c: UByte) = assertEquals(c, readC())

fun TestEmulator.assertD(d: UByte) = assertEquals(d, readD())

fun TestEmulator.assertE(e: UByte) = assertEquals(e, readE())

fun TestEmulator.assertH(h: UByte) = assertEquals(h, readH())

fun TestEmulator.assertL(l: UByte) = assertEquals(l, readL())

fun TestEmulator.assertAF(af: UShort) = assertEquals(af, readAF())

fun TestEmulator.assertBC(bc: UShort) = assertEquals(bc, readBC())

fun TestEmulator.assertDE(de: UShort) = assertEquals(de, readDE())

fun TestEmulator.assertHL(hl: UShort) = assertEquals(hl, readHL())

fun TestEmulator.assertPC(pc: UShort) = assertEquals(pc, readPC())

fun TestEmulator.assertSP(sp: UShort) = assertEquals(sp, readSP())

fun TestEmulator.readA(): UByte = this.readRegister("A").toInt().toUByte()

fun TestEmulator.readF(): UByte = this.readRegister("F").toInt().toUByte()

fun TestEmulator.readB(): UByte = this.readRegister("B").toInt().toUByte()

fun TestEmulator.readC(): UByte = this.readRegister("C").toInt().toUByte()

fun TestEmulator.readD(): UByte = this.readRegister("D").toInt().toUByte()

fun TestEmulator.readE(): UByte = this.readRegister("E").toInt().toUByte()

fun TestEmulator.readH(): UByte = this.readRegister("H").toInt().toUByte()

fun TestEmulator.readL(): UByte = this.readRegister("L").toInt().toUByte()

fun TestEmulator.readAF(): UShort = this.readRegister("AF").toInt().toUShort()

fun TestEmulator.readBC(): UShort = this.readRegister("BC").toInt().toUShort()

fun TestEmulator.readDE(): UShort = this.readRegister("DE").toInt().toUShort()

fun TestEmulator.readHL(): UShort = this.readRegister("HL").toInt().toUShort()

fun TestEmulator.readPC(): UShort = this.readRegister("PC").toInt().toUShort()

fun TestEmulator.readSP(): UShort = this.readRegister("SP").toInt().toUShort()

fun TestEmulator.writeA(a: UByte) = this.writeRegister("A", a.toLong())

fun TestEmulator.writeF(f: UByte) = this.writeRegister("F", f.toLong())

fun TestEmulator.writeB(b: UByte) = this.writeRegister("B", b.toLong())

fun TestEmulator.writeC(c: UByte) = this.writeRegister("C", c.toLong())

fun TestEmulator.writeD(d: UByte) = this.writeRegister("D", d.toLong())

fun TestEmulator.writeE(e: UByte) = this.writeRegister("E", e.toLong())

fun TestEmulator.writeH(h: UByte) = this.writeRegister("H", h.toLong())

fun TestEmulator.writeL(l: UByte) = this.writeRegister("L", l.toLong())

fun TestEmulator.writeAF(af: UShort) = this.writeRegister("AF", af.toLong())

fun TestEmulator.writeBC(bc: UShort) = this.writeRegister("BC", bc.toLong())

fun TestEmulator.writeDE(de: UShort) = this.writeRegister("DE", de.toLong())

fun TestEmulator.writeHL(hl: UShort) = this.writeRegister("HL", hl.toLong())

fun TestEmulator.writePC(pc: UShort) = this.writeRegister("PC", pc.toLong())

fun TestEmulator.writeSP(sp: UShort) = this.writeRegister("SP", sp.toLong())
