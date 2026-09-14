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

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private val ROM_LOGO =
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

private fun hex(text: String) =
    text
        .filter { !it.isWhitespace() }
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class GameBoyBankAnalyzerTest : IntegrationTest() {
    // 64 kB MBC5 ROM: bank switch + call, inline far call, RST 00 jump table
    private fun rom(): ByteArray =
        ByteArray(0x10000) { 0xff.toByte() }.also { rom ->
            hex("c9").copyInto(rom, 0x0000)
            hex("00 c3 50 01").copyInto(rom, 0x0100)
            ROM_LOGO.copyInto(rom, 0x0104)
            ByteArray(0x0150 - 0x0134).copyInto(rom, 0x0134)
            rom[0x0147] = 0x19
            rom[0x0148] = 0x01
            hex(
                """
                3e 02 ea 00 20 cd 00 40
                cd 00 02 10 40 03
                c7 70 01 74 01
                """,
            ).copyInto(rom, 0x0150)
            hex("18 fe").copyInto(rom, 0x0170)
            hex("18 fe").copyInto(rom, 0x0174)
            hex("c9").copyInto(rom, 0x0200)
            // vblank handler: unguarded JP (HL) table at 0x0310
            hex("c3 00 03").copyInto(rom, 0x0040)
            hex("fa 00 c0 87 5f 16 00 21 10 03 19 2a 66 6f e9").copyInto(rom, 0x0300)
            hex("18 03 1c 03").copyInto(rom, 0x0310)
            hex("18 fe").copyInto(rom, 0x0318)
            hex("18 fe c9").copyInto(rom, 0x031c)
            // joypad handler inside the last target's instruction window
            hex("c3 1e 03").copyInto(rom, 0x0060)
            // STAT handler: JP (HL) table guarded by CP 2 / RET NC; kept below the unguarded table,
            // whose switch recovery reads past its end
            hex("c3 80 02").copyInto(rom, 0x0048)
            hex("fa 00 c0 fe 02 d0 87 5f 16 00 21 a0 02 19 2a 66 6f e9").copyInto(rom, 0x0280)
            hex("a8 02 aa 02").copyInto(rom, 0x02a0)
            hex("c9").copyInto(rom, 0x02a8)
            hex("c9").copyInto(rom, 0x02aa)
            // timer handler: JP (HL) table after its targets, followed by a word into LD A,(nn)
            hex("c3 10 04").copyInto(rom, 0x0050)
            hex("18 fe 18 fe").copyInto(rom, 0x0400)
            hex("fa 00 c0 87 5f 16 00 21 20 04 19 2a 66 6f e9").copyInto(rom, 0x0410)
            hex("00 04 02 04 11 04").copyInto(rom, 0x0420)
            hex("c9").copyInto(rom, 0x8000)
            hex("c9").copyInto(rom, 0xc010)
        }

    // MBC1 ROM calling 0x4000 after selecting bank 1 << 5 | 5
    private fun mbc1Rom(size: Int): ByteArray =
        ByteArray(size) { 0xff.toByte() }.also { rom ->
            hex("00 c3 50 01").copyInto(rom, 0x0100)
            ROM_LOGO.copyInto(rom, 0x0104)
            ByteArray(0x0150 - 0x0134).copyInto(rom, 0x0134)
            rom[0x0147] = 0x01
            rom[0x0148] = (size / 0x8000).countTrailingZeroBits().toByte()
            // LD A,1; LD (0x4000),A; LD A,5; LD (0x2000),A; CALL 0x4000; JR -2
            hex("3e 01 ea 00 40 3e 05 ea 00 20 cd 00 40 18 fe").copyInto(rom, 0x0150)
            (0x4000 until size step 0x4000).forEach { rom[it] = 0xc9.toByte() }
        }

    // CGB ROM reading switchable WRAM and writing VRAM after SVBK/VBK writes
    private fun cgbRom(): ByteArray =
        ByteArray(0x8000) { 0xff.toByte() }.also { rom ->
            hex("00 c3 50 01").copyInto(rom, 0x0100)
            ROM_LOGO.copyInto(rom, 0x0104)
            ByteArray(0x0150 - 0x0134).copyInto(rom, 0x0134)
            rom[0x0143] = 0x80.toByte()
            hex(
                """
                3e 03 e0 70 fa a1 d9
                3e 01 ea 4f ff ea 00 80
                3e 00 e0 70 fa a1 d9
                fa 00 c0 e0 70 fa a1 d9
                3e 03 e0 70 0e 70 3e 02 e2 fa a1 d9
                18 fe
                """,
            ).copyInto(rom, 0x0150)
        }

    private fun analyze(
        farCalls: String,
        jumpTables: String,
        bytes: ByteArray = rom(),
        check: (Program) -> Unit,
    ) = ProgramLoader
        .builder()
        .source(bytes)
        .name("banked.gb")
        .loaders(GameBoyLoader::class.java)
        .load()
        .use { results ->
            val program = results.getPrimaryDomainObject(this)
            try {
                val id = program.startTransaction("analysis")
                try {
                    program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(GameBoyBankAnalyzer.NAME).apply {
                        setString(GameBoyBankAnalyzer.OPT_FAR_CALLS, farCalls)
                        setString(GameBoyBankAnalyzer.OPT_JUMP_TABLES, jumpTables)
                    }
                    val manager = AutoAnalysisManager.getAnalysisManager(program)
                    manager.initializeOptions()
                    manager.reAnalyzeAll(null)
                    manager.startAnalysis(TaskMonitor.DUMMY)
                } finally {
                    program.endTransaction(id, true)
                }
                check(program)
            } finally {
                program.release(this)
            }
        }

    private fun Program.addr(offset: Long) = addressFactory.defaultAddressSpace.getAddress(offset)

    private fun Program.bankAddr(
        bank: Int,
        offset: Long,
    ) = addressFactory.getAddressSpace("rom$bank").getAddress(offset)

    private fun Program.refs(
        from: Long,
        type: RefType,
    ): Set<Address> =
        referenceManager
            .getReferencesFrom(addr(from))
            .filter { it.referenceType == type }
            .map { it.toAddress }
            .toSet()

    @Test
    fun `call after bank register write resolves into the bank`() =
        analyze("", "") { program ->
            assertEquals(setOf(program.bankAddr(2, 0x4000)), program.refs(0x0155, RefType.CALL_OVERRIDE_UNCONDITIONAL))
            assertNotNull(program.functionManager.getFunctionAt(program.bankAddr(2, 0x4000)))
        }

    @Test
    fun `call after a bank switch helper resolves into the bank`() =
        analyze(
            "",
            "",
            rom().also { rom ->
                // rst08: CALL $0180; CALL $4000; RET
                hex("cd 80 01 cd 00 40 c9").copyInto(rom, 0x0008)
                // rst10: LD A,3; CALL $01A0; CALL $4000; RET
                hex("3e 03 cd a0 01 cd 00 40 c9").copyInto(rom, 0x0010)
                // PUSH AF; LD A,1; JR $018C / DI; LD ($2000),A; EI; POP AF; RET
                hex("f5 3e 01 18 07").copyInto(rom, 0x0180)
                hex("f3 ea 00 20 fb f1 c9").copyInto(rom, 0x018c)
                // LD ($2000),A; RET
                hex("ea 00 20 c9").copyInto(rom, 0x01a0)
            },
        ) { program ->
            assertEquals(setOf(program.bankAddr(1, 0x4000)), program.refs(0x000b, RefType.CALL_OVERRIDE_UNCONDITIONAL))
            assertEquals(setOf(program.bankAddr(3, 0x4000)), program.refs(0x0015, RefType.CALL_OVERRIDE_UNCONDITIONAL))
        }

    @Test
    fun `upper bank bits select banks past the low register range`() =
        analyze("", "", mbc1Rom(0x100000)) { program ->
            assertEquals(setOf(program.bankAddr(0x25, 0x4000)), program.refs(0x015a, RefType.CALL_OVERRIDE_UNCONDITIONAL))
        }

    @Test
    fun `upper bank bits survive a helper that writes only the low register`() =
        // LD A,1; LD ($4000),A; LD A,5; CALL $01A0; CALL $4000; JR -2 / LD ($2000),A; RET
        analyze(
            "",
            "",
            mbc1Rom(0x100000).also { rom ->
                hex("3e 01 ea 00 40 3e 05 cd a0 01 cd 00 40 18 fe").copyInto(rom, 0x0150)
                hex("ea 00 20 c9").copyInto(rom, 0x01a0)
            },
        ) { program ->
            assertEquals(setOf(program.bankAddr(0x25, 0x4000)), program.refs(0x015a, RefType.CALL_OVERRIDE_UNCONDITIONAL))
        }

    @Test
    fun `upper bank bits wrap on small ROMs`() =
        analyze("", "", mbc1Rom(0x10000)) { program ->
            assertEquals(setOf(program.bankAddr(1, 0x4000)), program.refs(0x015a, RefType.CALL_OVERRIDE_UNCONDITIONAL))
        }

    @Test
    fun `SVBK and VBK writes resolve RAM references into the selected bank`() =
        analyze("", "", cgbRom()) { program ->
            fun dataRefs(from: Long) =
                program.referenceManager
                    .getReferencesFrom(program.addr(from))
                    .filter { it.referenceType.isData }
                    .map { it.toAddress.toString(true) }
            // LDH ($70),A with A=3
            assertEquals(listOf("wram3::d9a1"), dataRefs(0x0154))
            // LD ($FF4F),A with A=1
            assertEquals(listOf("vram1::8000"), dataRefs(0x015c))
            // SVBK 0 selects bank 1
            assertEquals(listOf("ram:d9a1"), dataRefs(0x0163))
            // SVBK from memory
            assertEquals(listOf("ram:d9a1"), dataRefs(0x016b))
            // LDH (C),A after a constant SVBK write
            assertEquals(listOf("ram:d9a1"), dataRefs(0x0177))
        }

    @Test
    fun `decompiler names banked RAM by the selected bank`() =
        // LD A,3; LDH ($70),A; LD A,1; LDH ($4F),A; LD A,($D9A1); LD ($8000),A; RET
        analyze("", "", cgbRom().also { hex("3e 03 e0 70 3e 01 e0 4f fa a1 d9 ea 00 80 c9").copyInto(it, 0x0150) }) { program ->
            program.withTransaction {
                val symbols = program.symbolTable
                symbols.createLabel(
                    program.addressFactory.getAddressSpace("wram3").getAddress(0xd9a1),
                    "wram3_var",
                    SourceType.USER_DEFINED,
                )
                symbols.createLabel(program.addr(0xd9a1), "wram1_var", SourceType.USER_DEFINED)
                symbols.createLabel(
                    program.addressFactory.getAddressSpace("vram1").getAddress(0x8000),
                    "vram1_var",
                    SourceType.USER_DEFINED,
                )
                symbols.createLabel(program.addr(0x8000), "vram0_var", SourceType.USER_DEFINED)
            }
            val function =
                program.functionManager.getFunctionContaining(program.addr(0x0154)) ?: program.withTransaction {
                    CreateFunctionCmd(program.addr(0x0150)).applyTo(program)
                    program.functionManager.getFunctionAt(program.addr(0x0150))
                }
            assertNotNull(function)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program), decompiler.lastMessage)
                val results = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                val c = results.decompiledFunction?.c
                assertTrue(
                    c != null && c.contains("vram1_var = wram3_var;") && !c.contains("wram1_var") && !c.contains("vram0_var"),
                    "${results.errorMessage}\n$c",
                )
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `edited SVBK constant moves the RAM reference`() =
        analyze("", "", cgbRom()) { program ->
            program.withTransaction {
                program.listing.clearCodeUnits(program.addr(0x0150), program.addr(0x0151), false)
                program.memory.setByte(program.addr(0x0151), 5.toByte())
                DisassembleCommand(program.addr(0x0150), AddressSet(program.addr(0x0150), program.addr(0x0151)), false).applyTo(program)
                GameBoyRamBankAnalyzer().added(program, AddressSet(program.addr(0x0154)), TaskMonitor.DUMMY, MessageLog())
            }
            assertEquals(
                listOf("wram5::d9a1"),
                program.referenceManager
                    .getReferencesFrom(program.addr(0x0154))
                    .filter { it.referenceType.isData }
                    .map { it.toAddress.toString(true) },
            )
        }

    @Test
    fun `re-added default-space RAM reference keeps the bank reference primary`() =
        analyze("", "", cgbRom()) { program ->
            program.withTransaction {
                program.referenceManager.addMemoryReference(
                    program.addr(0x0154),
                    program.addr(0xd9a1),
                    RefType.READ,
                    SourceType.ANALYSIS,
                    1,
                )
                GameBoyRamBankAnalyzer().added(program, AddressSet(program.addr(0x0154)), TaskMonitor.DUMMY, MessageLog())
            }
            val refs = program.referenceManager.getReferencesFrom(program.addr(0x0154)).filter { it.referenceType.isData }
            assertEquals(listOf("wram3::d9a1" to true), refs.map { it.toAddress.toString(true) to it.isPrimary })
        }

    @Test
    fun `RAM bank analyzer only applies to CGB programs`() {
        analyze("", "") { program -> assertFalse(GameBoyRamBankAnalyzer().canAnalyze(program)) }
        analyze("", "", cgbRom()) { program -> assertTrue(GameBoyRamBankAnalyzer().canAnalyze(program)) }
    }

    @Test
    fun `inline far call dispatcher`() =
        analyze("0200", "") { program ->
            assertEquals(setOf(program.bankAddr(3, 0x4010)), program.refs(0x0158, RefType.CALL_OVERRIDE_UNCONDITIONAL))
            assertEquals(program.addr(0x015e), program.listing.getInstructionAt(program.addr(0x0158)).fallThrough)
            assertEquals(
                "word",
                program.listing
                    .getDataAt(program.addr(0x015b))
                    ?.dataType
                    ?.name,
            )
            assertNotNull(program.functionManager.getFunctionAt(program.bankAddr(3, 0x4010)))
        }

    @Test
    fun `decompiler continues after an inline far call`() =
        analyze(
            "0200",
            "",
            rom().also { rom ->
                // rst08: CALL $0600; RET
                hex("cd 00 06 c9").copyInto(rom, 0x0008)
                // dispatcher: POP HL; LD E,(HL); INC HL; LD D,(HL); INC HL; LD A,(HL+); PUSH HL; LD ($2000),A; PUSH DE; RET
                hex("e1 5e 23 56 23 2a e5 ea 00 20 d5 c9").copyInto(rom, 0x0200)
                // CALL $0200 / db $10,$40,$03; LD A,4; LD ($D00F),A; CALL $0200 / db $00,$40,$02; RET
                hex("cd 00 02 10 40 03 3e 04 ea 0f d0 cd 00 02 00 40 02 c9").copyInto(rom, 0x0600)
                // more far call sites: rst10/rst18 call $0620-$0650, each CALL $0200 / db $10,$40,$03; RET
                hex("cd 20 06 cd 30 06 c9").copyInto(rom, 0x0010)
                hex("cd 40 06 cd 50 06 c9").copyInto(rom, 0x0018)
                (0x0620..0x0650 step 0x10).forEach { hex("cd 00 02 10 40 03 c9").copyInto(rom, it) }
            },
        ) { program ->
            // inline bytes are data, not code the decompiler could walk through
            listOf(0x0603L, 0x060eL).forEach { offset ->
                assertEquals(
                    "word",
                    program.listing
                        .getDataAt(program.addr(offset))
                        ?.dataType
                        ?.name,
                )
            }
            // call sites followed by data must not make the dispatcher or the callee non-returning
            listOf(program.addr(0x0200), program.bankAddr(3, 0x4010)).forEach { entry ->
                val callee = program.functionManager.getFunctionAt(entry)
                assertNotNull(callee, entry.toString())
                assertFalse(callee.hasNoReturn(), entry.toString())
            }
            val function = program.functionManager.getFunctionAt(program.addr(0x0600))
            assertNotNull(function)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program), decompiler.lastMessage)
                val results = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                val c = results.decompiledFunction?.c
                assertTrue(
                    c != null && c.contains("rom3__4010") && c.contains("DAT_d00f = 4;") && c.contains("rom2__4000"),
                    "${results.errorMessage}\n$c",
                )
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `inline jump table dispatcher`() =
        analyze("0200", "0000") { program ->
            val rst = program.listing.getInstructionAt(program.addr(0x015e))
            assertEquals("RST", rst.mnemonicString)
            assertEquals(FlowOverride.CALL_RETURN, rst.flowOverride)
            assertEquals(setOf(program.addr(0x0170), program.addr(0x0174)), program.refs(0x015e, RefType.COMPUTED_JUMP))
            assertEquals(
                "word",
                program.listing
                    .getDataAt(program.addr(0x015f))
                    ?.dataType
                    ?.name,
            )
            assertEquals(
                "word",
                program.listing
                    .getDataAt(program.addr(0x0161))
                    ?.dataType
                    ?.name,
            )
            assertNotNull(program.listing.getInstructionAt(program.addr(0x0174)))
        }

    @Test
    fun `inline jump table decoded as fall-through code over its first target`() =
        // serial handler: PUSH AF; PUSH HL; LD A,($C853); AND 3; RST 00; dw $10C1, $10E7, $10F6, $1127
        // table bytes decode as POP BC / STOP / STOP / STOP / LD DE,$013E over $10C1
        analyze(
            "",
            "0000",
            rom().also { rom ->
                hex("c3 b1 10").copyInto(rom, 0x0058)
                hex("f5 e5 fa 53 c8 e6 03 c7 c1 10 e7 10 f6 10 27 11 3e 01 c9").copyInto(rom, 0x10b1)
                listOf(0x10e7, 0x10f6, 0x1127).forEach { rom[it] = 0xc9.toByte() }
            },
        ) { program ->
            assertEquals(
                setOf(0x10c1L, 0x10e7L, 0x10f6L, 0x1127L).map { program.addr(it) }.toSet(),
                program.refs(0x10b8, RefType.COMPUTED_JUMP),
            )
            assertEquals("LD", program.listing.getInstructionAt(program.addr(0x10c1))?.mnemonicString)
        }

    @Test
    fun `inline jump table ends before a word into the middle of code after it`() =
        // RST 00; dw $0909; ADD A,$10 (a word into LD HL,$1234 below); RST 38 x8; LD HL,$1234; RET
        analyze(
            "",
            "0000",
            rom().also { rom ->
                hex("c3 b1 10").copyInto(rom, 0x0058)
                hex("f5 e5 fa 53 c8 e6 03 c7 09 09 c6 10 ff ff ff ff ff ff ff ff 21 34 12 c9").copyInto(rom, 0x10b1)
            },
        ) { program ->
            assertEquals(setOf(program.addr(0x0909)), program.refs(0x10b8, RefType.COMPUTED_JUMP))
            assertFalse(
                program.listing
                    .getDataAt(program.addr(0x10bb))
                    ?.dataType
                    ?.name == "word",
            )
        }

    @Test
    fun `decompiler shows the cases of an inline jump table`() =
        analyze(
            "",
            "0000",
            rom().also { rom ->
                // rst08: CALL $0600; RET
                hex("cd 00 06 c9").copyInto(rom, 0x0008)
                // LD A,($C800); RST 00; dw $0670, $0674
                hex("fa 00 c8 c7 70 06 74 06").copyInto(rom, 0x0600)
                // CALL $0200; RET / LD ($C001),A; RET
                hex("cd 00 02 c9 ea 01 c0 c9").copyInto(rom, 0x0670)
            },
        ) { program ->
            assertEquals(setOf(program.addr(0x0670), program.addr(0x0674)), program.refs(0x0603, RefType.COMPUTED_JUMP))
            val function = program.functionManager.getFunctionAt(program.addr(0x0600))
            assertNotNull(function)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program), decompiler.lastMessage)
                val results = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                val c = results.decompiledFunction?.c
                assertTrue(
                    c != null && c.contains("switch") && c.contains("FUN_0200") && c.contains("DAT_c001"),
                    "${results.errorMessage}\n$c",
                )
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `inline jump table size follows the index bound`() =
        analyze(
            "",
            "0000",
            rom().also { rom ->
                // rst08: CALL $0600; CALL $0700; RET
                hex("cd 00 06 cd 00 07 c9").copyInto(rom, 0x0008)
                // LD A,($C883); AND 3; RST 00; dw $0680, $0683, $0683, $0683; LD A,$3D; LD ($C884),A; RET
                hex("fa 83 c8 e6 03 c7 80 06 83 06 83 06 83 06 3e 3d ea 84 c8 c9").copyInto(rom, 0x0600)
                // RET / CALL $060E; RET
                hex("c9 00 00 cd 0e 06 c9").copyInto(rom, 0x0680)
                // LD A,($C883); CP 2; RET NC; RST 00; dw $0780, $0783; LD A,$3D; LD ($C884),A; RET
                hex("fa 83 c8 fe 02 d0 c7 80 07 83 07 3e 3d ea 84 c8 c9").copyInto(rom, 0x0700)
                // RET / CALL $070B; RET
                hex("c9 00 00 cd 0b 07 c9").copyInto(rom, 0x0780)
            },
        ) { program ->
            assertEquals(setOf(program.addr(0x0680), program.addr(0x0683)), program.refs(0x0605, RefType.COMPUTED_JUMP))
            assertEquals("LD", program.listing.getInstructionAt(program.addr(0x060e))?.mnemonicString)
            assertEquals(setOf(program.addr(0x0780), program.addr(0x0783)), program.refs(0x0706, RefType.COMPUTED_JUMP))
            assertEquals("LD", program.listing.getInstructionAt(program.addr(0x070b))?.mnemonicString)
        }

    @Test
    fun `inline jump table cases do not see the dispatcher return address`() =
        analyze(
            "",
            "0000",
            rom().also { rom ->
                // rst08: CALL $0600; RET
                hex("cd 00 06 c9").copyInto(rom, 0x0008)
                // PUSH BC; LD A,($C800); RST 00; dw $0672, $0676
                hex("c5 fa 00 c8 c7 72 06 76 06").copyInto(rom, 0x0600)
                // POP BC; RET / POP BC; RET
                hex("c1 c9 00 00 c1 c9").copyInto(rom, 0x0672)
            },
        ) { program ->
            assertEquals(setOf(program.addr(0x0672), program.addr(0x0676)), program.refs(0x0604, RefType.COMPUTED_JUMP))
            val function = program.functionManager.getFunctionAt(program.addr(0x0600))
            assertNotNull(function)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program), decompiler.lastMessage)
                val results = decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY)
                val c = results.decompiledFunction?.c
                assertTrue(c != null && c.contains("switch") && !c.contains("0605") && !c.contains("0x605"), "${results.errorMessage}\n$c")
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `unguarded JP HL jump table`() =
        analyze("", "") { program ->
            assertEquals(setOf(program.addr(0x0318), program.addr(0x031c)), program.refs(0x030e, RefType.COMPUTED_JUMP))
            assertEquals(
                "word",
                program.listing
                    .getDataAt(program.addr(0x0312))
                    ?.dataType
                    ?.name,
            )
            assertNotNull(program.listing.getInstructionAt(program.addr(0x031c)))
            val function = program.functionManager.getFunctionContaining(program.addr(0x030e))
            assertTrue(function.body.contains(program.addr(0x031c)))
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program))
                val c =
                    decompiler
                        .decompileFunction(function, 10, TaskMonitor.DUMMY)
                        .decompiledFunction.c
                assertTrue(c.contains("switch") && !c.contains("halt_baddata"), c)
            } finally {
                decompiler.dispose()
            }
            assertNotNull(program.listing.getInstructionAt(program.addr(0x031e)))
        }

    @Test
    fun `JP HL table indexed with an 8-bit add carried into H`() =
        analyze(
            "",
            "",
            rom().also { rom ->
                // LDH A,($81); LD HL,$0520; ADD A; ADD L; LD L,A; JR NC,+1; INC H; LD A,(HL+); LD H,(HL); LD L,A; JP HL
                hex("c3 00 05").copyInto(rom, 0x0058)
                hex("f5 e5 f0 81 21 20 05 87 85 6f 30 01 24 2a 66 6f e9").copyInto(rom, 0x0500)
                hex("28 05 2a 05").copyInto(rom, 0x0520)
                hex("c9 00 c9").copyInto(rom, 0x0528)
                // LDH A,($81); LD HL,$0560; ADD A; ADD L; LD L,A; ADC H; SUB L; LD H,A; LD A,(HL+); LD H,(HL); LD L,A; JP HL
                hex("c3 40 05").copyInto(rom, 0x0008)
                hex("f0 81 21 60 05 87 85 6f 8c 95 67 2a 66 6f e9").copyInto(rom, 0x0540)
                hex("68 05 6a 05").copyInto(rom, 0x0560)
                hex("c9 00 c9").copyInto(rom, 0x0568)
            },
        ) { program ->
            assertEquals(setOf(program.addr(0x0528), program.addr(0x052a)), program.refs(0x0510, RefType.COMPUTED_JUMP))
            assertEquals(setOf(program.addr(0x0568), program.addr(0x056a)), program.refs(0x054e, RefType.COMPUTED_JUMP))
        }

    @Test
    fun `JP HL table ends at a word into the middle of an instruction`() =
        analyze("", "") { program ->
            assertEquals(setOf(program.addr(0x0400), program.addr(0x0402)), program.refs(0x041e, RefType.COMPUTED_JUMP))
        }

    @Test
    fun `guarded JP HL jump table is left to switch recovery`() =
        analyze("", "") { program ->
            assertEquals(setOf(program.addr(0x02a8), program.addr(0x02aa)), program.refs(0x0291, RefType.COMPUTED_JUMP))
            val namespaces = program.symbolTable.getSymbols(program.addr(0x0291)).map { it.parentNamespace.getName(true) }
            assertTrue(namespaces.none { it.contains("override") }, namespaces.toString())
        }

    @Test
    fun `JP HL recovery keeps user computed references`() =
        analyze("", "") { program ->
            val from = program.addr(0x030e)
            program.withTransaction {
                program.referenceManager.apply {
                    addMemoryReference(from, program.addr(0x0001), RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0)
                    addMemoryReference(from, program.addr(0x7fff), RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0)
                }
                GameBoyJumpTableAnalyzer().added(program, AddressSet(from), TaskMonitor.DUMMY, MessageLog())
            }
            assertTrue(program.addr(0x7fff) in program.refs(0x030e, RefType.COMPUTED_JUMP))
        }

    @Test
    fun `interrupt vectors and their handlers use the interrupt convention`() =
        analyze(
            "",
            "",
            rom().also { rom ->
                // serial: JP $0500; rst08: CALL $0500; RET
                hex("c3 00 05").copyInto(rom, 0x0058)
                hex("cd 00 05 c9").copyInto(rom, 0x0008)
                // PUSH AF; CALL $0200; POP AF; RETI
                hex("f5 cd 00 02 f1 d9").copyInto(rom, 0x0500)
            },
        ) { program ->
            fun convention(offset: Long) = program.functionManager.getFunctionAt(program.addr(offset))?.callingConventionName
            assertEquals("__interrupt", convention(0x0058))
            assertEquals("__interrupt", convention(0x0500))
            assertFalse(convention(0x0008) == "__interrupt")
            // re-analysis drops a signature found by other analyzers
            val handler = program.functionManager.getFunctionAt(program.addr(0x0500))
            program.withTransaction {
                handler.updateFunction(
                    "__asm",
                    ReturnParameterImpl(ByteDataType.dataType, program),
                    listOf(ParameterImpl("a", ByteDataType.dataType, program)),
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    false,
                    SourceType.ANALYSIS,
                )
                GameBoyInterruptAnalyzer().added(program, handler.body, TaskMonitor.DUMMY, MessageLog())
            }
            assertEquals("__interrupt", handler.callingConventionName)
            assertEquals(0, handler.parameterCount)
            assertEquals("void", handler.returnType.name)
        }

    @Test
    fun `helpers restoring BC, DE and HL use the callee-saved convention`() =
        analyze(
            "",
            "",
            rom().also { rom ->
                // rst08: CALL $0700; RET / rst10: CALL $07A0; CALL $07C0; RET / rst18: CALL $0800; RET
                hex("cd 00 07 c9").copyInto(rom, 0x0008)
                hex("cd a0 07 cd c0 07 c9").copyInto(rom, 0x0010)
                hex("cd 00 08 c9").copyInto(rom, 0x0018)
                // LD DE,$14FF; loop: CALL $0780; DEC D; JR NZ,loop; RET
                hex("11 ff 14 cd 80 07 15 20 fa c9").copyInto(rom, 0x0700)
                // LD ($C839),A; PUSH BC; PUSH DE; PUSH HL; LD A,($C000); LD B,A; LD D,A; LD H,A; POP HL; POP DE; POP BC; RET
                hex("ea 39 c8 c5 d5 e5 fa 00 c0 47 57 67 e1 d1 c1 c9").copyInto(rom, 0x0780)
                // pops in push order
                hex("c5 d5 e5 47 57 67 c1 d1 e1 c9").copyInto(rom, 0x07a0)
                // RET Z before the pops
                hex("c5 d5 e5 a7 c8 47 e1 d1 c1 c9").copyInto(rom, 0x07c0)
                // BC and DE only
                hex("c5 d5 47 57 d1 c1 c9").copyInto(rom, 0x0800)
                // serial handler saving every register: JP $07E0 / PUSH AF; PUSH BC; PUSH DE; PUSH HL; POP HL; POP DE; POP BC; POP AF; RETI
                hex("c3 e0 07").copyInto(rom, 0x0058)
                hex("f5 c5 d5 e5 e1 d1 c1 f1 d9").copyInto(rom, 0x07e0)
            },
        ) { program ->
            fun convention(offset: Long) = program.functionManager.getFunctionAt(program.addr(offset))?.callingConventionName
            assertEquals("__asm_saved", convention(0x0780))
            assertEquals(
                listOf("__asm", "__asm", "__asm"),
                listOf(0x07a0L, 0x07c0L, 0x0800L).map { convention(it)?.replace("unknown", "__asm") },
            )
            assertEquals("__interrupt", convention(0x07e0))
            val caller = program.functionManager.getFunctionAt(program.addr(0x0700))
            assertNotNull(caller)
            val decompiler = DecompInterface()
            try {
                assertTrue(decompiler.openProgram(program), decompiler.lastMessage)
                val results = decompiler.decompileFunction(caller, 10, TaskMonitor.DUMMY)
                val c = results.decompiledFunction?.c
                assertTrue(c != null && c.contains("while") && !c.contains("extraout"), "${results.errorMessage}\n$c")
            } finally {
                decompiler.dispose()
            }
        }

    @Test
    fun `callee-saved inference rejects stack tricks, fall-through and imported signatures`() =
        analyze(
            "",
            "",
            rom().also { rom ->
                // rst08: CALL $0820; CALL $0840; RET / rst10: CALL $084B; RET / rst18: CALL $0860; RET
                hex("cd 20 08 cd 40 08 c9").copyInto(rom, 0x0008)
                hex("cd 4b 08 c9").copyInto(rom, 0x0010)
                hex("cd 60 08 c9").copyInto(rom, 0x0018)
                // PUSH BC; PUSH DE; PUSH HL; LD DE,$1234; POP HL; PUSH DE; POP HL; POP DE; POP BC; RET
                hex("c5 d5 e5 11 34 12 e1 d5 e1 d1 c1 c9").copyInto(rom, 0x0820)
                // PUSH BC; PUSH DE; PUSH HL; LD A,($C000); DEC A; POP HL; POP DE; POP BC; RET Z / next: LD B,0; RET
                hex("c5 d5 e5 fa 00 c0 3d e1 d1 c1 c8 06 00 c9").copyInto(rom, 0x0840)
                // PUSH BC; PUSH DE; PUSH HL; LD B,A; POP HL; POP DE; POP BC; RET
                hex("c5 d5 e5 47 e1 d1 c1 c9").copyInto(rom, 0x0860)
            },
        ) { program ->
            fun convention(offset: Long) = program.functionManager.getFunctionAt(program.addr(offset))?.callingConventionName
            assertNotNull(program.functionManager.getFunctionAt(program.addr(0x0820)))
            assertFalse(convention(0x0820) == "__asm_saved", "stack trick")
            assertNotNull(program.functionManager.getFunctionAt(program.addr(0x0840)))
            assertNotNull(program.functionManager.getFunctionAt(program.addr(0x084b)))
            assertFalse(convention(0x0840) == "__asm_saved", "fall-through")
            assertEquals("__asm_saved", convention(0x0860))
            val helper = program.functionManager.getFunctionAt(program.addr(0x0860))
            program.withTransaction {
                helper.updateFunction(
                    "__asm",
                    ReturnParameterImpl(ByteDataType.dataType, program),
                    listOf(ParameterImpl("a", ByteDataType.dataType, program)),
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    false,
                    SourceType.IMPORTED,
                )
                GameBoyCalleeSavedAnalyzer().added(program, helper.body, TaskMonitor.DUMMY, MessageLog())
            }
            assertEquals("__asm", helper.callingConventionName, "imported")
            assertEquals(SourceType.IMPORTED, helper.signatureSource)
        }

    @Test
    fun `dispatchers are not assumed without options`() =
        analyze("", "") { program ->
            assertTrue(program.refs(0x0158, RefType.CALL_OVERRIDE_UNCONDITIONAL).isEmpty())
            assertTrue(program.refs(0x015e, RefType.COMPUTED_JUMP).isEmpty())
        }

    @Test
    fun `dispatcher addresses parse`() =
        assertEquals(setOf(0x0699L, 0x0L, 0x28L), GameBoyBankAnalyzer.parseAddresses("0x0699, \$0000 28 bogus"))
}
