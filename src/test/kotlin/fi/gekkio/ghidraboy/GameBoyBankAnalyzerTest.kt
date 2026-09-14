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

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
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
    fun `upper bank bits select banks past the low register range`() =
        analyze("", "", mbc1Rom(0x100000)) { program ->
            assertEquals(setOf(program.bankAddr(0x25, 0x4000)), program.refs(0x015a, RefType.CALL_OVERRIDE_UNCONDITIONAL))
        }

    @Test
    fun `upper bank bits wrap on small ROMs`() =
        analyze("", "", mbc1Rom(0x10000)) { program ->
            assertEquals(setOf(program.bankAddr(1, 0x4000)), program.refs(0x015a, RefType.CALL_OVERRIDE_UNCONDITIONAL))
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
    fun `dispatchers are not assumed without options`() =
        analyze("", "") { program ->
            assertTrue(program.refs(0x0158, RefType.CALL_OVERRIDE_UNCONDITIONAL).isEmpty())
            assertTrue(program.refs(0x015e, RefType.COMPUTED_JUMP).isEmpty())
        }

    @Test
    fun `dispatcher addresses parse`() =
        assertEquals(setOf(0x0699L, 0x0L, 0x28L), GameBoyBankAnalyzer.parseAddresses("0x0699, \$0000 28 bogus"))
}
