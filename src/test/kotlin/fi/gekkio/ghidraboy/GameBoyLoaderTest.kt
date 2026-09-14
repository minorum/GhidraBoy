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

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.listing.Program
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private val LOGO =
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class GameBoyLoaderTest : IntegrationTest() {
    // valid logo, header fields and checksum
    private fun rom(
        size: Int,
        header: Map<Int, Int> = emptyMap(),
    ): ByteArray =
        ByteArray(size).also { rom ->
            LOGO.copyInto(rom, 0x0104)
            rom[0x0148] = (size / 0x8000).countTrailingZeroBits().toByte()
            header.forEach { (offset, value) -> rom[offset] = value.toByte() }
            var checksum = 0
            for (i in 0x0134..0x014c) {
                checksum = checksum - rom[i].toInt().and(0xff) - 1
            }
            rom[0x014d] = checksum.toByte()
        }

    private fun <T> load(
        bytes: ByteArray,
        log: MessageLog = MessageLog(),
        f: (Program) -> T,
    ): T =
        ProgramLoader
            .builder()
            .source(bytes)
            .name("test.gb")
            .log(log)
            .loaders(GameBoyLoader::class.java)
            .load()
            .use { results ->
                val program = results.getPrimaryDomainObject(this)
                try {
                    f(program)
                } finally {
                    program.release(this)
                }
            }

    private fun blocks(
        bytes: ByteArray,
        prefix: String,
    ): Map<String, Long> =
        load(bytes) { program ->
            program.memory.blocks
                .filter { it.name.startsWith(prefix) }
                .associate { it.name to it.size }
        }

    @Test
    fun `unbanked ROM smaller than 32 kB`() = assertEquals(mapOf("rom" to 0x4000L), blocks(rom(0x4000), "rom"))

    @Test
    fun `unbanked 32 kB ROM`() = assertEquals(mapOf("rom" to 0x8000L), blocks(rom(0x8000), "rom"))

    @Test
    fun `banked ROM with partial last bank`() =
        assertEquals(
            mapOf("rom0" to 0x4000L, "rom1" to 0x4000L, "rom2" to 0x1000L),
            blocks(rom(0x9000), "rom"),
        )

    @Test
    fun `ROM bank numbers wrap past the ROM size`() =
        load(rom(0x10000).also { rom -> (1..3).forEach { rom[it * 0x4000] = it.toByte() } }) { program ->
            val bankBytes = GameBoyEmulation.bankBytes(program)
            assertEquals(1.toByte(), bankBytes.apply(5)?.get(0))
            assertEquals(3.toByte(), bankBytes.apply(3)?.get(0))
        }

    @Test
    fun `cartridge RAM banks follow the header`() {
        assertEquals(mapOf("xram" to 0x2000L), blocks(rom(0x8000, mapOf(0x0149 to 0x02)), "xram"))
        assertEquals(
            mapOf("xram0" to 0x2000L, "xram1" to 0x2000L, "xram2" to 0x2000L, "xram3" to 0x2000L),
            blocks(rom(0x8000, mapOf(0x0149 to 0x03)), "xram"),
        )
    }

    @Test
    fun `vectors with code are entry points`() {
        // rst08 and intr_stat hold 0xff filler
        val bytes = rom(0x8000).also { rom -> (0x00..0x60 step 8).forEach { rom[it] = 0xc9.toByte() } }
        bytes[0x08] = 0xff.toByte()
        bytes[0x48] = 0xff.toByte()
        load(bytes) { program ->
            val entries =
                program.symbolTable.externalEntryPointIterator
                    .iterator()
                    .asSequence()
                    .map { it.offset }
                    .toSet()
            assertEquals((0x00L..0x60L step 8).toSet() - setOf(0x08L, 0x48L) + 0x100L, entries)
        }
    }

    @Test
    fun `echo RAM mirrors work RAM`() {
        load(rom(0x8000)) { program ->
            val echo = program.memory.getBlock("echo")!!
            assertTrue(echo.isMapped)
            assertEquals(0xe000L, echo.start.offset)
            assertEquals(0x1e00L, echo.size)
        }
        load(rom(0x8000, mapOf(0x0143 to 0x80))) { program ->
            assertEquals(0x1000L, program.memory.getBlock("echo0").size)
            val echo1 = program.memory.getBlock("echo1")
            assertEquals(0xe00L, echo1.size)
            val mapped =
                echo1.sourceInfos
                    .single()
                    .mappedRange
                    .get()
            assertEquals("wram1", program.memory.getBlock(mapped.minAddress).name)
        }
    }

    @Test
    fun `hardware registers use bitfield types`() =
        load(rom(0x8000)) { program ->
            val space = program.addressFactory.defaultAddressSpace
            assertEquals(
                "lcdc",
                program.listing
                    .getDataAt(space.getAddress(0xff40))
                    .dataType.name,
            )
            assertEquals(
                "stat",
                program.listing
                    .getDataAt(space.getAddress(0xff41))
                    .dataType.name,
            )
            assertEquals(
                "interrupts",
                program.listing
                    .getDataAt(space.getAddress(0xffff))
                    .dataType.name,
            )
            assertEquals(1, DataTypes.LCDC.length)
        }

    @Test
    fun `header checks are logged`() {
        val good = MessageLog()
        load(rom(0x8000, mapOf(0x0147 to 0x1b)), good) {}
        assertTrue(good.toString().contains("Cartridge type: MBC5_RAM_BATT"), good.toString())
        assertFalse(good.toString().contains("checksum"), good.toString())
        assertFalse(good.toString().contains("size mismatch"), good.toString())

        val bad = MessageLog()
        load(rom(0x8000).also { it[0x014d] = (it[0x014d] + 1).toByte() }, bad) {}
        assertTrue(bad.toString().contains("Header checksum mismatch"), bad.toString())

        val truncated = MessageLog()
        load(rom(0x4000, mapOf(0x0148 to 0x00)), truncated) {}
        assertTrue(truncated.toString().contains("ROM size mismatch"), truncated.toString())
    }
}
