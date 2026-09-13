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

import ghidra.app.util.importer.ProgramLoader
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

private val LOGO =
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class GameBoyLoaderTest : IntegrationTest() {
    private fun rom(size: Int): ByteArray = ByteArray(size).also { LOGO.copyInto(it, 0x0104) }

    private fun romBlocks(bytes: ByteArray): Map<String, Long> =
        ProgramLoader.builder().source(bytes).name("test.gb").loaders(GameBoyLoader::class.java).load().use { results ->
            val program = results.getPrimaryDomainObject(this)
            try {
                program.memory.blocks
                    .filter { it.name.startsWith("rom") }
                    .associate { it.name to it.size }
            } finally {
                program.release(this)
            }
        }

    @Test
    fun `unbanked ROM smaller than 32 kB`() = assertEquals(mapOf("rom" to 0x4000L), romBlocks(rom(0x4000)))

    @Test
    fun `unbanked 32 kB ROM`() = assertEquals(mapOf("rom" to 0x8000L), romBlocks(rom(0x8000)))

    @Test
    fun `banked ROM with partial last bank`() =
        assertEquals(
            mapOf("rom0" to 0x4000L, "rom1" to 0x4000L, "rom2" to 0x1000L),
            romBlocks(rom(0x9000)),
        )
}
