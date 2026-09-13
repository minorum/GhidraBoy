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
    ubyteArrayOf(
        0xceu, 0xedu, 0x66u, 0x66u, 0xccu, 0x0du, 0x00u, 0x0bu, 0x03u, 0x73u, 0x00u, 0x83u, 0x00u, 0x0cu, 0x00u, 0x0du,
        0x00u, 0x08u, 0x11u, 0x1fu, 0x88u, 0x89u, 0x00u, 0x0eu, 0xdcu, 0xccu, 0x6eu, 0xe6u, 0xddu, 0xddu, 0xd9u, 0x99u,
        0xbbu, 0xbbu, 0x67u, 0x63u, 0x6eu, 0x0eu, 0xecu, 0xccu, 0xddu, 0xdcu, 0x99u, 0x9fu, 0xbbu, 0xb9u, 0x33u, 0x3eu,
    ).asByteArray()

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
