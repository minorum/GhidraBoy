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
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.BuiltInDataTypeManager
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Program
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

private val LOGO =
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class GbFarPtrDataTypeTest : IntegrationTest() {
    // 64 kB ROM: banks 1-3; 32 kB ROM: unbanked
    private fun load(
        pointers: Map<Int, List<Int>>,
        size: Int = 0x10000,
        check: (Program) -> Unit,
    ) = ProgramLoader
        .builder()
        .source(
            ByteArray(size).also { rom ->
                LOGO.copyInto(rom, 0x0104)
                rom[0x0148] = (size / 0x8000).countTrailingZeroBits().toByte()
                pointers.forEach { (offset, bytes) -> bytes.forEachIndexed { i, b -> rom[offset + i] = b.toByte() } }
            },
        ).name("far.gb")
        .loaders(GameBoyLoader::class.java)
        .load()
        .use { results ->
            val program = results.getPrimaryDomainObject(this)
            try {
                check(program)
            } finally {
                program.release(this)
            }
        }

    private fun Program.apply(
        offset: Long,
        type: DataType,
    ) = withTransaction {
        DataUtilities.createData(
            this,
            addressFactory.defaultAddressSpace.getAddress(offset),
            type,
            -1,
            false,
            DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
        )
    }

    private fun Program.targets(offset: Long) =
        referenceManager
            .getReferencesFrom(addressFactory.defaultAddressSpace.getAddress(offset))
            .map { it.toAddress.toString(true) }

    @Test
    fun `far pointer data types are built in`() =
        listOf("gb_far_ptr_ba", "gb_far_ptr_ab").forEach {
            assertNotNull(BuiltInDataTypeManager.getDataTypeManager().getDataType(CategoryPath.ROOT, it), it)
        }

    @Test
    fun `far pointers reference the banked address`() =
        load(
            mapOf(
                0x0200 to listOf(0x02, 0x23, 0x41),
                0x0203 to listOf(0x23, 0x41, 0x02),
                0x0206 to listOf(0x00, 0x23, 0x41),
                0x0209 to listOf(0x03, 0x23, 0x01),
                0x020c to listOf(0x07, 0x23, 0x41),
                0x0210 to listOf(0x01, 0x00, 0x40, 0x02, 0x10, 0x40, 0x03, 0x20, 0x40),
            ),
        ) { program ->
            val ba = GbFarPtrBaDataType()
            program.apply(0x0200, ba)
            val ab = program.apply(0x0203, GbFarPtrAbDataType())
            program.apply(0x0206, ba)
            program.apply(0x0209, ba)
            program.apply(0x020c, ba)
            program.apply(0x0210, ArrayDataType(ba, 3, 3))
            assertEquals(listOf("rom2::4123"), program.targets(0x0200))
            assertEquals(listOf("rom2::4123"), program.targets(0x0203))
            assertEquals("rom2::4123", ab.defaultValueRepresentation)
            // bank 0 in the banked area has no mapped default-space memory; the home area stays in the default space
            assertEquals(emptyList<String>(), program.targets(0x0206))
            assertEquals(listOf("ram:0123"), program.targets(0x0209))
            // bank past the ROM size
            assertEquals(emptyList<String>(), program.targets(0x020c))
            assertEquals(
                listOf(listOf("rom1::4000"), listOf("rom2::4010"), listOf("rom3::4020")),
                listOf(0x0210L, 0x0213L, 0x0216L).map { program.targets(it) },
            )
        }

    @Test
    fun `far pointers into an unbanked ROM reference the default space`() =
        load(mapOf(0x0200 to listOf(0x01, 0x23, 0x41)), size = 0x8000) { program ->
            program.apply(0x0200, GbFarPtrBaDataType())
            assertEquals(listOf("ram:4123"), program.targets(0x0200))
        }
}
