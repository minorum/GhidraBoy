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
import ghidra.program.model.data.DataImage
import ghidra.program.model.data.DataUtilities
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.awt.image.BufferedImage

private val LOGO =
    "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

class Gb2bppTileDataTypeTest : IntegrationTest() {
    // every row: low bitplane 0x0f, high bitplane 0x33
    private val tile = ByteArray(16) { if (it % 2 == 0) 0x0f else 0x33 }

    @Test
    fun `tile rows combine the low and high bitplane bytes into shades`() =
        assertEquals(List(8) { listOf(0, 0, 2, 2, 1, 1, 3, 3) }.flatten(), Gb2bppTileDataType.shades(tile).toList())

    @Test
    fun `tile data type is built in and renders ROM bytes as images`() {
        assertNotNull(BuiltInDataTypeManager.getDataTypeManager().getDataType(CategoryPath.ROOT, Gb2bppTileDataType.NAME))
        val rom =
            ByteArray(0x8000).also { rom ->
                LOGO.copyInto(rom, 0x0104)
                (0..1).forEach { tile.copyInto(rom, 0x0200 + 16 * it) }
                // element 1, row 0: low bitplane 0xff
                rom[0x0210] = 0xff.toByte()
            }
        ProgramLoader.builder().source(rom).name("tiles.gb").loaders(GameBoyLoader::class.java).load().use { results ->
            val program = results.getPrimaryDomainObject(this)
            try {
                val address = program.addressFactory.defaultAddressSpace.getAddress(0x0200)
                val array = ArrayDataType(Gb2bppTileDataType.dataType, 2, 16)
                val data =
                    program.withTransaction {
                        DataUtilities.createData(
                            program,
                            address,
                            array,
                            -1,
                            false,
                            DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
                        )
                    }
                assertEquals(2, data.numComponents)
                val image = (data.getComponent(1).value as DataImage).imageIcon.image as BufferedImage
                assertEquals(8 to 8, image.width to image.height)
                assertEquals(
                    listOf(0xaaaaaa, 0xaaaaaa, 0x000000, 0x000000, 0xaaaaaa, 0xaaaaaa, 0x000000, 0x000000),
                    (0 until 8).map { image.getRGB(it, 0) and 0xffffff },
                )
                assertEquals(
                    listOf(0xffffff, 0xffffff, 0x555555, 0x555555, 0xaaaaaa, 0xaaaaaa, 0x000000, 0x000000),
                    (0 until 8).map { image.getRGB(it, 7) and 0xffffff },
                )
            } finally {
                program.release(this)
            }
        }
    }
}
