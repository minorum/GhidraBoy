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

class GbCgbPaletteDataTypeTest : IntegrationTest() {
    @Test
    fun `BGR555 words scale to 24-bit RGB`() =
        assertEquals(
            listOf(0xff0000, 0x00ff00, 0x0000ff, 0xffffff, 0xffffff, 0x000000, 0x847bff),
            listOf(0x001f, 0x03e0, 0x7c00, 0x7fff, 0xffff, 0x8000, 0x7df0).map { GbCgbColorDataType.rgb(it) },
        )

    @Test
    fun `color and palette data types are built in and render ROM bytes`() {
        listOf(GbCgbColorDataType.NAME, GbCgbPaletteDataType.NAME).forEach {
            assertNotNull(BuiltInDataTypeManager.getDataTypeManager().getDataType(CategoryPath.ROOT, it), it)
        }
        val rom =
            ByteArray(0x8000).also { rom ->
                LOGO.copyInto(rom, 0x0104)
                // palette 0 all black; palette 1 red, green, blue, white; then one color
                byteArrayOf(0x1f, 0x00, 0xe0.toByte(), 0x03, 0x00, 0x7c, 0xff.toByte(), 0x7f).copyInto(rom, 0x0208)
                byteArrayOf(0xff.toByte(), 0xff.toByte()).copyInto(rom, 0x0210)
            }
        ProgramLoader.builder().source(rom).name("palettes.gb").loaders(GameBoyLoader::class.java).load().use { results ->
            val program = results.getPrimaryDomainObject(this)
            try {
                val space = program.addressFactory.defaultAddressSpace
                val (palettes, color) =
                    program.withTransaction {
                        listOf(
                            0x0200L to ArrayDataType(GbCgbPaletteDataType.dataType, 2, 8),
                            0x0210L to GbCgbColorDataType.dataType,
                        ).map { (offset, type) ->
                            DataUtilities.createData(
                                program,
                                space.getAddress(offset),
                                type,
                                -1,
                                false,
                                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
                            )
                        }
                    }
                assertEquals(2, palettes.numComponents)
                assertEquals("#000000 #000000 #000000 #000000", palettes.getComponent(0).defaultValueRepresentation)
                val palette = palettes.getComponent(1)
                assertEquals("#FF0000 #00FF00 #0000FF #FFFFFF", palette.defaultValueRepresentation)
                val image = (palette.value as DataImage).imageIcon.image as BufferedImage
                assertEquals(32 to 8, image.width to image.height)
                assertEquals(listOf(0xff0000, 0x00ff00, 0x0000ff, 0xffffff), (0 until 4).map { image.getRGB(8 * it + 4, 4) and 0xffffff })
                assertEquals("#FFFFFF", color.defaultValueRepresentation)
                assertEquals(8 to 8, ((color.value as DataImage).imageIcon.image as BufferedImage).let { it.width to it.height })
            } finally {
                program.release(this)
            }
        }
    }
}
