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
package fi.gekkio.ghidraboy;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataImage;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Resource;
import ghidra.program.model.mem.MemBuffer;

import javax.swing.ImageIcon;
import java.awt.image.BufferedImage;

// 8x8 tile as stored in VRAM: low and high bitplane byte per row
public class Gb2bppTileDataType extends BuiltIn implements Resource {
    // built-in types live in the root category, so the name carries the platform
    static final String NAME = "gb_2bpp_tile";

    public static final Gb2bppTileDataType dataType = new Gb2bppTileDataType();

    static final int SIZE = 8;
    static final int LENGTH = 2 * SIZE;
    // DMG shades 0-3
    static final int[] PALETTE = {0xffffff, 0xaaaaaa, 0x555555, 0x000000};

    public Gb2bppTileDataType() {
        this(null);
    }

    public Gb2bppTileDataType(DataTypeManager dtm) {
        super(CategoryPath.ROOT, NAME, dtm);
    }

    @Override
    public int getLength() {
        return LENGTH;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return dtm == getDataTypeManager() ? this : new Gb2bppTileDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "Game Boy 2bpp 8x8 tile (low and high bitplane byte per row)";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return NAME;
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        return "<" + NAME + ">";
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        var bytes = new byte[LENGTH];
        if (buf.getBytes(bytes, 0) != LENGTH) {
            return null;
        }
        return new TileImage(shades(bytes));
    }

    @Override
    public Class<?> getValueClass(Settings settings) {
        return DataImage.class;
    }

    @Override
    public String getDefaultLabelPrefix() {
        return "TILE";
    }

    // shade index per pixel, rows top to bottom, bit 7 leftmost
    static int[] shades(byte[] bytes) {
        var shades = new int[SIZE * SIZE];
        for (int y = 0; y < SIZE; y++) {
            int low = bytes[2 * y] & 0xff;
            int high = bytes[2 * y + 1] & 0xff;
            for (int x = 0; x < SIZE; x++) {
                int bit = 7 - x;
                shades[y * SIZE + x] = ((high >> bit) & 1) << 1 | ((low >> bit) & 1);
            }
        }
        return shades;
    }

    static class TileImage extends DataImage {
        private final BufferedImage image;

        TileImage(int[] shades) {
            image = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_RGB);
            for (int i = 0; i < shades.length; i++) {
                image.setRGB(i % SIZE, i / SIZE, PALETTE[shades[i]]);
            }
            setDescription("<" + NAME + ">");
        }

        @Override
        public ImageIcon getImageIcon() {
            return new ImageIcon(image);
        }

        @Override
        public String getImageFileType() {
            return "png";
        }
    }
}
