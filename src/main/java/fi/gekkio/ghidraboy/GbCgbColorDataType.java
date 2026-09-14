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
import java.util.Arrays;
import java.util.stream.Collectors;

// CGB BGR555 color: little-endian word 0bbbbbgggggrrrrr
public class GbCgbColorDataType extends BuiltIn implements Resource {
    static final String NAME = "gb_cgb_color";

    public static final GbCgbColorDataType dataType = new GbCgbColorDataType();

    static final int SWATCH = 8;

    public GbCgbColorDataType() {
        this(null);
    }

    public GbCgbColorDataType(DataTypeManager dtm) {
        this(NAME, dtm);
    }

    protected GbCgbColorDataType(String name, DataTypeManager dtm) {
        super(CategoryPath.ROOT, name, dtm);
    }

    int colorCount() {
        return 1;
    }

    @Override
    public int getLength() {
        return 2 * colorCount();
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return dtm == getDataTypeManager() ? this : new GbCgbColorDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "Game Boy Color BGR555 color";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return getName();
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        var colors = colors(buf);
        return colors == null ? "??" : Arrays.stream(colors).mapToObj("#%06X"::formatted).collect(Collectors.joining(" "));
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        var colors = colors(buf);
        return colors == null ? null : new SwatchImage(colors, getRepresentation(buf, settings, length));
    }

    @Override
    public Class<?> getValueClass(Settings settings) {
        return DataImage.class;
    }

    @Override
    public String getDefaultLabelPrefix() {
        return "COLOR";
    }

    private int[] colors(MemBuffer buf) {
        var bytes = new byte[getLength()];
        if (buf.getBytes(bytes, 0) != bytes.length) {
            return null;
        }
        var colors = new int[colorCount()];
        for (int i = 0; i < colors.length; i++) {
            colors[i] = rgb((bytes[2 * i] & 0xff) | (bytes[2 * i + 1] & 0xff) << 8);
        }
        return colors;
    }

    // 24-bit RGB, bit 15 ignored
    static int rgb(int word) {
        return scale(word) << 16 | scale(word >> 5) << 8 | scale(word >> 10);
    }

    private static int scale(int channel) {
        var value = channel & 0x1f;
        return value << 3 | value >> 2;
    }

    static class SwatchImage extends DataImage {
        private final BufferedImage image;

        SwatchImage(int[] colors, String description) {
            image = new BufferedImage(SWATCH * colors.length, SWATCH, BufferedImage.TYPE_INT_RGB);
            for (int x = 0; x < image.getWidth(); x++) {
                for (int y = 0; y < SWATCH; y++) {
                    image.setRGB(x, y, colors[x / SWATCH]);
                }
            }
            setDescription(description);
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
