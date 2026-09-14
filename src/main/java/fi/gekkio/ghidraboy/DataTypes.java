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

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import java.util.Arrays;

public final class DataTypes {
    private DataTypes() {
    }

    private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "Game Boy");

    public static final ByteDataType u8 = ByteDataType.dataType;
    public static final WordDataType u16 = WordDataType.dataType;
    public static final CharDataType ch = CharDataType.dataType;

    public static final TypeDef LOGO;
    public static final Enum CGB_FLAG;
    public static final Structure TITLE_BLOCK_OLD;
    public static final Structure TITLE_BLOCK_NEW;
    public static final Union TITLE_BLOCK;
    public static final Enum SGB_FLAG;
    public static final Enum CART_TYPE;
    public static final Enum ROM_SIZE;
    public static final Enum RAM_SIZE;
    public static final Enum REGION;
    public static final Structure HEADER;
    public static final Enum LCDC;
    public static final Structure STAT;
    public static final Enum INTERRUPTS;
    public static final Enum P1;
    public static final Enum SC;
    public static final Enum TAC;
    public static final Structure NR10;
    public static final Structure NRX1;
    public static final Structure NRX2;
    public static final Structure NRX4;
    public static final Enum NR30;
    public static final Structure NR32;
    public static final Structure NR43;
    public static final Structure NR50;
    public static final Enum NR51;
    public static final Enum NR52;
    public static final Structure PALETTE;
    public static final Enum KEY1;
    public static final Structure VBK;
    public static final Enum RP;
    public static final Structure PALETTE_INDEX;
    public static final Structure SVBK;

    static {
        LOGO = new TypedefDataType(PATH, "logo", array(u8, 0x30));

        CGB_FLAG = new EnumDataType(PATH, "cgb_flag", 1);
        CGB_FLAG.add("NONE", 0x00);
        CGB_FLAG.add("SUPPORT", 0x80);
        CGB_FLAG.add("ONLY", 0xc0);

        TITLE_BLOCK_OLD = new StructureDataType(PATH, "title_block_old", 0);
        TITLE_BLOCK_OLD.add(array(ch, 15), "title", null);
        TITLE_BLOCK_OLD.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK_NEW = new StructureDataType(PATH, "title_block_new", 0);
        TITLE_BLOCK_NEW.add(array(ch, 11), "title", null);
        TITLE_BLOCK_NEW.add(array(ch, 4), "manufacturer_code", null);
        TITLE_BLOCK_NEW.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK = new UnionDataType(PATH, "title_block");
        TITLE_BLOCK.add(array(ch, 16), "title_only", null);
        TITLE_BLOCK.add(TITLE_BLOCK_OLD, "old_format", null);
        TITLE_BLOCK.add(TITLE_BLOCK_NEW, "new_format", null);

        SGB_FLAG = new EnumDataType(PATH, "sgb_flag", 1);
        SGB_FLAG.add("NONE", 0x00);
        SGB_FLAG.add("SUPPORT", 0x03);

        CART_TYPE = new EnumDataType(PATH, "cart_type", 1);
        CART_TYPE.add("ROM_ONLY", 0x00);
        CART_TYPE.add("MBC1", 0x01);
        CART_TYPE.add("MBC1_RAM", 0x02);
        CART_TYPE.add("MBC1_RAM_BATT", 0x03);
        CART_TYPE.add("MBC2", 0x05);
        CART_TYPE.add("MBC2_BATT", 0x06);
        CART_TYPE.add("RAM", 0x08);
        CART_TYPE.add("RAM_BATT", 0x09);
        CART_TYPE.add("MMM01", 0x0b);
        CART_TYPE.add("MMM01_RAM", 0x0c);
        CART_TYPE.add("MMM01_RAM_BATT", 0x0d);
        CART_TYPE.add("MBC3_RTC_BATT", 0x0f);
        CART_TYPE.add("MBC3_RAM_RTC_BATT", 0x10);
        CART_TYPE.add("MBC3", 0x11);
        CART_TYPE.add("MBC3_RAM", 0x12);
        CART_TYPE.add("MBC3_RAM_BATT", 0x13);
        CART_TYPE.add("MBC5", 0x19);
        CART_TYPE.add("MBC5_RAM", 0x1a);
        CART_TYPE.add("MBC5_RAM_BATT", 0x1b);
        CART_TYPE.add("MBC5_RUMBLE", 0x1c);
        CART_TYPE.add("MBC5_RAM_RUMBLE", 0x1d);
        CART_TYPE.add("MBC5_RAM_BATT_RUMBLE", 0x1e);
        CART_TYPE.add("MBC6", 0x20);
        CART_TYPE.add("MBC7", 0x22);
        CART_TYPE.add("POCKET_CAMERA", 0xfc);
        CART_TYPE.add("TAMA5", 0xfd);
        CART_TYPE.add("HUC3", 0xfe);
        CART_TYPE.add("HUC1", 0xff);

        ROM_SIZE = new EnumDataType(PATH, "rom_size", 1);
        ROM_SIZE.add("32K", 0x00);
        ROM_SIZE.add("64K", 0x01);
        ROM_SIZE.add("128K", 0x02);
        ROM_SIZE.add("256K", 0x03);
        ROM_SIZE.add("512K", 0x04);
        ROM_SIZE.add("1MB", 0x05);
        ROM_SIZE.add("2MB", 0x06);
        ROM_SIZE.add("4MB", 0x07);
        ROM_SIZE.add("8MB", 0x08);

        RAM_SIZE = new EnumDataType(PATH, "ram_size", 1);
        RAM_SIZE.add("NONE", 0x00);
        RAM_SIZE.add("2KB", 0x01);
        RAM_SIZE.add("8KB", 0x02);
        RAM_SIZE.add("32KB", 0x03);
        RAM_SIZE.add("128KB", 0x04);
        RAM_SIZE.add("64KB", 0x05);

        REGION = new EnumDataType(PATH, "region", 1);
        REGION.add("JAPAN", 0x00);
        REGION.add("WORLD", 0x01);

        HEADER = new StructureDataType(PATH, "header", 0);
        HEADER.add(TITLE_BLOCK, "title_block", null);
        HEADER.add(array(ch, 2), "new_licensee_code", null);
        HEADER.add(SGB_FLAG, "sgb_flag", null);
        HEADER.add(CART_TYPE, "cartridge_type", null);
        HEADER.add(ROM_SIZE, "rom_size", null);
        HEADER.add(RAM_SIZE, "ram_size", null);
        HEADER.add(REGION, "region", null);
        HEADER.add(u8, "old_licensee_code", null);
        HEADER.add(u8, "mask_rom_version", null);
        HEADER.add(u8, "header_checksum", null);
        HEADER.add(u16, "global_checksum", null);

        // flag registers: constant writes decompile as ORed hardware.inc names
        LCDC = flags("lcdc", "LCDCF_BGON", 0x01, "LCDCF_OBJON", 0x02, "LCDCF_OBJ16", 0x04, "LCDCF_BG9C00", 0x08, "LCDCF_BG8800", 0x10,
                "LCDCF_WINON", 0x20, "LCDCF_WIN9C00", 0x40, "LCDCF_ON", 0x80);
        INTERRUPTS = flags("interrupts", "IEF_VBLANK", 0x01, "IEF_STAT", 0x02, "IEF_TIMER", 0x04, "IEF_SERIAL", 0x08, "IEF_JOYPAD", 0x10);
        P1 = flags("p1", "P1F_0", 0x01, "P1F_1", 0x02, "P1F_2", 0x04, "P1F_3", 0x08, "P1F_4", 0x10, "P1F_5", 0x20);
        SC = flags("sc", "SCF_SOURCE", 0x01, "SCF_SPEED", 0x02, "SCF_START", 0x80);
        TAC = flags("tac", "TACF_262KHZ", 0x01, "TACF_65KHZ", 0x02, "TACF_16KHZ", 0x03, "TACF_START", 0x04);
        NR30 = flags("nr30", "AUD3ENA_ON", 0x80);
        NR51 = flags("nr51", "AUDTERM_1_RIGHT", 0x01, "AUDTERM_2_RIGHT", 0x02, "AUDTERM_3_RIGHT", 0x04, "AUDTERM_4_RIGHT", 0x08,
                "AUDTERM_1_LEFT", 0x10, "AUDTERM_2_LEFT", 0x20, "AUDTERM_3_LEFT", 0x40, "AUDTERM_4_LEFT", 0x80);
        NR52 = flags("nr52", "AUDENA_CH1_ON", 0x01, "AUDENA_CH2_ON", 0x02, "AUDENA_CH3_ON", 0x04, "AUDENA_CH4_ON", 0x08, "AUDENA_ON", 0x80);
        KEY1 = flags("key1", "KEY1F_PREPARE", 0x01, "KEY1F_DBLSPEED", 0x80);
        RP = flags("rp", "RPF_WRITE_HI", 0x01, "RPF_DATAIN", 0x02, "RPF_ENREAD", 0xc0);

        // registers with multi-bit values: bitfields from bit 0 upwards
        STAT = bitfields("stat", "mode:2", "lyc_equal", "mode0_interrupt", "mode1_interrupt", "mode2_interrupt", "lyc_interrupt", "unused");
        NR10 = bitfields("nr10", "sweep_step:3", "sweep_decrease", "sweep_pace:3", "unused");
        NRX1 = bitfields("nrx1", "length:6", "duty:2");
        NRX2 = bitfields("nrx2", "envelope_pace:3", "envelope_increase", "volume:4");
        NRX4 = bitfields("nrx4", "period_high:3", "unused:3", "length_enable", "trigger");
        NR32 = bitfields("nr32", "unused:5", "output_level:2", "unused_7");
        NR43 = bitfields("nr43", "divider:3", "width_7bit", "shift:4");
        NR50 = bitfields("nr50", "right_volume:3", "vin_right", "left_volume:3", "vin_left");
        PALETTE = bitfields("palette", "color0:2", "color1:2", "color2:2", "color3:2");
        VBK = bitfields("vbk", "bank", "unused:7");
        PALETTE_INDEX = bitfields("palette_index", "index:6", "unused", "auto_increment");
        SVBK = bitfields("svbk", "bank:3", "unused:5");
    }

    private static Enum flags(String name, Object... namesAndValues) {
        var e = new EnumDataType(PATH, name, 1);
        for (int i = 0; i < namesAndValues.length; i += 2) {
            e.add((String) namesAndValues[i], ((Number) namesAndValues[i + 1]).longValue());
        }
        return e;
    }

    private static Structure bitfields(String name, String... fields) {
        var s = new StructureDataType(PATH, name, 0);
        s.setPackingEnabled(true);
        for (var field : fields) {
            var parts = field.split(":");
            try {
                s.addBitField(u8, parts.length > 1 ? Integer.parseInt(parts[1]) : 1, parts[0], null);
            } catch (InvalidDataTypeException e) {
                throw new IllegalStateException(e);
            }
        }
        return s;
    }

    public static void addAll(DataTypeManager m) {
        var types = new DataType[]{LOGO, CGB_FLAG, TITLE_BLOCK_OLD, TITLE_BLOCK_NEW, TITLE_BLOCK, SGB_FLAG, CART_TYPE, ROM_SIZE, RAM_SIZE, REGION, HEADER, LCDC, STAT, INTERRUPTS,
                P1, SC, TAC, NR10, NRX1, NRX2, NRX4, NR30, NR32, NR43, NR50, NR51, NR52, PALETTE, KEY1, VBK, RP, PALETTE_INDEX, SVBK};
        var c = m.createCategory(PATH);
        Arrays.stream(types).forEach(d -> c.addDataType(d, DataTypeConflictHandler.DEFAULT_HANDLER));
    }

    static Array array(DataType d, int size) {
        return new ArrayDataType(d, size, -1);
    }
}
