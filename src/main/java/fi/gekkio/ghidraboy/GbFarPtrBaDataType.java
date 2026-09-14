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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

// bank byte, then address word (pret dba); Address values get references from the listing
public class GbFarPtrBaDataType extends BuiltIn {
    public GbFarPtrBaDataType() {
        this(null);
    }

    public GbFarPtrBaDataType(DataTypeManager dtm) {
        this("gb_far_ptr_ba", dtm);
    }

    protected GbFarPtrBaDataType(String name, DataTypeManager dtm) {
        super(CategoryPath.ROOT, name, dtm);
    }

    protected int bankOffset() {
        return 0;
    }

    protected int addressOffset() {
        return 1;
    }

    @Override
    public int getLength() {
        return 3;
    }

    // arrays and structures otherwise pad each entry to 4 bytes
    @Override
    public int getAlignment() {
        return 1;
    }

    @Override
    public int getAlignedLength() {
        return getLength();
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return dtm == getDataTypeManager() ? this : new GbFarPtrBaDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "Game Boy far pointer: bank byte, then address word";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return getName();
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        var memory = buf.getMemory();
        if (memory == null) {
            return null;
        }
        try {
            return target(memory.getProgram(), buf.getByte(bankOffset()) & 0xff, buf.getShort(addressOffset()) & 0xffff);
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    @Override
    public Class<?> getValueClass(Settings settings) {
        return Address.class;
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        return getValue(buf, settings, length) instanceof Address address ? address.toString(true) : "??";
    }

    @Override
    public String getDefaultLabelPrefix() {
        return "FAR_PTR";
    }

    // banked ROM area in romN, anything else in the default space; null for banks the ROM doesn't have
    static Address target(Program program, int bank, int offset) {
        if (bank == 0 || offset < 0x4000 || offset >= 0x8000) {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        var block = program.getMemory().getBlock("rom" + bank);
        return block != null && block.isOverlay() ? block.getStart().getAddressSpace().getAddress(offset) : null;
    }
}
