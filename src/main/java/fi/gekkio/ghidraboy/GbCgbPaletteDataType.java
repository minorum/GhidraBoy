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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

// CGB palette: 4 BGR555 colors
public class GbCgbPaletteDataType extends GbCgbColorDataType {
    static final String NAME = "gb_cgb_palette";

    public static final GbCgbPaletteDataType dataType = new GbCgbPaletteDataType();

    public GbCgbPaletteDataType() {
        this(null);
    }

    public GbCgbPaletteDataType(DataTypeManager dtm) {
        super(NAME, dtm);
    }

    @Override
    int colorCount() {
        return 4;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return dtm == getDataTypeManager() ? this : new GbCgbPaletteDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "Game Boy Color palette (4 BGR555 colors)";
    }

    @Override
    public String getDefaultLabelPrefix() {
        return "PALETTE";
    }
}
