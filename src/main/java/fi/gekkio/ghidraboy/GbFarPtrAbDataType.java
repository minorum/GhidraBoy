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

// address word, then bank byte (pret dab)
public class GbFarPtrAbDataType extends GbFarPtrBaDataType {
    public GbFarPtrAbDataType() {
        this(null);
    }

    public GbFarPtrAbDataType(DataTypeManager dtm) {
        super("gb_far_ptr_ab", dtm);
    }

    @Override
    protected int bankOffset() {
        return 2;
    }

    @Override
    protected int addressOffset() {
        return 0;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return dtm == getDataTypeManager() ? this : new GbFarPtrAbDataType(dtm);
    }

    @Override
    public String getDescription() {
        return "Game Boy far pointer: address word, then bank byte";
    }
}
