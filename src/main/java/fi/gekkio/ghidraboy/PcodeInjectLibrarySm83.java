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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeInjectLibrarySm83 extends PcodeInjectLibrary {
    static final String BANK_RAM = "bank_ram";

    public PcodeInjectLibrarySm83(SleighLanguage language) {
        super(language);
    }

    public PcodeInjectLibrarySm83(PcodeInjectLibrarySm83 other) {
        super(other);
    }

    @Override
    public PcodeInjectLibrary clone() {
        return new PcodeInjectLibrarySm83(this);
    }

    @Override
    public InjectPayload allocateInject(String sourceName, String name, int type) {
        if (type == InjectPayload.CALLOTHERFIXUP_TYPE && BANK_RAM.equals(name)) {
            return new BankRam(sourceName);
        }
        return super.allocateInject(sourceName, name, type);
    }

    // bank_ram(value): copy through the overlay address the analyzer referenced
    static final class BankRam extends InjectPayloadCallother {
        BankRam(String sourceName) {
            super(sourceName);
        }

        @Override
        public PcodeOp[] getPcode(Program program, InjectContext context) {
            var input = context.inputlist.get(0);
            var output = context.output.get(0);
            if (output.isAddress()) {
                output = bankVarnode(program, context.baseAddr, output);
            } else {
                input = bankVarnode(program, context.baseAddr, input);
            }
            return new PcodeOp[] {new PcodeOp(context.baseAddr, 0, PcodeOp.COPY, new Varnode[] {input}, output)};
        }

        private static Varnode bankVarnode(Program program, Address from, Varnode memory) {
            for (var ref : program.getReferenceManager().getReferencesFrom(from)) {
                var to = ref.getToAddress();
                if (ref.isMemoryReference() && to.getAddressSpace().isOverlaySpace() && to.getOffset() == memory.getOffset()) {
                    return new Varnode(to, memory.getSize());
                }
            }
            return memory;
        }
    }
}
