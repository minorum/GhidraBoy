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
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallfixup;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.List;

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
        if (type == InjectPayload.CALLFIXUP_TYPE && GameBoyJumpTableAnalyzer.INLINE_TABLE_FIXUP.equals(name)) {
            return new InlineJumpTable(sourceName);
        }
        return super.allocateInject(sourceName, name, type);
    }

    // SP += 2; goto [inst_next + A * 2], bounded by the cases the analyzer marked at the call
    static final class InlineJumpTable extends InjectPayloadCallfixup {
        private static final int MAX_ENTRIES = 256;

        InlineJumpTable(String sourceName) {
            super(sourceName);
        }

        @Override
        public PcodeOp[] getPcode(Program program, InjectContext context) {
            var af = program.getAddressFactory();
            var at = context.baseAddr;
            var sp = register(program, "SP");
            var a = register(program, "A");
            var unique = new UniqueVarnodes(program);
            // table entries, not references: repeated targets share one reference
            var cases = GameBoyJumpTableAnalyzer.markedTargets(program, at).isEmpty() ? 0 : tableEntries(program, context.nextAddr);
            var ops = new ArrayList<PcodeOp>();
            ops.add(op(at, ops, PcodeOp.INT_ADD, sp, constant(af, 2, sp.getSize()), sp));
            Varnode outside = null;
            PcodeOp guard = null;
            if (cases > 0) {
                outside = unique.next(1);
                ops.add(op(at, ops, PcodeOp.INT_LESSEQUAL, constant(af, cases, 1), a, outside));
                guard = op(at, ops, PcodeOp.CBRANCH, null, outside, null);
                ops.add(guard);
            }
            var index = unique.next(2);
            ops.add(op(at, ops, PcodeOp.INT_ZEXT, a, null, index));
            var offset = unique.next(2);
            ops.add(op(at, ops, PcodeOp.INT_ADD, index, index, offset));
            var entry = unique.next(2);
            ops.add(op(at, ops, PcodeOp.INT_ADD, constant(af, context.nextAddr.getOffset(), 2), offset, entry));
            var target = unique.next(2);
            ops.add(op(at, ops, PcodeOp.LOAD, spaceId(af, context.nextAddr), entry, target));
            ops.add(op(at, ops, PcodeOp.BRANCHIND, target, null, null));
            if (guard != null) {
                // out-of-range index: unreachable return instead of more table entries
                guard.setInput(constant(af, ops.size() - guard.getSeqnum().getTime(), 4), 0);
                var ret = unique.next(2);
                ops.add(op(at, ops, PcodeOp.LOAD, spaceId(af, context.nextAddr), sp, ret));
                ops.add(op(at, ops, PcodeOp.RETURN, ret, null, null));
            }
            return ops.toArray(PcodeOp[]::new);
        }

        // consecutive words markTable created after the call
        private static int tableEntries(Program program, Address table) {
            var listing = program.getListing();
            var count = 0;
            try {
                while (count < MAX_ENTRIES && listing.getDataAt(table.addNoWrap(2L * count)) instanceof Data data
                        && data.getDataType() instanceof WordDataType) {
                    count++;
                }
            } catch (AddressOverflowException e) {
                // the address space ends the table
            }
            return count;
        }

        private static PcodeOp op(Address at, List<PcodeOp> ops, int opcode, Varnode in0, Varnode in1, Varnode out) {
            var inputs = in1 == null ? (in0 == null ? new Varnode[0] : new Varnode[] {in0}) : new Varnode[] {in0, in1};
            if (opcode == PcodeOp.CBRANCH) {
                inputs = new Varnode[] {null, in1};
            }
            return new PcodeOp(at, ops.size(), opcode, inputs, out);
        }

        private static Varnode register(Program program, String name) {
            var register = program.getRegister(name);
            return new Varnode(register.getAddress(), register.getMinimumByteSize());
        }

        private static Varnode constant(AddressFactory af, long value, int size) {
            return new Varnode(af.getConstantAddress(value), size);
        }

        private static Varnode spaceId(AddressFactory af, Address address) {
            return new Varnode(af.getConstantAddress(address.getAddressSpace().getSpaceID()), 4);
        }
    }

    // temporaries above the language's unique base
    private static final class UniqueVarnodes {
        private final AddressFactory af;
        private long next;

        UniqueVarnodes(Program program) {
            af = program.getAddressFactory();
            next = ((SleighLanguage) program.getLanguage()).getUniqueBase();
        }

        Varnode next(int size) {
            var varnode = new Varnode(af.getUniqueSpace().getAddress(next), size);
            next += 0x10;
            return varnode;
        }
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
