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

import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.function.IntFunction;

public final class GameBoyEmulation {
    private GameBoyEmulation() {
    }

    // ponytail: interrupts and HALT/STOP wake-up are not emulated, the userops only let execution continue
    public static final class UseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
        @PcodeUserop
        public void IME(byte[] enable) {
        }

        @PcodeUserop
        public void halt() {
        }

        @PcodeUserop
        public void stop() {
        }
    }

    public static class Emulator extends PcodeEmulator {
        public Emulator(Language language, PcodeEmulationCallbacks<byte[]> callbacks) {
            super(language, callbacks);
        }

        @Override
        protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
            return new UseropLibrary();
        }
    }

    // maps the selected ROM bank into 0x4000-0x7FFF, bank 1 until the first bank register write
    public static class BankSwitching implements PcodeEmulationCallbacks<byte[]> {
        private final BankRegister register;
        private final IntFunction<byte[]> bankBytes;
        private int bank = 1;
        private boolean mapped;

        BankSwitching(BankRegister register, IntFunction<byte[]> bankBytes) {
            this.register = register;
            this.bankBytes = bankBytes;
        }

        @Override
        public <A, U> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
            if (address.isMemoryAddress() && register.contains(address.getOffset()) && value instanceof byte[] bytes && bytes.length > 0) {
                bank = register.apply(bank, address.getOffset(), bytes[0] & 0xff);
                map(piece, address.getAddressSpace());
            }
        }

        @Override
        public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
            if (mapped || set.isEmpty()) {
                return set;
            }
            var space = set.getMinAddress().getAddressSpace();
            if (!space.isMemorySpace()) {
                return set;
            }
            var window = new AddressSet(space.getAddress(0x4000), space.getAddress(0x7fff));
            if (!set.intersects(window) || !map(piece, space)) {
                return set;
            }
            return set.subtract(window);
        }

        @SuppressWarnings("unchecked")
        private <A, U> boolean map(PcodeExecutorStatePiece<A, U> piece, AddressSpace space) {
            var bytes = bankBytes.apply(bank);
            if (bytes == null) {
                return false;
            }
            piece.setVarInternal(space, 0x4000, bytes.length, (U) bytes);
            mapped = true;
            return true;
        }
    }

    static IntFunction<byte[]> bankBytes(Program program) {
        var memory = program.getMemory();
        var banks = BankRegister.romBanks(program);
        return bank -> {
            // MBC wraps bank numbers past the ROM size
            var block = memory.getBlock("rom" + bank % banks);
            if (block == null) {
                return null;
            }
            var bytes = new byte[(int) block.getSize()];
            try {
                block.getBytes(block.getStart(), bytes);
            } catch (MemoryAccessException e) {
                return null;
            }
            return bytes;
        };
    }
}
