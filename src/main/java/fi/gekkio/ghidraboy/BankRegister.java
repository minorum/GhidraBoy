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

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

// ROM bank select registers of the cartridge's MBC: low bits, and upper bits placed above them
record BankRegister(int mask, boolean zeroSelectsOne, long start, long end, boolean mbc2, long highStart, long highEnd, int highShift, int highMask) {
    static BankRegister of(Program program) {
        try {
            return of(program.getMemory().getByte(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0147)) & 0xff);
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    // ponytail: MBC1 multicart wiring and MBC30 8-bit banks are not modelled
    static BankRegister of(int cartType) {
        return switch (cartType) {
            case 0x01, 0x02, 0x03 -> new BankRegister(0x1f, true, 0x2000, 0x3fff, false, 0x4000, 0x5fff, 5, 0x03);
            case 0x05, 0x06 -> new BankRegister(0x0f, true, 0x0000, 0x3fff, true, 0, -1, 0, 0);
            case 0x0f, 0x10, 0x11, 0x12, 0x13 -> new BankRegister(0x7f, true, 0x2000, 0x3fff, false, 0, -1, 0, 0);
            case 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e -> new BankRegister(0xff, false, 0x2000, 0x2fff, false, 0x3000, 0x3fff, 8, 0x01);
            default -> null;
        };
    }

    // romN blocks created by the loader
    static int romBanks(Program program) {
        var memory = program.getMemory();
        var banks = 1;
        while (memory.getBlock("rom" + banks) != null) {
            banks++;
        }
        return banks;
    }

    boolean contains(long address) {
        return containsLow(address) || containsHigh(address);
    }

    boolean containsHigh(long address) {
        return address >= highStart && address <= highEnd;
    }

    private boolean containsLow(long address) {
        // MBC2 selects the ROM bank when address bit 8 is set
        return address >= start && address <= end && (!mbc2 || (address & 0x100) != 0);
    }

    // bank after writing value to address
    int apply(int bank, long address, int value) {
        if (containsLow(address)) {
            var low = value & mask;
            return (bank & ~mask) | (low == 0 && zeroSelectsOne ? 1 : low);
        }
        if (containsHigh(address)) {
            return (bank & ~(highMask << highShift)) | ((value & highMask) << highShift);
        }
        return bank;
    }
}
