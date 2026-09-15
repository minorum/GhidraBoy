# Change Log

## [Unreleased]

### Changed

- Renamed to ghidra-sm83 (extension, zip and repository). Uninstall GhidraBoy
  before installing it

## 20260915 - 2026-09-15

First release of this continuation; upstream Gekkio/GhidraBoy is archived.

### Added

- Data types `gb_2bpp_tile` (8×8 2bpp tile image), `gb_far_ptr_ba` /
  `gb_far_ptr_ab` (bank + address pointers referencing banked ROM),
  `gb_cgb_color` and `gb_cgb_palette` (BGR555 colors with swatches)
- "Game Boy Interrupt Handlers" analyzer: `__interrupt` convention (no
  parameters, every register preserved) on vectors and their handlers
- "Game Boy Callee-Saved Registers" analyzer: `__asm_saved` on functions that
  push BC, DE and HL on entry and pop them before every return, including
  balanced inner PUSH/POP pairs
- "Game Boy Unowned Code" analyzer: code disassembled later is attached to the
  functions jumping into it; home code entered only from banked code becomes
  its own function
- Routines copied from ROM into RAM are mapped as executable `wram_code_*` /
  `hram_code_*` overlays, and calls and jumps into the copy target them
- Inline jump table dispatchers decompile as a switch bounded by the table
  size or a preceding `AND n` / `CP n`
- Configurable inline argument dispatchers in the bank analyzer

- RST and interrupt vectors are entry points, so analysis creates functions there
- Echo RAM blocks mapped onto work RAM
- Cartridge RAM banks from the header RAM size, as overlays
- Hardware register data types: flag enums with hardware.inc names for LCDC,
  IE/IF, P1, SC, TAC, NR30, NR51, NR52, KEY1 and RP; bitfield structs for STAT,
  NR10, NRx1, NRx2, NRx4, NR32, NR43, NR44, NR50, palettes, VBK, SVBK and
  BCPS/OCPS
- Loader log: cartridge type, header checksum and ROM size mismatches
- Calling conventions `__asm_a`, `__asm_hl`, `__asm_f`, `__asm_void` and
  `__asm_saved` (callee preserves BC, DE and HL)
- "Game Boy Bank Switching" analyzer: resolves calls into banked ROM after
  constant MBC bank register writes, including MBC1/MBC5 upper bank bits, plus
  optional inline far call and jump table dispatchers configured by address
- "Game Boy RAM Banks" analyzer: moves GBC VRAM/WRAM references into the bank
  selected by a constant `VBK`/`SVBK` write; the decompiler follows them for
  `LD A,(nn)` and `LD (nn),A`
- "Game Boy JP (HL) Jump Tables" analyzer: recovers word jump tables
  dispatched through `LD HL,table` ... `LD A,(HL+)` / `LD H,(HL)` / `LD L,A` /
  `JP HL` when Ghidra's switch recovery finds nothing or reads past the table
- "Game Boy (SM83) Emulator" for the Debugger: runs `IME`/`HALT`/`STOP` and
  switches ROM banks on MBC register writes, including upper bank bits (no
  interrupts)

### Changed

- Only I/O registers that change without CPU writes are volatile (declared in
  the processor spec), so the decompiler shows register writes such as
  `LCDC = LCDC | LCDCF_ON`. In existing projects, clear the Volatile flag of the
  `io` and `ie` blocks in the Memory Map to get the same result
- Add support for Ghidra 12.1.3
- GBC VRAM bank 0 and WRAM bank 1 are default-space blocks, so absolute
  `$8000-$9FFF` and `$D000-$DFFF` references hit mapped memory
- Drop support for Ghidra 11.x
- Build with Java 21 target
- SBC carry is expressed as a comparison, so 16-bit `SUB` / `SBC` compares
  decompile as a three-way byte comparison
- MBC register writes decompile as `mbc_write(address, value)`
- `LDH (n)` operands display the `$FFxx` address
- Far `JP` into banked ROM and `JP` into RAM routines are tail calls
- Calls clobber F
- Non-returning function discovery is disabled for SM83
- The header jump target is the start entry point

### Fixed

- ADC carry flag was never set when only the carry-in overflowed
- SBC zero flag was computed from the old A value
- SBC carry flag missed the borrow for operand 0xff with carry-in
- ROMs that are not a whole number of 16 kB blocks failed to load
- POP AF kept the low nibble of F
- STOP is decoded as a 2-byte instruction
- DAA is implemented in p-code instead of the `daaOperand` user op
- Bank switches done by a called helper are tracked
- `JP (HL)` tables with an 8-bit index added with carry into H are recovered
- Table targets blocked by cleared code are disassembled
- Resolved far `JP` targets in banked ROM are disassembled
- Decompiler timeout in functions entering another function's inline jump table

## 20250830 - 2025-08-30

### Changed

- Add support for Ghidra 11.4.2

## 20250801 - 2025-08-01

### Changed

- Add support for Ghidra 11.4.1

## 20250420 - 2025-04-20

### Changed

- Add support for Ghidra 11.3.2

## 20250309 - 2025-03-09

### Changed

- Add support for Ghidra 11.3.1

## 20250206 - 2025-02-06

### Changed

- Add support for Ghidra 11.3

## 20240929 - 2024-09-29

### Changed

- Build with Java 21
- Add support for Ghidra 11.2

## 20240711 - 2024-07-11

### Changed

- Add support for Ghidra 11.1.2

## 20240709 - 2024-07-09

### Changed

- Add support for Ghidra 11.1.1

## 20240609 - 2024-06-09

### Changed

- Build with Ghidra 11.1
- Drop support for older Ghidra versions due to decompiler behaviour change

## 20231227 - 2023-12-27

### Changed

- Build with Ghidra 11.0

## 20231006 - 2023-10-06

### Changed

- Build with Ghidra 10.4

## 20230830 - 2023-08-30

### Changed

- Build with Ghidra 10.3.3

## 20230718 - 2023-07-18

### Changed

- Build with Ghidra 10.3.2

## 20230511 - 2023-05-11

### Changed

- Build with Ghidra 10.3

## 20230420 - 2023-04-20

### Changed

- Build with Ghidra 10.2.3

### Fixed

- DAA pseudo op tracks data dependencies much better

## 20221116 - 2022-11-16

### Changed

- Build with Ghidra 10.2.2

### Fixed

- Revert unintended change in memory block order

## 20221115 - 2022-11-15

### Added

- Meaningful comments to all created memory blocks

### Changed

- Improve decompilation result when checking negative flags (NC, NZ)
- Build with Ghidra 10.2.1
- Build with Java 17

### Fixed

- Typo in ROM bank memory block comment
- Fix accidental generation of duplicate data types

## 20220521 - 2022-05-21

### Changed

- Build with Ghidra 10.1.4

## 20220510 - 2022-05-10

### Changed

- Build with Ghidra 10.1.3

## 20220316 - 2022-03-16

### Changed

- Build with Ghidra 10.1.2

## 20211211 - 2021-12-11

### Changed

- Build with Ghidra 10.1

## 20211028 - 2021-10-28

### Changed

- Build with Ghidra 10.0.4

## 20210817 - 2021-08-17

### Changed

- Build with Ghidra 10.0.2

## 20210728 - 2021-07-28

### Changed

- Build with Ghidra 10.0.1

## 20210630 - 2021-06-30

### Changed

- Build with Ghidra 10.0

## 20210529 - 2021-05-29

### Changed

- Build with Ghidra 9.2.4

## 20210418 - 2021-04-18

### Changed

- Build with Ghidra 9.2.3

## 20210120 - 2021-01-20

### Added

- Absolute offset as the comment in ROM memory banks. Note: this is done when importing a ROM, so existing projects won't automatically get the comments just by upgrading GhidraBoy

### Changed

- Build with Ghidra 9.2.2

## 20201223 - 2020-12-23

### Changed

- Build with Ghidra 9.2.1

## 20201113 - 2020-11-13

### Changed

- Build with Ghidra 9.2

## 20200219 - 2020-02-19

### Changed

- Build with Ghidra 9.1.2

## 20200122 - 2020-01-22

### Changed

- Build with Ghidra 9.1.1

### Fixed

- Fix INC (HL) and DEC (HL) behaviour. These were considered no-ops

## 20191104 - 2019-11-04

### Changed

- Build with Ghidra 9.1 final release

## 20190924 - 2019-09-24

### Fixed

- Fix compatibility with Ghidra 9.1 development version changes

## 20190803 - 2019-08-03

### Added

- Initial release for Ghidra 9.1 development version
