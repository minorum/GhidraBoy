# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and test

A real Ghidra installation is required (not source). Point at it with `GHIDRA_INSTALL_DIR` or `-Pghidra.dir=`:

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew                      # default tasks: clean assemble -> build/distributions/*_GhidraBoy.zip
./gradlew build                # assemble + test + ktlint (what CI runs)
./gradlew test                 # all tests (compiles sleigh first)
./gradlew test --tests 'fi.gekkio.ghidraboy.DisassemblyTest'
./gradlew test --tests 'fi.gekkio.ghidraboy.emu.MiscInstructionTest.*DAA*'
./gradlew compileSleigh        # sm83.slaspec -> data/languages/sm83.sla (gitignored)
./gradlew ktlintCheck          # ktlintFormat to fix
```

Ghidra version, release name and the zip filename are read from `$GHIDRA_INSTALL_DIR/Ghidra/application.properties`. CI (`.github/workflows/ci.yml`) builds against every version listed in README; adding support for a new Ghidra version means adding a matrix entry there (version, build date, sha256) and updating the README list. Tagged pushes create a draft GitHub release.

## Architecture

**Loader**: banked ROMs (> 32 kB), cartridge RAM banks and CGB VRAM/WRAM banks are modelled as Ghidra overlay blocks (`romN`, `xramN`, `wramN`).

**Bank switching**: `GameBoyBankAnalyzer` adds override references from bank 0 calls/jumps into `romN` after `LD A,n` + a write to the MBC bank register (`BankRegister`, decoded from header byte 0x147), and handles game-specific inline far call / jump table dispatchers configured by address in its analysis options (empty by default).

**Emulation**: `GameBoyEmulation` has the userop library for `IME`/`halt`/`stop` and bank-switch callbacks; `GameBoyEmulatorFactory` plugs them into the Debugger. Debug jars are compile-only, so tests exercise `GameBoyEmulation` directly and never load the factory.

**Tests** (`src/test/kotlin/`): `GhidraApplication` is a JUnit extension that boots headless Ghidra once and registers the repo root as a Ghidra module so the freshly compiled `sm83.sla` is picked up; it ignores installed extensions, and the test task points Ghidra's temp, cache and settings dirs into `build/ghidra-test` so a running Ghidra cannot interfere. `IntegrationTest` is the base that resolves the SM83 language. Three test families:
- `DisassemblyTest`: bytes -> expected mnemonic text.
- `emu/*`: run instructions in Ghidra's `PcodeEmulator` via `TestEmulator` (`EmuTest` base) and assert register/flag/memory state; `EmulatorCallbacks` fails uninitialized reads and unregistered userops.
- `decompiler/DecompilerTest`: assemble a snippet, decompile, compare exact C output.

Changing anything in `sm83*.sinc` should be covered by all three where applicable; the emulator tests are the semantic oracle for p-code.
