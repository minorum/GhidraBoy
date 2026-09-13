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

**Loader**: banked ROMs (> 32 kB) and CGB VRAM/WRAM banks are modelled as Ghidra overlay blocks; there is no bank-switch analysis, so calls into 0x4000-0x7FFF resolve to a bank only by hand.

**Tests** (`src/test/kotlin/`): `GhidraApplication` is a JUnit extension that boots headless Ghidra once and registers the repo root as a Ghidra module so the freshly compiled `sm83.sla` is picked up. `IntegrationTest` is the base that resolves the SM83 language. Three test families:
- `DisassemblyTest`: bytes -> expected mnemonic text.
- `emu/*`: run instructions in Ghidra's `EmulatorHelper` (`EmuTest` base) and assert register/flag/memory state; `FailOnMemoryFault` makes stray accesses fail.
- `decompiler/DecompilerTest`: assemble a snippet, decompile, compare exact C output.

Changing anything in `sm83*.sinc` should be covered by all three where applicable; the emulator tests are the semantic oracle for p-code.
