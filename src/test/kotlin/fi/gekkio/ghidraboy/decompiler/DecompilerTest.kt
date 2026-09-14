package fi.gekkio.ghidraboy.decompiler

import fi.gekkio.ghidraboy.DataTypes.u16
import fi.gekkio.ghidraboy.DataTypes.u8
import fi.gekkio.ghidraboy.GameBoyKind
import fi.gekkio.ghidraboy.GameBoyUtils
import fi.gekkio.ghidraboy.IntegrationTest
import fi.gekkio.ghidraboy.withTransaction
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.assembler.Assemblers
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DecompilerTest : IntegrationTest() {
    private lateinit var program: Program
    private lateinit var decompiler: DecompInterface

    @Test
    fun `simple decompilation works`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x55
                INC A
                LD (0xc234), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                DAT_c234 = 0x56;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `MBC register writes decompile as mbc_write`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x01
                LD (0x2000), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            undefined1 FUN_0000(void)
            {
                mbc_write(0x2000,1);
                return 1;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `switchable RAM without a bank reference`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, (0xd9a1)
                LD (0x8000), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                DAT_8000 = DAT_d9a1;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `Github issue 10`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, (0x1234)
                AND A
                JR NZ, 0x0009
                LD C, 0x6A
                LDH (C), A
                RETI
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                if (DAT_1234 == '\0') {
                    OCPS = (palette_index)0x0;
                }
                IME(1);
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun memcpy() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, B
                OR C
                RET Z
                LD A, (DE)
                LD (HL+), A
                INC DE
                DEC BC
                JR 0x0000
                """.trimIndent(),
                name = "memcpy",
                params =
                    listOf(
                        parameter("dst", pointer(u8), register("HL")),
                        parameter("src", pointer(u8), register("DE")),
                        parameter("len", u16, register("BC")),
                    ),
            )
        assertDecompiled(
            f,
            """
            void memcpy(byte *dst,byte *src,word len)
            {
                for (; (char)(len >> 8) != '\0' || (char)len != '\0'; len = len - 1) {
                    *dst = *src;
                    src = src + 1;
                    dst = dst + 1;
                }
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun memset() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD D, A
                LD A, B
                OR C
                RET Z
                LD A, D
                LD (HL+), A
                DEC BC
                JR 0x0001
                """.trimIndent(),
                name = "memset",
                params =
                    listOf(
                        parameter("dst", pointer(u8), register("HL")),
                        parameter("val", u8, register("A")),
                        parameter("len", u16, register("BC")),
                    ),
            )
        assertDecompiled(
            f,
            """
            void memset(byte *dst,byte val,word len)
            {
                for (; (char)(len >> 8) != '\0' || (char)len != '\0'; len = len - 1) {
                    *dst = val;
                    dst = dst + 1;
                }
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `LCDC flag set`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LDH A, (0xff40)
                OR 0x80
                LDH (0xff40), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                LCDC = LCDC | LCDCF_ON;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `LCDC constant write`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x83
                LDH (0xff40), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                LCDC = LCDCF_ON|LCDCF_OBJON|LCDCF_BGON;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `TAC constant write`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x05
                LDH (0xff07), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                TAC = TACF_START|TACF_262KHZ;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `NR52 constant write`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x80
                LDH (0xff26), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                NR52 = AUDENA_ON;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `IE flag clear`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LDH A, (0xffff)
                AND 0xFE
                LDH (0xffff), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                IE = IE & ~IEF_VBLANK;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `STAT bitfield read`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LDH A, (0xff41)
                AND 0x03
                CP 0x01
                RET NZ
                LD A, 0x01
                LD (0xC000), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                stat sVar1;
                sVar1 = STAT;
                if (sVar1.mode != 1) {
                    return;
                }
                DAT_c000 = 1;
                return;
            }
            """.trimIndent(),
        )
    }

    // Ghidra 12.1 does not recover bitfield writes to volatile memory
    @Test
    fun `IF stays volatile`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LDH A, (0xff0f)
                AND 0xFE
                LDH (0xff0f), A
                RET
                """.trimIndent(),
            )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                interrupts iVar1;
                iVar1 = IF;
                IF = iVar1 & ~IEF_VBLANK;
                return;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `upper nibble popcount`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD D, A
                XOR A
                LD E, A
                SLA D
                ADC E
                SLA D
                ADC E
                SLA D
                ADC E
                SLA D
                ADC E
                RET
                """.trimIndent(),
                name = "popcnt4_upper",
                params =
                    listOf(
                        parameter("value", u8, register("A")),
                    ),
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte popcnt4_upper(byte value)
            {
                return (((value & 0x7f) >> 6) - ((char)value >> 7)) + ((value & 0x3f) >> 5) +
                    ((value & 0x10) >> 4);
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `read_joypad_state`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x20
                LDH (0xff00), A
                LDH A, (0xff00)
                LDH A, (0xff00)
                CPL
                AND 0x0F
                SWAP A
                LD B, A
                LD A, 0x10
                LDH (0xff00), A
                LDH A, (0xff00)
                LDH A, (0xff00)
                LDH A, (0xff00)
                LDH A, (0xff00)
                LDH A, (0xff00)
                LDH A, (0xff00)
                CPL
                AND 0x0F
                OR B
                LD B, A
                LD A, 0x30
                LDH (0xff00), A
                LD A, B
                RET
                """.trimIndent(),
                name = "read_joypad_state",
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte read_joypad_state(void)
            {
                p1 pVar1;
                p1 pVar2;
                P1 = P1F_5;
                pVar1 = P1;
                pVar1 = P1;
                P1 = P1F_4;
                pVar2 = P1;
                pVar2 = P1;
                pVar2 = P1;
                pVar2 = P1;
                pVar2 = P1;
                pVar2 = P1;
                P1 = P1F_5|P1F_4;
                return ~pVar2 & 0xf | ~pVar1 << 4;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `sla8_to_16`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD C, A
                XOR A
                SLA C
                RLA
                SLA C
                RLA
                SLA C
                RLA
                SLA C
                RLA
                LD B, A
                RET
                """.trimIndent(),
                name = "sla8_to_16",
                params =
                    listOf(
                        parameter("value", u8, register("A")),
                    ),
                returnParam = returnParameter(u16, register("BC")),
            )
        assertDecompiled(
            f,
            """
            word sla8_to_16(byte value)
            {
                return CONCAT11((((value >> 7) << 1 | (value & 0x7f) >> 6) << 1 | (value & 0x3f) >> 5) << 1 |
                    (value & 0x1f) >> 4,value << 4);
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `DAA decompilation`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, 0x01
                ADD C
                DAA
                LD C, A
                RET Z
                INC C
                RET
                """.trimIndent(),
                name = "daa",
                params =
                    listOf(
                        parameter("value", u8, register("C")),
                    ),
                returnParam = returnParameter(u8, register("C")),
            )
        assertDecompiled(
            f,
            """
            byte daa(byte value)
            {
                byte bVar1;
                char cVar2;
                bVar1 = value + 1;
                cVar2 = bVar1 + ((0xfe < value || 0x99 < bVar1) * '`' |
                    (((value & 0xf) + 1 & 0x10) != 0 || 9 < (bVar1 & 0xf)) * '\x06');
                if (cVar2 == '\0') {
                    return 0;
                }
                return cVar2 + 1;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `calling conventions are available`() {
        val names = language.defaultCompilerSpec.callingConventions.map { it.name }
        val expected = listOf("__asm", "__asm_a", "__asm_hl", "__asm_f", "__asm_void", "__asm_saved", "__interrupt")
        assertTrue(names.containsAll(expected), names.toString())
    }

    @Test
    fun `interrupt convention has no parameters or return value`() {
        assembleFunction(address(0x0100), "RET", name = "helper")
        assertDecompiled(
            assembleFunction(
                address(0x0000),
                """
                PUSH AF
                PUSH BC
                PUSH DE
                PUSH HL
                CALL 0x0100
                POP HL
                POP DE
                POP BC
                POP AF
                RETI
                """.trimIndent(),
                name = "handler",
                callingConvention = "__interrupt",
            ),
            """
            void __interrupt handler(void)
            {
                helper();
                IME(1);
                return;
            }
            """.trimIndent(),
        )
    }

    private fun callerOfHelper(helperConvention: String): Function {
        assembleFunction(address(0x0100), "RET", name = "helper", callingConvention = helperConvention)
        return assembleFunction(
            address(0x0000),
            """
            LD B, 0x12
            CALL 0x0100
            LD A, B
            RET
            """.trimIndent(),
            name = "caller",
            returnParam = returnParameter(u8, register("A")),
        )
    }

    @Test
    fun `default convention clobbers registers across calls`() =
        assertDecompiled(
            callerOfHelper("__asm"),
            """
            byte caller(void)
            {
                byte extraout_B;
                helper();
                return extraout_B;
            }
            """.trimIndent(),
        )

    @Test
    fun `default convention clobbers flags across calls`() {
        assembleFunction(address(0x0100), "RET", name = "helper")
        assertDecompiled(
            assembleFunction(
                address(0x0000),
                """
                XOR A
                CALL 0x0100
                LD A, 0x00
                RET NC
                LD A, 0x01
                RET
                """.trimIndent(),
                name = "caller",
                returnParam = returnParameter(u8, register("A")),
            ),
            """
            byte caller(void)
            {
                byte extraout_F;
                helper();
                if (!(bool)(extraout_F >> 4 & 1)) {
                    return 0;
                }
                return 1;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `callee-saved convention keeps registers across calls`() =
        assertDecompiled(
            callerOfHelper("__asm_saved"),
            """
            byte caller(void)
            {
                helper();
                return 0x12;
            }
            """.trimIndent(),
        )

    @Test
    fun `INC half carry decompilation`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, C
                INC A
                DAA
                RET
                """.trimIndent(),
                name = "inc_daa",
                params =
                    listOf(
                        parameter("value", u8, register("C")),
                    ),
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte inc_daa(byte value)
            {
                byte bVar1;
                byte in_F;
                bVar1 = value + 1;
                return bVar1 + (((bool)((in_F & 0x10) >> 4) || 0x99 < bVar1) * '`' |
                    ((value & 0xf) == 0xf || 9 < (bVar1 & 0xf)) * '\x06');
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `DEC half carry decompilation`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, C
                DEC A
                DAA
                RET
                """.trimIndent(),
                name = "dec_daa",
                params =
                    listOf(
                        parameter("value", u8, register("C")),
                    ),
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte dec_daa(byte value)
            {
                byte in_F;
                return (value - 1) - (((in_F & 0x10) >> 4) * '`' | ((value & 0xf) == 0) * '\x06');
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `16-bit shifts through carry on a register pair`() {
        listOf(
            Triple("srl16", "SRL B\nRR C\nSRL B\nRR C\nSRL B\nRR C\nSRL B\nRR C\nRET", "return value >> 4;"),
            Triple("sla16", "SLA C\nRL B\nSLA C\nRL B\nRET", "return value << 2;"),
            Triple("sra16", "SRA B\nRR C\nSRA B\nRR C\nRET", "return (int)value >> 2;"),
        ).forEachIndexed { i, (name, code, body) ->
            val f =
                assembleFunction(
                    address(0x0100L * (i + 1)),
                    code,
                    name = name,
                    params = listOf(parameter("value", u16, register("BC"))),
                    returnParam = returnParameter(u16, register("BC")),
                )
            assertDecompiled(
                f,
                """
                word $name(word value)
                {
                    $body
                }
                """.trimIndent(),
            )
        }
    }

    @Test
    fun `RLCA decompiles as a rotate`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                RLCA
                RET
                """.trimIndent(),
                name = "rotl",
                params = listOf(parameter("value", u8, register("A"))),
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte rotl(byte value)
            {
                return value << 1 | value >> 7;
            }
            """.trimIndent(),
        )
    }

    @Test
    fun `16-bit compare through SUB and SBC`() {
        val f =
            assembleFunction(
                address(0x0000),
                """
                LD A, E
                SUB C
                LD A, D
                SBC B
                JR C, 0x0009
                LD A, 0x00
                RET
                LD A, 0x01
                RET
                """.trimIndent(),
                name = "less16",
                params = listOf(parameter("a", u16, register("DE")), parameter("b", u16, register("BC"))),
                returnParam = returnParameter(u8, register("A")),
            )
        assertDecompiled(
            f,
            """
            byte less16(word a,word b)
            {
                byte bVar1;
                byte bVar2;
                bVar2 = (byte)(a >> 8);
                bVar1 = (byte)(b >> 8);
                if (bVar1 <= bVar2 && (bVar2 != bVar1 || (byte)b <= (byte)a)) {
                    return 0;
                }
                return 1;
            }
            """.trimIndent(),
        )
    }

    @BeforeAll
    override fun beforeAll() {
        super.beforeAll()
        decompiler = DecompInterface()
    }

    private val consumer = Any()

    @BeforeEach
    fun beforeEach() {
        program = ProgramDB("test", language, language.defaultCompilerSpec, consumer)
        program.withTransaction {
            program.memory.createInitializedBlock("rom", address(0x0000), 0x8000, 0, TaskMonitor.DUMMY, false)
            GameBoyUtils.addHardwareBlocks(program, GameBoyKind.CGB, MessageLog())
            GameBoyUtils.populateHardwareBlocks(program, GameBoyKind.CGB)
        }
        assertTrue(decompiler.openProgram(program)) { "Failed to initialize decompiler" }
    }

    @AfterEach
    fun afterEach() {
        decompiler.closeProgram()
        program.release(consumer)
    }

    @AfterAll
    fun afterAll() {
        decompiler.dispose()
    }

    private fun assembleFunction(
        address: Address,
        code: String,
        name: String? = null,
        params: List<Parameter>? = null,
        returnParam: Parameter? = null,
        callingConvention: String = "default",
    ): Function =
        program.withTransaction {
            val instructions: Iterable<Instruction> =
                Assemblers.getAssembler(program).assemble(address, *code.lines().toTypedArray())
            val addressSet = AddressSet()
            for (instruction in instructions) {
                addressSet.add(instruction.minAddress, instruction.maxAddress)
            }
            program.functionManager.createFunction(name, address, addressSet, SourceType.USER_DEFINED).apply {
                setCustomVariableStorage(true)
                val force = true
                if (params != null) {
                    updateFunction(
                        callingConvention,
                        returnParam,
                        params,
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        force,
                        SourceType.USER_DEFINED,
                    )
                } else {
                    updateFunction(
                        callingConvention,
                        returnParam,
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        force,
                        SourceType.USER_DEFINED,
                    )
                }
            }
        }

    private fun decompile(function: Function) =
        decompiler
            .decompileFunction(function, 10, TaskMonitor.DUMMY)
            .also {
                assertTrue(it.decompileCompleted()) { "Decompilation did not complete" }
            }.decompiledFunction.c

    private fun formatCode(code: String) =
        code
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .joinToString(separator = "\n")

    private fun assertDecompiled(
        function: Function,
        @Language("C") code: String,
    ) = assertEquals(formatCode(code), formatCode(decompile(function)))

    private fun parameter(
        name: String,
        type: DataType,
        register: Register,
    ) = ParameterImpl(name, type, register, program)

    private fun returnParameter(
        type: DataType,
        register: Register,
    ) = ReturnParameterImpl(type, register, program)

    private fun pointer(type: DataType) = PointerDataType(type)

    private fun register(name: String) = program.getRegister(name)
}
