//
// Created by . on 9/13/24.
//

#ifndef NANOBOYADVANCE_GENERATE_PRIVATE_H
#define NANOBOYADVANCE_GENERATE_PRIVATE_H

#define ARM32_NOP 0xe1a00000  // mov r0, r0
// 0b000000001010 op1 op2 00000110 op3
#define ARM32_ADC(op1, op2, op3) (0b00000000101000000000000000000000 | (op1 << 16) | (op2 << 12) | op3)
#define THUMB_ADC(op1, op2, op3) (0b0001100000000000 | (op1 << 6) | (op2 << 3) | op3)
#define ARM32_ADC_R1_R2 ARM32_ADC(1, 2, 2)
#define ARM32_ADC_R2_R3 ARM32_ADC(2, 3, 3)
#define ARM32_ADC_R3_R4 ARM32_ADC(3, 4, 4)
#define ARM32_ADC_R8_R9 ARM32_ADC(8, 9, 9)
#define THUMB_NOP 0x46c0      // mov r8, r8
#define THUMB_ADC_R1_R2 THUMB_ADC(1,2,2)
#define THUMB_ADC_R2_R3 THUMB_ADC(2,3,3)
#define THUMB_ADC_R3_R4 THUMB_ADC(3,4,4)
#define THUMB_ADC_R6_R7 THUMB_ADC(6,7,7)
#include <string.h>

#define NUM_TESTS 20000
#define ALLOC_BUF_SIZE (10 * 1024 * 1024)

struct RW {
    u32 addr;
    u32 val;
    u32 cycle_num;
    int access;
    u32 sz;
};

struct arm_test_state {
    u32 r[16];
    u32 r_fiq[7]; // r8-r15 in fiq mode
    u32 r_svc[2];
    u32 r_abt[2];
    u32 r_irq[2];
    u32 r_und[2];
    u32 CPSR;
    u32 SPSR_fiq, SPSR_svc, SPSR_abt, SPSR_irq, SPSR_und;
    struct {
        u32 opcode[2];
    } pipeline;
    void print(const char *w);
    void randomize(bool thumb);
    void copy_to_arm(nba::core::arm::ARM7TDMI &cpu);
    void copy_from_arm(nba::core::arm::ARM7TDMI &cpu);
};

namespace opc {
    namespace classes {
        enum kinds {
            NONE = 0,
            ARM_MUL_MLA,
            ARM_MULL_MLAL,
            ARM_SWP,
            ARM_LDRH_STRH,
            ARM_LDRSB_LDRSH,
            ARM_MRS,
            ARM_MSR_reg,
            ARM_MSR_imm,
            ARM_BX,
            ARM_data_proc_immediate_shift,
            ARM_data_proc_register_shift,
            ARM_data_proc_immediate,
            ARM_LDR_STR_immediate_offset,
            ARM_LDR_STR_register_offset,
            ARM_LDM_STM,
            ARM_B_BL,
            ARM_STD_LDC,
            ARM_CDP,
            ARM_MCR_MRC,
            ARM_SWI,

            // THUMB Instructions,
            THUMB_ADD_SUB,
            THUMB_LSL_LSR_ASR,
            THUMB_MOV_CMP_ADD_SUB,
            THUMB_data_proc,
            THUMB_BX,
            THUMB_ADD_CMP_MOV_hi,
            THUMB_LDR_PC_relative,
            THUMB_LDRH_STRH_reg_offset,
            THUMB_LDRSH_LDRSB_reg_offset,
            THUMB_LDR_STR_reg_offset,
            THUMB_LDRB_STRB_reg_offset,
            THUMB_LDR_STR_imm_offset,
            THUMB_LDRB_STRB_imm_offset,
            THUMB_LDRH_STRH_imm_offset,
            THUMB_LDR_STR_SP_relative,
            THUMB_ADD_SP_or_PC,
            THUMB_ADD_SUB_SP,
            THUMB_PUSH_POP,
            THUMB_LDM_STM,
            THUMB_SWI,
            THUMB_UNDEFINED_BCC,
            THUMB_BCC,
            THUMB_B,
            THUMB_BL_BLX_prefix,
            THUMB_BL_suffix
        };
    }
    static const int total = 45; // 45 with THUMB
}

struct bsf {
    u32 mask;
    u32 shift;
    bool is_if;
    bool is_ne;
    u32 which_mask;
    u32 which_equals;
    int limit;
};

struct opc_info {
    opc::classes::kinds num;
    u32 mask;
    u32 format;
    u32 format2;
    std::string name;
    bool has_cond;
    bool is_data_processing;
    bool is_thumb;
    bool has_shifter;
    bool is_msr_immediate;
    bool is_msr_reg;
    std::vector<bsf> bsfs;

    void clear() { is_msr_immediate= false; is_msr_reg = false; is_thumb = false; is_data_processing = false; format = 0; mask = 0; has_cond = has_shifter = false; num = opc::classes::NONE,  bsfs.clear(); format2 = 0; }
    u32 generate_opcode();
};

struct transaction {
    enum {
        TK_READ_INS,
        TK_READ_DATA,
        TK_WRITE_DATA
    } tkind{};
    u32 addr{}, data{}, cycle{}, size{}, access{};
};

struct armtest {
    std::vector<transaction> transactions;
    arm_test_state state_begin, state_end;
    bool is_thumb;
    u32 opcodes[5];
    u32 base_addr;
    bool is_msr;
};

enum ARM_modes {
    mode_usr = 0b10000,
    mode_fiq = 0b10001,
    mode_irq = 0b10010,
    mode_svc = 0b10011,
    //mode_mon 0b10110,
    mode_abt = 0b10111,
    mode_und = 0b11011,
    mode_sys = 0b11111
};

struct testarray {
    u8 *buf;
    char outpath[500];
    armtest test[NUM_TESTS];
};

#endif //NANOBOYADVANCE_GENERATE_PRIVATE_H
