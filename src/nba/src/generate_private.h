//
// Created by . on 9/13/24.
//

#ifndef NANOBOYADVANCE_GENERATE_PRIVATE_H
#define NANOBOYADVANCE_GENERATE_PRIVATE_H

#define ARM32_NOP 0xe1a00000  // mov r0, r0
// 0b000000001010 op1 op2 00000110 op3
#define ARM32_ADC(op1, op2, op3) (0b00000000101000000000000001100000 | (op1 << 16) | (op2 << 12) | op3)
#define ARM32_ADC_R1_R2 ARM32_ADC(1, 2, 2)
#define ARM32_ADC_R2_R3 ARM32_ADC(2, 3, 3)
#define ARM32_ADC_R3_R4 ARM32_ADC(3, 4, 4)
#define ARM32_ADC_R8_R9 ARM32_ADC(8, 9, 9)
#define THUMB_NOP 0x46c0      // mov r8, r8
#include <string.h>

#define NUM_TESTS 5000
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
    u32 SPSR, SPSR_fiq, SPSR_svc, SPSR_abt, SPSR_irq, SPSR_und;
    struct {
        u32 opcode[2];
    } pipeline;
    void randomize(bool thumb);
    void copy_to_arm(nba::core::arm::ARM7TDMI &cpu);
    void copy_from_arm(nba::core::arm::ARM7TDMI &cpu);
};

namespace opc{
    namespace classes {
        enum kinds {
            NONE = 0,
            BX,
            BLOCK_DATA_TRANSFER,
            BRANCH_AND_BRANCHL,
            SWI,
            UNDEFINED,
            SINGLE_DATA_TRANSFER,
            SINGLE_DATA_SWAP,
            MUL,
            MULL,
            HW_DATA_TRANSFER_REGISTER,
            HW_DATA_TRANSFER_IMM,
            MRS,
            MSR_TO_PSR,
            MSR_FLAG_ONLY,
            DATA_PROCESSING
        };
    };
    static const int total = 12;
};

struct bsf {
    u32 mask;
    u32 shift;
};

struct opc_info {
    opc::classes::kinds num;
    u32 mask;
    u32 format;
    std::string name;
    bool has_cond;
    bool is_data_processing;
    bool is_thumb;
    bool has_shifter;
    std::vector<bsf> bsfs;

    void clear() { is_thumb = false; is_data_processing = false; format = 0; mask = 0; has_cond = has_shifter = false; num = opc::classes::NONE,  bsfs.clear(); }
    u32 generate_opcode();
};

struct armtest {
    std::vector<RW> reads;
    std::vector<RW> writes;
    arm_test_state state_begin, state_end;
    bool is_thumb;
    u32 opcodes[5];

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
