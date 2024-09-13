//
// Created by . on 9/13/24.
//

#ifndef NANOBOYADVANCE_GENERATE_PRIVATE_H
#define NANOBOYADVANCE_GENERATE_PRIVATE_H

#define ARM32_NOP 0xe1a00000  // mov r0, r0
#define THUMB_NOP 0x46c0      // mov r8, r8

struct RW {
    u32 addr;
    u32 val;
    u32 cycle_num;
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


struct armtest {
    std::vector<RW> reads;
    std::vector<RW> writes;
    arm_test_state state_begin, state_end;
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


#endif //NANOBOYADVANCE_GENERATE_PRIVATE_H
