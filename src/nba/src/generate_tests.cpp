//
// Created by . on 9/13/24.
//

#include <cstdio>

#include "arm/arm7tdmi.hpp"
#include "bus/bus.hpp"
#include "core.hpp"
#include "generate_tests.h"

#include "myrandom.h"
#include "generate_private.h"

using nba::core::arm::BANK_SVC;
using nba::core::arm::BANK_NONE;
using nba::core::arm::BANK_ABT;
using nba::core::arm::BANK_FIQ;
using nba::core::arm::BANK_IRQ;
using nba::core::arm::BANK_UND;

struct armtest *current_test;

u32 bus_read(u32 addr, u32 sz, int access)
{
    printf("\nREAD ADDR %08X sz:%d", addr, sz);
    if (sz == 4) return ARM32_NOP;
    if (sz == 2) return THUMB_NOP;
    if (sz == 1) return 0xFF;
}

void bus_write(u32 addr, u32 val, u32 sz, int access)
{
    printf("\nWRITE ADDR %08x sz:%d val:%08x", addr, sz, val);
}

u32 (*bus_rd_ptr)(u32, u32, int) = bus_read;
void (*bus_wt_ptr)(u32, u32, u32, int) = bus_write;

static u32 rnd_modes[8] = { mode_usr, mode_fiq, mode_irq, mode_svc, mode_abt, mode_und, mode_sys };

struct sfc32_state rstate;

static u32 get_cpsr(bool thumb) {
    u32 r = sfc32(&rstate);
    u32 flags = r & 0b11110000000000000000000011000000;
    flags |= rnd_modes[r & 7];
    if (thumb) flags |= 0b100000;
    // bit 4 is forced to 1 on ARM7TDMI
    flags |= 0b10000;
    return flags;
}

void arm_test_state::randomize(bool thumb) {
    for (u32 i = 0; i < 15; i++) {
        if (i < 2) {
            r_svc[i] = sfc32(&rstate);
            r_abt[i] = sfc32(&rstate);
            r_irq[i] = sfc32(&rstate);
            r_und[i] = sfc32(&rstate);
        }
        if (i < 7) {
            r_fiq[i] = sfc32(&rstate);
        }
        r[i] = sfc32(&rstate);
    }
    // for CPSR...bits 31-28 random.
    // 7-6 IF. randomly set!
    // 5, T. Thumb!
    // 4-0 = mode. must be valid from list of modes above
    CPSR = get_cpsr(thumb);
    SPSR = get_cpsr(thumb);
    SPSR_fiq = get_cpsr(thumb);
    SPSR_svc = get_cpsr(thumb);
    SPSR_abt = get_cpsr(thumb);
    SPSR_irq = get_cpsr(thumb);
    SPSR_und = get_cpsr(thumb);

    for (u32 i = 0; i < 2; i++) {
        if (thumb)
            pipeline.opcode[i] = THUMB_NOP;
        else
            pipeline.opcode[i] = ARM32_NOP;
    }
}


void arm_test_state::copy_to_arm(nba::core::arm::ARM7TDMI &cpu)
{
    cpu.SwitchMode(nba::core::arm::Mode::MODE_USR);
    for (u32 i = 0; i < 15; i++) {
        cpu.state.reg[i] = r[i];
        if (i < 2) { // 5 and 6
            cpu.state.bank[BANK_SVC][5+i] = r_svc[i];
            cpu.state.bank[BANK_ABT][5+i] = r_abt[i];
            cpu.state.bank[BANK_IRQ][5+i] = r_irq[i];
            cpu.state.bank[BANK_UND][5+i] = r_und[i];
        }
        if (i < 7) {
            cpu.state.bank[BANK_FIQ][i] = r_fiq[i];
        }
    }
    cpu.state.spsr[BANK_SVC] = SPSR_svc;
    cpu.state.spsr[BANK_ABT] = SPSR_abt;
    cpu.state.spsr[BANK_IRQ] = SPSR_irq;
    cpu.state.spsr[BANK_UND] = SPSR_und;
    cpu.state.spsr[BANK_FIQ] = SPSR_fiq;
    cpu.pipe.opcode[0] = pipeline.opcode[0];
    cpu.pipe.opcode[1] = pipeline.opcode[1];
    cpu.state.cpsr = CPSR;
    cpu.SwitchModeOther((nba::core::arm::Mode)CPSR & 0x1F);
}

void arm_test_state::copy_from_arm(nba::core::arm::ARM7TDMI &cpu)
{
    CPSR = cpu.state.cpsr;
    cpu.SwitchMode(nba::core::arm::Mode::MODE_USR);

    SPSR_svc = cpu.state.spsr[BANK_SVC];
    SPSR_abt = cpu.state.spsr[BANK_ABT];
    SPSR_irq = cpu.state.spsr[BANK_IRQ];
    SPSR_und = cpu.state.spsr[BANK_UND];
    SPSR_fiq = cpu.state.spsr[BANK_FIQ];
    pipeline.opcode[0] = cpu.pipe.opcode[0];
    pipeline.opcode[1] = cpu.pipe.opcode[1];

    for (u32 i = 0; i < 15; i++) {
        r[i] = cpu.state.reg[i];
        if (i < 2) { // 5 and 6
            r_svc[i] = cpu.state.bank[BANK_SVC][5+i];
            r_abt[i] = cpu.state.bank[BANK_ABT][5+i];
            r_irq[i] = cpu.state.bank[BANK_IRQ][5+i];
            r_und[i] = cpu.state.bank[BANK_UND][5+i];
        }
        if (i < 7) {
            r_fiq[i] = cpu.state.bank[BANK_FIQ][i];
        }
    }
}


struct yo {
    yo(std::shared_ptr<nba::Config> config) : core(config) {};

    nba::core::Core core;
};

void generate_tests()
{
    printf("\nGENERATE ME UP!");
    auto conf = std::make_shared<nba::Config>();
    yo core(conf);

    //sfc32_seed(ta->fname, &rstate);
}