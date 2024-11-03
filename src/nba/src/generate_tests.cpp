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
    CPSR = cpu.state.cpsr.v;
    cpu.SwitchMode(nba::core::arm::Mode::MODE_USR);

    SPSR_svc = cpu.state.spsr[BANK_SVC].v;
    SPSR_abt = cpu.state.spsr[BANK_ABT].v;
    SPSR_irq = cpu.state.spsr[BANK_IRQ].v;
    SPSR_und = cpu.state.spsr[BANK_UND].v;
    SPSR_fiq = cpu.state.spsr[BANK_FIQ].v;
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

static void field(opc_info &inf, u32 hi_bit, u32 lo_bit)
{
    u32 num_bits = (hi_bit - lo_bit) + 1;
    // 4, 2
    // 4 - 2 = 2 + 1 = 3
    // <<shl by lo_bit
    // 1 << 3 = 8. - 1 = 7. so mask is (1 << numbits) - 1
    u32 mask = (1 << num_bits) - 1;
    inf.bsfs.push_back({mask, lo_bit});
}

static void fill_opc_info(int num, opc_info &inf)
{
    inf.clear();
    using namespace opc::classes;
    switch(num) {
        case DATA_PROCESSING:
            inf.format = 0b11110010000111111111111111111111;
            inf.name = "data_processing"
            /* CMP, CMN, TST and TEQ should have S=1 when is_data_processing - true */
            field(inf,24,21); // opcode
            field(inf,20,20); // S

            field(inf,19,16); // Rn
            field(inf,15,12); // Rd
            field(inf,25,25); // I
            inf.has_cond = true;
            inf.has_shifter = true;
            inf.is_data_processing = true;
            break;
        case BLOCK_DATA_TRANSFER:
            inf.name = "block_data_transfer";
            inf.format = 0b00001000000000000000000000000000;
            inf.has_cond = true;
            field(inf, 24, 0); // PUSWL Rn register_list
            break;
        case BRANCH_AND_BRANCHL:
            inf.name = "branch_andor_link"
            inf.format = 0b00001010000000000000000000000000;
            inf.has_cond = true;
            field(inf, 24, 0); // PUSWL Rn register_list
            break;
        case BX:
            inf.name = "branch_exchange";
            inf.format = 0b00000001001011111111111100010000;
            inf.has_cond = true;
            field(inf, 3, 0); // Rn
            break;
        case MUL:
            inf.name = "mul";
            inf.format = 0b00000000000000000000000010010000;
            inf.has_cond = true;
            field(inf, 21, 8);
            field(inf, 3, 0);
            break;
        case MULL:
            inf.name = "mull";
            inf.format = 0b00000000100000000000000010010000;
            inf.has_cond = true;
            field(inf, 22, 8);
            field(inf, 3, 0);
            break;
        case HW_DATA_TRANSFER_REGISTER:
            inf.nmae = "hw_data_transfer_register";
            inf.format = 0b00000000000000000000000010010000;
            inf.has_cond = true;
            field(inf, 24, 23);
            field(inf, 21, 12);
            field(inf, 6, 5);
            field(inf, 3, 0);
            break;
        case HW_DATA_TRANSFER_IMM:
            inf.name = "hw_data_transfer_immediate";
            inf.format = 0b00000000010000000000000010010000;
            inf.has_cond = true;
            field(inf, 24, 23);
            field(inf, 21, 7);
            field(inf, 5, 5);
            field(inf, 3, 0);
            break;
        case MRS:
            inf.name = "mrs";
            inf.format = 0b00000001000011110000000000000000;
            inf.has_cond = true;
            field(inf, 22, 22);
            field(inf, 15, 12);
            break;
        case MSR_TO_PSR:
            inf.name = "msr_to_psr";
            inf.format = (0b00000001 << 24) | (0b00101001 << 16) | (0b11110000 << 8) | 0b00000000;
            inf.has_cond = true;
            field(inf, 22, 22);
            field(inf, 3, 0);
            break;
        case MSR_FLAG_ONLY:
            inf.name = "msr_to_psr_flags_only";
            inf.format = 0b00000001001010001111000000000000;
            inf.has_cond = true;
            field(inf, 25, 25);
            field(inf, 22, 22);
            field(inf, 11, 0);
            break;
        case SINGLE_DATA_TRANSFER:
            inf.name = "single_data_transfer";
            inf.format = 0b00000100000000000000000000000000;
            inf.has_cond = true;
            field(inf, 25, 0);
            break;
        case SINGLE_DATA_SWAP:
            inf.name = "single_data_swap";
            inf.format = 0b00000001000000000000000010010000;
            inf.has_cond = true;
            field(inf, 22, 22); // B
            field(inf, 19, 12); // Rn, Rd
            field(inf, 3, 0); // Rm
            break;
        case SWI:
            inf.name = "swi";
            inf.format = 0b00001111000000000000000000000000;
            inf.has_cond = true;
            break;
        case UNDEFINED:
            inf.name = "undefined";
            inf.format = 0b00000110000000000000000000010000;
            field(inf, 24, 0); // PUSWL Rn register_list
            break;
        default:
            assert(1==0);
    }
}

testarray tests;

opc_info::generate_opcode()
{
    u32 out = format;
    u32 idx = 0;
    u32 last_v = 0;
    for (auto &bf : bsfs) {
        u32 v = sfc32(&rstate) & bf.mask;
        if ((idx == 1) && (is_data_processing)) {
            // S must be set to 1 for some opcodes

            if ((last >= 8) && (last_v < 12)) {
                v = 1;
            }
        }
        out |= v << bf.shift;
        last_v = v;
        idx++;
    }
    if (has_cond) {
        u32 v = 15;
        while (v == 15) {
            v = sfc32(rstate) & 15;
        }
        out |= (v << 28);
    }
    return out;
}

static void generate_opc_tests(yo &core, opc_info &inf)
{
    sfc32_seed(inf.name);
    for (u32 testnum = 0; testnum < NUM_TESTS; testnum++) {
        armtest &test = &tests.test[testnum];
        test.state_begin.randomize(inf.is_thumb);
        test.state_begin.copy_to_arm(core.core.cpu);

        u32 opcode = inf.generate_opcode();

        test.opcodes[0] = opcode;

        if (test.is_thumb) {
            assert(1==0);
        }
        else {
            test.opcodes[1] = ARM32_ADC_R1_R2; // first opcode after test
            test.opcodes[2] = ARM32_ADC_R2_R3; // branch taken to correct
            test.opcodes[3] = ARM32_ADC_R3_R4; // branch taken incorrect
            test.opcodes[4] = ARM32_ADC_R8_R9; // 
        }
        copy_state_to_cpu(&tst->initial, &t->cpu);

        // Make sure our CPU isn't interrupted...
        //t->cpu.interrupt_highest_priority = 0;
        SH4IInterpreter::trace_cycles = 0;
        SH4IInterpreter::cycles_left = 0;

        // Zero our test struct
        test_struct.test = tst;
        test_struct.read_num = 0;
        test_struct.write_addr = test_struct.write_size = -1;
        test_struct.write_value = -1;
        test_struct.write_cycle = 50;
        test_struct.ifetch_num = 0;
        for (u32 j = 0; j < 7; j++) {
            if (j < 4) {
                test_struct.ifetch_addr[j] = -1;
                test_struct.ifetch_data[j] = 65536;

            }
            test_struct.read_addrs[j] = -1;
            test_struct.read_sizes[j] = -1;
            test_struct.read_values[j] = 0;
            test_struct.read_cycles[j] = 50;
        }

        // Run CPU 4 cycles
        // Our amazeballs CPU can run 2-for-1 so do it special!
        // ONLY opcode 1 could have a delay slot so all should finish
        t->cpu.Loop();
        assert(SH4IInterpreter::trace_cycles == 4);
        assert(SH4IInterpreter::cycles_left == 0);

        for (u32 cycle = 0; cycle < 4; cycle++) {
            struct test_cycle *c = &tst->cycles[cycle];
            clear_test_cycle(c);
            if ((cycle == 1)  && (test_struct.write_cycle != 50)) {
                c->actions |= TCA_WRITE;
                c->write_addr = test_struct.write_addr;
                c->write_val = test_struct.write_value;
            }
            for (u32 j = 0; j < 7; j++) {
                if ((test_struct.read_cycles[j] != 50) && (cycle == 1)) {
                    assert((c->actions & TCA_READ) == 0);
                    c->actions |= TCA_READ;
                    c->read_addr = test_struct.read_addrs[j];
                    c->read_val = test_struct.read_values[j];
                }
            }
            c->actions |= TCA_FETCHINS;
            c->fetch_addr = test_struct.ifetch_addr[cycle];
            c->fetch_val = test_struct.ifetch_data[cycle];
            assert(c->fetch_addr <= 0xFFFFFFFF);
            assert(c->fetch_addr >= 0);
            assert(c->fetch_val <= 0xFFFF);
        }
        // Now fill out rest of test
        copy_state_from_cpu(&tst->final, &t->cpu);
    }
    write_tests(ta);
}


void generate_tests()
{
    auto conf = std::make_shared<nba::Config>();
    yo core(conf);

    snprintf(tests.outpath, 500, "/Users/dave/dev/ARM7TDMI/v1/%s.json.bin", gti.name);
    fflush(stdout);
    for (u32 opc_num = 0; opc_num < opc::total; opc_num++) {
        opc_info inf;
        fill_opc_info(opc_num, inf);
        printf("\nGenerate tests %s", inf.name.c_str());
        generate_opc_tests(core, inf);
    }
    //sfc32_seed(ta->fname, &rstate);
}