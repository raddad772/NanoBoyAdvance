//
// Created by . on 9/13/24.
//

#include <cstdio>
#include <pwd.h>
#include <unistd.h>


#include "arm/arm7tdmi.hpp"
#include "bus/bus.hpp"
#include "core.hpp"
#include "generate_tests.h"

#include "myrandom.h"
#include "generate_private.h"
#include "mpwd.h"

namespace nba {
    namespace core {
        u32 global_steps = 0;
    }
}

using nba::core::global_steps;

struct sfc32_state rstate;

using nba::core::arm::BANK_SVC;
using nba::core::arm::BANK_NONE;
using nba::core::arm::BANK_ABT;
using nba::core::arm::BANK_FIQ;
using nba::core::arm::BANK_IRQ;
using nba::core::arm::BANK_UND;

typedef signed long long i64;

#define OUTBUF_SZ (20 * 1024 * 1024)
static u8 outbuf[OUTBUF_SZ];

struct generating_test_struct {
    armtest *test;
    u32 cycle_num;
    nba::core::arm::ARM7TDMI *cpu;
};


static struct generating_test_struct test_struct = {};

u32 bus_read(u32 addr, u32 sz, int access)
{
    enum Access {
        Nonsequential = 0,
        Sequential = 1,
        Code = 2,
        Dma = 4,
        Lock = 8
    };
    transaction t;
    t.addr = addr;
    t.size = sz;
    t.cycle = global_steps;

    // if this is the instruction right after the one we executed, return "good ins"
    // if it's different, return "good jump"
    // else, return "bad ins"
    armtest *tst = test_struct.test;
    u32 v;

    if (access & Access::Code) {
        t.tkind = transaction::TK_READ_INS;
        i64 addrdiff = ((i64)addr - (i64)tst->base_addr);
        if ((addrdiff >= 0) && (addrdiff <= 12)) {
            // opcode fetch in-order!
            //printf("\nIN-ORDER FETCH! %08x", (u32)(addrdiff >> 2));
            v = tst->opcodes[addrdiff >> 2];
        }
        else {
            // out-of-order!
            //printf("\nOUT OF ORDER FETCH!");
            v = tst->opcodes[3];
        }
    } else {
        // Generate an 8, 16, or 32-bit value!
        t.tkind = transaction::TK_READ_DATA;
        u32 mask;
        switch(sz) {
            case 1:
                mask = 0xFF;
                break;
            case 2:
                mask = 0xFFFF;
                break;
            case 4:
                mask = 0xFFFFFFFF;
                break;
            default:
                assert(1==2);
        }
        //printf("\nREAD NORMAL!");
        v = sfc32(&rstate) & mask;
    }

    t.data = v;
    t.access = access;

    test_struct.test->transactions.push_back(t);

    return v;
}

void bus_write(u32 addr, u32 val, u32 sz, int access)
{
    //printf("\nWRITE ADDR %08x sz:%d val:%08x", addr, sz, val);
    transaction t;
    t.addr = addr;
    t.data = val;
    t.size = sz;
    t.tkind = transaction::TK_WRITE_DATA;
    t.cycle = global_steps;
    t.access = access;
    test_struct.test->transactions.push_back(t);
}

u32 (*bus_rd_ptr)(u32, u32, int) = bus_read;
void (*bus_wt_ptr)(u32, u32, u32, int) = bus_write;

static u32 rnd_modes[8] = { mode_usr, mode_fiq, mode_irq, mode_svc, mode_abt, mode_und, mode_sys };

static u32 get_cpsr(bool thumb) {
    u32 r = sfc32(&rstate);
    u32 flags = r & 0b11110000000000000000000011000000;
    flags |= rnd_modes[r & 7];
    if (thumb) flags |= 0b100000;
    // bit 4 is forced to 1 on ARM7TDMI
    flags |= 0b10000;
    return flags;
}

void arm_test_state::print(const char *w)
{
    printf("\n\n%s", w);
    for (u32 i = 0; i < 16; i++) {
        printf("\nR%d: %08x", i, r[i]);
    }
}

void arm_test_state::randomize(bool thumb) {
    for (u32 i = 0; i < 16; i++) {
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
    if (thumb) r[15] &= 0xFFFFFFFE;
    else r[15] &= 0xFFFFFFFC;
    // for CPSR...bits 31-28 random.
    // 7-6 IF. randomly set!
    // 5, T. Thumb!
    // 4-0 = mode. must be valid from list of modes above
    CPSR = get_cpsr(thumb);
    //SPSR = get_cpsr(thumb);
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
    cpu.Reset();
    if (cpu.state.cpsr.f.mode != nba::core::arm::Mode::MODE_USR)
        cpu.SwitchMode(nba::core::arm::Mode::MODE_USR);
    for (u32 i = 0; i < 16; i++) {
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
    cpu.state.spsr[BANK_SVC].v = SPSR_svc;
    cpu.state.spsr[BANK_ABT].v = SPSR_abt;
    cpu.state.spsr[BANK_IRQ].v = SPSR_irq;
    cpu.state.spsr[BANK_UND].v = SPSR_und;
    cpu.state.spsr[BANK_FIQ].v = SPSR_fiq;
    cpu.pipe.opcode[0] = pipeline.opcode[0];
    cpu.pipe.opcode[1] = pipeline.opcode[1];
    cpu.state.cpsr.v = CPSR;
    if ((CPSR & 0x1F) != 16)
        cpu.SwitchModeOther((nba::core::arm::Mode)CPSR & 0x1F);
}

void arm_test_state::copy_from_arm(nba::core::arm::ARM7TDMI &cpu)
{
    CPSR = cpu.state.cpsr.v;
    if (cpu.state.cpsr.f.mode != nba::core::arm::Mode::MODE_USR)
        cpu.SwitchMode(nba::core::arm::Mode::MODE_USR);

    SPSR_svc = cpu.state.spsr[BANK_SVC].v;
    SPSR_abt = cpu.state.spsr[BANK_ABT].v;
    SPSR_irq = cpu.state.spsr[BANK_IRQ].v;
    SPSR_und = cpu.state.spsr[BANK_UND].v;
    SPSR_fiq = cpu.state.spsr[BANK_FIQ].v;
    pipeline.opcode[0] = cpu.pipe.opcode[0];
    pipeline.opcode[1] = cpu.pipe.opcode[1];

    for (u32 i = 0; i < 16; i++) {
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
    u32 mask = (1 << num_bits) - 1;
    inf.bsfs.push_back({mask, lo_bit, false, false, 0, 0});
}

static void field_when(opc_info &inf, u32 which_hi, u32 which_lo, u32 equals, u32 hi_bit, u32 lo_bit)
{
    u32 num_bits = (hi_bit - lo_bit) + 1;
    u32 mask = (1 << num_bits) - 1;

    u32 which_mask = (1 << ((which_hi - which_lo) + 1)) - 1;
    u32 which_equals = equals << which_lo;
    inf.bsfs.push_back({mask, lo_bit, true, true, which_mask, which_equals});
}

static void field_when_not(opc_info &inf, u32 which_hi, u32 which_lo, u32 equals, u32 hi_bit, u32 lo_bit)
{
    u32 num_bits = (hi_bit - lo_bit) + 1;
    u32 mask = (1 << num_bits) - 1;

    u32 which_mask = (1 << ((which_hi - which_lo) + 1)) - 1;
    u32 which_equals = equals << which_lo;
    inf.bsfs.push_back({mask, lo_bit, true, false, which_mask, which_equals});
}

static void fill_opc_info(u32 num, opc_info &inf)
{
    inf.clear();
    using namespace opc::classes;
    switch(num) {
        case MUL_MLA: // // 000'000.. 1001  MUL, MLA
            inf.name = "mul_mla";
            inf.format = 0b00000000000000000000000010010000;
            inf.has_cond = true;
            field(inf, 21,8); // S, Rd, Rn, Rs
            field(inf, 3, 0); // Rm
            break;
        case MULL_MLAL:
            inf.name = "mull_mlal";
            inf.format = 0b00000000100000000000000010010000;
            inf.has_cond = true;
            field(inf, 21,8); // S, Rd, Rn, Rs
            field(inf, 3, 0); // Rm
            break;
        case SWP:
            inf.name = "swp";
            inf.format = 0b00000001000000000000000010010000;
            inf.has_cond = true;
            field(inf, 22, 22); // B
            field(inf, 19, 12); // Rn, Rd
            field(inf, 3, 0); // Rm
            break;
        case LDRH_STRH:
            inf.name = "ldrh_strh";
            inf.format = 0b00000000000000000000000010110000;
            inf.has_cond = true;
            field(inf, 24, 22); // P, U, I
            field_when(inf, 24, 24, 1, 21, 21); // when P=1, W may be 0 or 1
            field(inf, 20, 12); // L, Rn, Rd
            field_when(inf, 22, 22, 1, 11, 8); // when I=1, immediate offset upper 4 bits
            field(inf, 3, 0); // Rm or lower 4 bits of immediate offset
            break;
        case LDRSB_LDRSH:
            inf.name = "ldrsb_ldrsh";
            inf.format = 0b00000000000100000000000011010000;
            inf.has_cond = true;
            field(inf, 24, 22); // P, U, I
            field_when(inf, 24, 24, 1, 21, 21); // when P=1, W may be 0 or 1
            field(inf, 19, 12); // Rn, Rd
            field_when(inf, 22, 22, 1, 11, 8); // when I=1, immediate offset upper 4 bits
            field(inf, 5, 5); // LRDSB or LDRSH
            field(inf, 3, 0); // Rm or lower 4 bits of immediate offset
            break;
        case MRS:
            inf.name = "mrs";
            inf.format = 0b00000001000011110000000000000000;
            inf.has_cond = true;
            field(inf, 15, 12); // Rd
            break;
        case MSR_reg: // 000'10.10 0000  MSR (register)
            inf.name = "msr_reg";
            inf.format = 0b00000001001000001111000000000000;
            inf.has_cond = true;
            field(inf, 19, 16); // f s x c
            field(inf, 3, 0); // Rm
            break;
        case MSR_imm: // 001'10.10 ....
            inf.name = "msr_imm";
            inf.format = 0b00000011001000001111000000000000;
            inf.has_cond = true;
            field(inf, 19, 16); // f s x c
            field(inf, 11, 8); // shift applied to imm
            field(inf, 7, 0); // unsigned 8bit immediate
            break;
        case BX:
            inf.name = "bx";
            inf.format = 0b00000001001011111111111100010000;
            inf.has_cond = true;
            field(inf, 3, 0); // operand register
            break;
        case data_proc_immediate_shift: // 000'..... ...0  Data Processing (immediate shift)
            inf.name = "data_proc_immediate_shift";
            inf.format = 0b00000000000000000000000000000000; // I=0, R=0
            inf.has_cond = true;
            inf.is_data_processing = true;
            field(inf, 24, 20); // opcode, S
            field(inf, 19, 12); // Rn, Rd. special rules for some opcodes
            field(inf, 11, 7); // shift amount because I=0 and R=0
            field(inf, 6, 5); // shift type
            field(inf, 3, 0); // Rm
            break;
        case data_proc_register_shift: // //000'..... 0..1  Data Processing (register shift)
            inf.name = "data_proc_register_shift";
            inf.format = 0b00000000000000000000000000010000;   // I=0, R=1
            inf.has_cond = true;
            inf.is_data_processing = true;
            field(inf, 24, 20); // opcode, S
            field(inf, 19, 12); // Rn, Rd. special rules for some opcodes
            field(inf, 11, 8); // Rs. only lower 8 bits used
            field(inf, 6, 5); // shift type
            field(inf, 3, 0); // Rm
            break;
        /*case undefined_instruction: // 001'10.00
            inf.name = "undefined";
            inf.format = 0b000000110000*/
        case data_processing_immediate:  // 001'..... ....
            inf.name = "data_proc_immediate";
            inf.format = 0b00000010000000000000000000000000;   // I=1
            inf.has_cond = true;
            inf.is_data_processing = true;
            field(inf, 24, 20); // opcode, S
            field(inf, 19, 12); // Rn, Rd. special rules for some opcodes
            field(inf, 11, 8); // Is
            field(inf, 7, 0); // nn
            break;
        case LDR_STR_immediate_offset: // //010'..... ....  LDR, STR (immediate offset)
            inf.name = "ldr_str_immediate_offset";
            inf.format = 0b00000100000000000000000000000000; // I=0
            inf.has_cond = true;
            field(inf, 24, 22); // P, U, B
            field(inf, 21, 21); // T or W
            field(inf, 20, 12); // L, Rn, Rd
            field(inf, 11, 0); // immediate offset
            break;
        case LDR_STR_register_offset:
            inf.name = "ldr_str_immediate_offset";
            inf.format = 0b00000110000000000000000000000000; // I=1
            inf.has_cond = true;
            field(inf, 24, 12); // P, U, B, T/W, L, Rn, Rd
            field(inf, 11, 5); // shift amount, shift type
            field(inf, 3, 0); // Rm
            break;
        case LDM_STM: // 100'..... ....
            inf.name = "ldm_stm";
            inf.format = 0b00001000000000000000000000000000;
            inf.has_cond = true;
            field(inf, 24, 0); // all options
            break;
        case B_BL: // 101'..... ....
            inf.name = "b_bl";
            inf.format = 0b00001010000000000000000000000000;
            inf.has_cond = true;
            field(inf, 24, 24); // B or BL
            field(inf, 23, 0); // offset
            break;
        case STC_LDC: // 110'..... ....
            inf.name = "stc_ldc";
            inf.format = 0b00001100000000000000000000000000;
            inf.has_cond = true;
            field(inf, 24, 0); // all options
            break;
        case CDP: // 111'0.... ...0
            inf.name = "cdp";
            inf.format = 0b00001110000000000000000000000000;
            inf.has_cond = true;
            field(inf, 23, 5);
            field(inf, 3, 0);
            break;
        case MCR_MRC: // 111'0.... ...1
            inf.name = "mcr_rc";
            inf.format = 0b00001110000000000000000000010000;
            field(inf, 23, 5);
            field(inf, 3, 0);
            break;
        case SWI: // 111'1.... ....
            inf.name = "swi";
            inf.format = 0b00001111000000000000000000000000;
            field(inf, 23, 0); // comment field, ignored by processor.
            inf.has_cond = true;
            break;
        default:
            assert(1==0);
    }
}

testarray tests;

u32 opc_info::generate_opcode()
{
    bool pf = false;
    if ((strcmp("data_proc_register_shift", name.c_str()) == 0)) {
        pf = true;
    }
    u32 out = format;
    u32 idx = 0;
    //u32 last_v = 0;
    for (auto &bf : bsfs) {
        u32 v = (sfc32(&rstate) & bf.mask) << bf.shift;
        if (pf) printf("\nField bits mask: %08x shift:%d", bf.mask, bf.shift);
        if (bf.is_if) {
            u32 t = out & bf.which_mask;
            if (bf.is_ne) {
                if (t == bf.which_equals) v = 0;
            }
            else if (t != bf.which_equals) v = 0;
        }
        out |= v;
        idx++;
    }
    if (is_data_processing) {
        u32 opcode = (out >> 21) & 15;
        switch(opcode) {
            case 0x0D: // MOV
            case 0x0F: // MVN
                out &= ~(15 << 16); // Clear bits 19-16
                break;
            case 0x0A: // CMP. CMP, CMN, TST, TEQ
            case 0x0B: // CMN
            case 0x08: // TST
            case 0x09: // TEQ
                // 0 *OR* 1 in bits 15-12
                // S must be 1 also
                u32 bit = 0b1111 * (sfc32(&rstate) & 1);
                out &= ~(15 << 12); // clear bits 15-12
                out |= (bit << 12); // set them again
                out &= ~(1 << 20);
                out |= (1 << 20);
                break;
        }
    }
    if (has_cond) {
        u32 c = sfc32(&rstate) & 15;
        if (c == 0) {
            u32 v = 15;
            while (v == 15) {
                v = sfc32(&rstate) & 15;
            }
            out |= (v << 28);
        }
    }
    return out;
}

static void construct_path(char* w, const char* who)
{
    const char *homeDir = getenv("HOME");

    if (!homeDir) {
        struct passwd* pwd = getpwuid(getuid());
        if (pwd)
            homeDir = pwd->pw_dir;
    }

    char *tp = w;
    tp += sprintf(tp, "%s/dev/%s", homeDir, who);
}

#define TB_INITIAL_STATE 1
#define TB_FINAL_STATE 2
#define TB_TRANSACTIONS 3
#define TB_OPCODES 4

static u32 write_state(u8* where, struct arm_test_state *state, u32 is_final)
{
    cW[M32](where, 4, is_final ?  TB_FINAL_STATE : TB_INITIAL_STATE);

    u32 rs = 8;
    // R0-R15 offset 8
#define W32(val) cW[M32](where, rs, state-> val); rs += 4
    u32 i;
    for (i = 0; i < 16; i++) {
        W32(r[i]);
    }

    for (i = 0; i < 7; i++) {
        W32(r_fiq[i]);
    }

    for (i = 0; i < 2; i++) {
        W32(r_svc[i]);
    }

    for (i = 0; i < 2; i++) {
        W32(r_abt[i]);
    }
    for (i = 0; i < 2; i++) {
        W32(r_irq[i]);
    }
    for (i = 0; i < 2; i++) {
        W32(r_und[i]);
    }

    W32(CPSR);
    W32(SPSR_fiq);
    W32(SPSR_svc);
    W32(SPSR_abt);
    W32(SPSR_irq);
    W32(SPSR_und);
    W32(pipeline.opcode[0]);
    W32(pipeline.opcode[1]);

#undef W32
    // Write size of block
    cW[M32](where, 0, rs);
    return rs;
}

static u32 write_transactions(u8 *where, const struct armtest *test)
{
    cW[M32](where, 4, TB_TRANSACTIONS);
    cW[M32](where, 8, test->transactions.size());
    u32 r = 12;
#define W32(v) cW[M32](where, r, v); r += 4
    for (auto &t : test->transactions) {
        W32((u32)t.tkind);
        W32(t.size);
        W32(t.addr);
        W32(t.data);
        W32(t.cycle);
        W32(t.access);
    }
    cW[M32](where, 0, r);
#undef W32
    return r;
}

static u32 write_opcodes(u8* where, struct armtest *test)
{
    cW[M32](where, 4, TB_OPCODES);
    u32 r = 8;
#define W32(val) cW[M32](where, r, val); r += 4
    W32((u32)test->opcodes[0]);
    W32((u32)test->opcodes[1]);
    W32((u32)test->opcodes[2]);
    W32((u32)test->opcodes[3]);
    W32((u32)test->opcodes[4]);

    W32(test->base_addr);
#undef W32

    cW[M32](where, 0, r);
    return r;
}

void write_tests(opc_info &inf)
{
    char fpath[250];
    char rp[250];
    sprintf(rp, "ARM7TDMI/v1/%s.json.bin", inf.name.c_str());
    construct_path(fpath, rp);
    printf("\nFILE PATH %s", fpath);
    remove(fpath);

    FILE *f = fopen(fpath, "wb");

    u32 r = 0xD33DBAE0;
    fwrite(&r, 1, sizeof(r), f);
    r = NUM_TESTS;
    fwrite(&r, 1, sizeof(r), f);

    u32 outbuf_idx = 0;
    for (u32 tnum = 0; tnum < NUM_TESTS; tnum++) {
        armtest *t = &tests.test[tnum];
        // Write out initial state, final state
        u32 outbuf_start = outbuf_idx;
        outbuf_idx += 4;
        outbuf_idx += write_state(&outbuf[outbuf_idx], &t->state_begin, 0);
        outbuf_idx += write_state(&outbuf[outbuf_idx], &t->state_end, 1);
        outbuf_idx += write_transactions(&outbuf[outbuf_idx], t);
        outbuf_idx += write_opcodes(&outbuf[outbuf_idx], t);
        cW[M32](outbuf, outbuf_start, outbuf_idx - outbuf_start);
    }
    assert(outbuf_idx < OUTBUF_SZ);
    fwrite(outbuf, 1, outbuf_idx, f);

    fclose(f);
}

static void generate_opc_tests(yo &core, opc_info &inf) {
    sfc32_seed(inf.name.c_str(), &rstate);
    for (u32 testnum = 0; testnum < NUM_TESTS; testnum++) {
        armtest &test = tests.test[testnum];
        test.state_begin.randomize(inf.is_thumb);

        u32 opcode = inf.generate_opcode();

        test.opcodes[0] = opcode;

        if (test.is_thumb) {
            assert(1 == 0);
        } else {
            test.opcodes[1] = ARM32_ADC_R1_R2; // first opcode after test
            test.opcodes[2] = ARM32_ADC_R2_R3; // branch taken to correct
            test.opcodes[3] = ARM32_ADC_R3_R4; // final prefetch
            test.opcodes[4] = ARM32_ADC_R8_R9; // unknown opcode location
        }
        test.state_begin.pipeline.opcode[0] = test.opcodes[0];
        test.state_begin.pipeline.opcode[1] = test.opcodes[1];
        test.base_addr = test.state_begin.r[15];
        test.state_begin.r[15] += (test.is_thumb ? 4 : 8);
        test.state_begin.copy_to_arm(core.core.cpu);
        global_steps = 0;

        // Make sure our CPU isn't interrupted...
        core.core.cpu.trace_cycles = 0;
        core.core.cpu.cycles_left = 0;

        // Zero our test struct
        test_struct.test = &test;
        test_struct.test->transactions.clear();
        test_struct.cycle_num = 0;

        // Run CPU 1 cycle!
        core.core.cpu.Run();
        test_struct.cycle_num++;

        // Now fill out rest of test
        test.state_end.copy_from_arm(core.core.cpu);
    }
    write_tests(inf);
}

void generate_tests()
{
    auto conf = std::make_shared<nba::Config>();
    yo core(conf);

    test_struct.cpu = &core.core.cpu;

    //snprintf(tests.outpath, 500, "/Users/dave/dev/ARM7TDMI/v1/%s.json.bin", gti.name);
    fflush(stdout);
    for (u32 opc_num = 1; opc_num <= opc::total; opc_num++) {
    //u32 opc_num = opc::classes::kinds::SINGLE_DATA_SWAP;
        opc_info inf;
        fill_opc_info(opc_num, inf);
        printf("\nGenerate tests %s", inf.name.c_str());
        generate_opc_tests(core, inf);
    }
    //sfc32_seed(ta->fname, &rstate);
}