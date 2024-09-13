//
// Created by . on 9/13/24.
//

#ifndef NANOBOYADVANCE_MYRANDOM_H
#define NANOBOYADVANCE_MYRANDOM_H

//
// Created by . on 5/10/24.
//

#ifndef JSMOOCH_EMUS_MYRANDOM_H
#define JSMOOCH_EMUS_MYRANDOM_H

struct sfc32_state {
    unsigned long long a, b, c, d;
};

void sfc32_seed(const char *seed, struct sfc32_state *state);
unsigned long sfc32(struct sfc32_state *state);

#endif //JSMOOCH_EMUS_MYRANDOM_H


#endif //NANOBOYADVANCE_MYRANDOM_H
