#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include<string.h>
#include "params.h"

#define RIGHT_ONE(n)  ((1<<n)-1)
#define LEFT_ONE(n)   (RIGHT_ONE(n)<<(32-n))

typedef uint32_t poly[POLY_WORDS];
typedef uint16_t poly_noise[PARAM_K];


void poly_from_bytes(poly r, const uint8_t *cr);
void poly_to_bytes(uint8_t *cr, const poly r);

int poly_getnoise(poly_noise r,const unsigned char *seed, uint16_t nonce);
void poly_getrandom(poly r,const unsigned char *seed, uint16_t nonce);
void poly_mul(poly r,const poly a,const poly_noise s);
void poly_add(poly r, const poly a, const poly b);
void poly_addnoise(poly r, const poly a, const poly_noise b);
#endif
