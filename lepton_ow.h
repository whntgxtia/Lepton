#ifndef LEPTON_OW_H
#define LEPTON_OW_H
#include "params.h"
#include "poly.h"

typedef struct {
	uint8_t seed[SEED_BYTES];
	poly b;
} pubkey;

typedef struct {
	poly_noise s;
} seckey;

typedef struct {
	poly u;
	uint32_t v[CT2_WORDS];
} cipher;

extern int randombytes(unsigned char *x, unsigned long long xlen);

int lepton_ow_keygen_KAT(uint8_t *cpk, uint8_t *csk, const uint8_t *seed);
int lepton_ow_enc_KAT(uint8_t *cct, const uint8_t *cpk, const uint8_t *msg, const uint8_t *seed);
int lepton_ow_dec_KAT(uint8_t *msg, const uint8_t *csk, const uint8_t *cct);

#endif
