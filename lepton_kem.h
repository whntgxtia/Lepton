#ifndef LEPTON_KEM_H
#define LEPTON_KEM_H
#include "lepton_ow.h"

int lepton_kem_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed);
int lepton_kem_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed);

int lepton_kem_keygen(uint8_t *pk, uint8_t *sk);
int lepton_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int lepton_kem_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct);



#endif
