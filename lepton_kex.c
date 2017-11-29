#include "lepton_kex.h"
#include "fips202.h"

int lepton_kex_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed)
{
	return lepton_ow_keygen_KAT(pk,sk,seed);
}
int lepton_kex_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed)
{
	uint8_t buf[CPA_BUF_BYTES];
	int flag;
	
	memcpy(buf,seed,SEED_BYTES);
	memcpy(&buf[SEED_BYTES],pk,CPA_PK_BYTES);
	
	shake128(buf,2*SEED_BYTES,buf,SEED_BYTES + CPA_PK_BYTES);//generating (m,r) for one-way encryption
	
	flag = lepton_ow_enc_KAT(ct,pk,buf,&buf[SEED_BYTES]);
	
	memcpy(&buf[SEED_BYTES],ct,CPA_CT_BYTES);
	shake128(ss,SEED_BYTES,buf,SEED_BYTES + CPA_CT_BYTES);//hashing to the session key K
	return flag;
}
int lepton_kex_keygen(uint8_t *pk, uint8_t *sk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kex_keygen_KAT(pk,sk,seed);
}
int lepton_kex_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
	uint8_t seed[SEED_BYTES];
	randombytes(seed,SEED_BYTES);
	return lepton_kex_enc_KAT(ct,ss,pk,seed);
}
int lepton_kex_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct)
{
	uint8_t buf[CPA_BUF_BYTES];
	if(lepton_ow_dec_KAT(buf,sk,ct))//decrypting the one-way ciphertext
		return -1;
	
	memcpy(&buf[SEED_BYTES],ct,CPA_CT_BYTES);
	shake128(ss,SEED_BYTES,buf,SEED_BYTES+CPA_CT_BYTES);//hashing to the session key K
	return 0;
}
