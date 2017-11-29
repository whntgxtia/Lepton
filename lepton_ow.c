#include "lepton_ow.h"
#include "bch_codec.h"
#include "fips202.h"
#include "precomp9-30-256.c"
#include <stdio.h>

static inline void pk_to_bytes(uint8_t *cpk, pubkey *pk)
{
	memcpy(cpk,pk->seed,SEED_BYTES);
	poly_to_bytes(&cpk[SEED_BYTES],pk->b);
}
static inline void pk_from_bytes(pubkey *pk, const uint8_t *cpk)
{
	memcpy(pk->seed,cpk,SEED_BYTES);
	poly_from_bytes(pk->b,&cpk[SEED_BYTES]);	
}
static inline void sk_from_bytes(seckey *sk,const uint8_t *csk)
{
	int i=0,j=0;
	for(i=0;i<PARAM_K;i++,j+=2)
		sk->s[i] = (((uint16_t)csk[j])<<8) | ((uint16_t)csk[j+1]);
}
static inline void sk_to_bytes(uint8_t * csk, seckey*sk)
{
	int i=0,j=0;
	for(i=0;i<PARAM_K;i++,j+=2)
	{
		csk[j] = (sk->s[i]>>8) & 0xff;
		csk[j+1] = sk->s[i] & 0xff;
	}
}

static inline void cipher_from_bytes(cipher*ct, const uint8_t *cct)
{
	int i = CT1_BYTES & 0x3,j=0,k=0;
	poly_from_bytes(ct->u,cct);
	j = CT1_BYTES;
	
	k=(CT2_BYTES>>2);
	
	for(i=0;i<k;i++)
	{
		ct->v[i] = (((uint32_t)cct[j])<<24) | (((uint32_t)cct[j+1])<<16)| (((uint32_t)cct[j+2])<<8)|((uint32_t)cct[j+3]);
		j += 4;
	}
	i = CT2_BYTES & 0x3;
	if(i!=0)
	{
		ct->v[CT2_WORDS-1] = 0;
		for(k=0;k<i;k++)
			ct->v[CT2_WORDS-1] |= ((uint32_t)cct[j++])<<((3-k)*8);
	}
}
static inline void cipher_to_bytes(uint8_t *cct, cipher *ct)
{
	int i = CT1_BYTES & 0x3,j=0,k=0;
	uint32_t v=0;
	
	poly_to_bytes(cct,ct->u);
	j = CT1_BYTES;
	
	k=(CT2_BYTES>>2);
	for(i=0;i<k;i++)
	{
		v = ct->v[i];
		cct[j++] = (v>>24) & 0xff;
		cct[j++] = (v>>16) & 0xff;
		cct[j++] = (v>>8) & 0xff;
		cct[j++] = v & 0xff;
	}
	i = CT2_BYTES & 0x3;
	if(i!=0)
	{
		v = ct->v[CT2_WORDS-1];
		for(k=0;k<i;k++)
			cct[j++] = (v>>((3-k)*8)) & 0xff;
	}
	i = CT2_BITS & 0x7;
	if(i!=0)
		cct[j-1] &= ((1<<i)-1)<<(8-i); //clearing the last unused bits
}
static inline void repeated_encode(uint32_t *out, uint8_t *in, int ilen)//out should be initialized as zeros
{
    int nbytes = (ilen>>3);
    uint8_t filter[8]={0x80,0x40,0x20,0x10,0x8,0x4,0x2,0x1};
    int i,j,len;
    int p1=0,p2=0;
    for(i=0;i<nbytes;i++)
    {
        for(j=0;j<8;j++)
        {
            len = PARAM_RCN;
            if(in[i]&filter[j])
            {
                if(len<p2)
                {
                    p2 -= len;
                    out[p1] |= (RIGHT_ONE(len)<<p2);
                }
                else
                {
                    if(p2!=0)
                    {
                        out[p1++] |= (RIGHT_ONE(p2));
                        len -= p2;
                        p2 = 0;
                    }
                    if(len>0)
                    {
                        p2 = 32 - len;
                        out[p1] = (RIGHT_ONE(len) <<p2);
                    }
                }
            }
            else
            {
                if(len<p2)
                    p2 -= len;
                else
                {
                    if(p2!=0)
                    {
                        p1++;
                        len -= p2;
                        p2 = 0;
                    }
                    if(len>0)
                        p2 = 32 - len;
                }
            }
        }
    }
    
    for(j=0;j<(ilen & 7);j++)
    {
        len = PARAM_RCN;
        if(in[i]&filter[j])
        {
            if(len<p2)
            {
                p2 -= len;
                out[p1] |= (RIGHT_ONE(len)<<p2);
            }
            else
            {
                if(p2!=0)
                {
                    out[p1++] |= RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32-len;
                    out[p1] = (RIGHT_ONE(len)<<p2);
                }
            }
        }
        else
        {
            if(len<p2)
                p2 -= len;
            else
            {
                if(p2!=0)
                {
                    p1++;
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                    p2 = 32 - len;
            }
        }
    }
}
static inline int rc_decode(uint32_t v)
{
    int c;
    
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    c = (((v + (v >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
    
    if(c>PARAM_RCT)
        return 1;
    else
        return 0;
}
static inline void repeated_decode(uint8_t *out, int olen, uint32_t *in)
{
    int nbytes = (olen>>3);
    uint32_t word;
    int p1=0,p2=0;
    int i,j,len;
    
    for(i=0;i<nbytes;i++)
    {
        out[i]=0;
        for(j=0;j<8;j++)
        {
            len = PARAM_RCN;
            word = 0;
            if(len<p2)
            {
                p2 -= len;
                word = (in[p1]>>p2)& RIGHT_ONE(len);
            }
            else
            {
                if(p2!=0)
                {
                    word = in[p1++] & RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32 -len;
                    word = (word<<len) | in[p1]>>p2;
                }
                
            }
            out[i] = (out[i]<<1) | rc_decode(word);
        }
    }
    j = olen&7;
    if(j!=0)
    {
        out[i]=0;
        while(j--)
        {
            len = PARAM_RCN;
            word = 0;
            if(len<p2)
            {
                p2 -= len;
                word = (in[p1]>>p2)& RIGHT_ONE(len);
            }
            else
            {
                if(p2!=0)
                {
                    word = in[p1++] & RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32-len;
                    word = (word<<len) | in[p1]>>p2;
                }
                
            }
            out[i] = (out[i]<<1) | rc_decode(word);
        }
        out[i]<<= (8-(olen&7));
    }
}
int lepton_ow_keygen_KAT(uint8_t *cpk, uint8_t *csk, const uint8_t *seed)
{	  
    poly_noise x;
    poly a;
    pubkey pk;
    seckey sk;
    
    uint8_t buf[2*SEED_BYTES];
    
    cshake128_simple(buf,2*SEED_BYTES,0,seed,SEED_BYTES);   
    memcpy(pk.seed,&buf[SEED_BYTES],SEED_BYTES);
    poly_getrandom(a,pk.seed,0);
    
    if(poly_getnoise(sk.s,buf,0)|| poly_getnoise(x,buf,1))
    	return -1;//error happens
    
    poly_mul(pk.b,a,sk.s);
    poly_addnoise(pk.b,pk.b,x);
    
    pk_to_bytes(cpk,&pk);
    sk_to_bytes(csk,&sk);
    return 0;
}
int lepton_ow_enc_KAT(uint8_t *cct, const uint8_t *cpk, const uint8_t *msg, const uint8_t *seed)
{
    poly_noise r,e1,e2;
    poly a,t;
    pubkey pk;
    cipher ct;
    
    uint8_t becc[BCH_CODEBYTES]={0};
    uint32_t recc[CT2_WORDS]={0};
    int i;
    
    pk_from_bytes(&pk,cpk);
    poly_getrandom(a,pk.seed,0);
    
    if(poly_getnoise(r,seed,0) || poly_getnoise(e1,seed,1) || poly_getnoise(e2,seed,2))
    	return -1;//error happens
    
    poly_mul(ct.u,a,r);
    poly_addnoise(ct.u,ct.u,e1);
    
    poly_mul(t,pk.b,r);
    poly_addnoise(t,t,e2);
    
    encode_bch(&bch,msg,SEED_BYTES,&becc[SEED_BYTES]);
    
    memcpy(becc,msg,SEED_BYTES);
    
    repeated_encode(recc,becc,ECC_BITS + SEED_BITS);
    for(i=0;i<CT2_WORDS;i++)
        ct.v[i] = t[i]^recc[i];  
    cipher_to_bytes(cct,&ct);
    
    return 0;
}
int lepton_ow_dec_KAT(uint8_t *msg, const uint8_t *csk, const uint8_t *cct)
{
    poly t;
    uint32_t recc[CT2_WORDS]={0};
    uint8_t becc[BCH_CODEBYTES]={0};
		seckey sk;
    cipher ct;
    int i=0;
    
    
    sk_from_bytes(&sk,csk);
    
    cipher_from_bytes(&ct,cct);  
    poly_mul(t,ct.u,sk.s);
    
    for(i=0;i<CT2_WORDS;i++)
        recc[i] = t[i]^ct.v[i];
     
    repeated_decode(becc,ECC_BITS + SEED_BITS,recc);
    
    uint16_t errLocOut[PARAM_BCT];
    int nerr = decode_bch(&bch, becc, SEED_BYTES,&becc[SEED_BYTES],errLocOut);
    
    if(nerr<0)
    	return -1;//error happens
    
    correct_bch(becc,SEED_BYTES,errLocOut,nerr);
    memcpy(msg,becc,SEED_BYTES);
    
    return 0;   
}

