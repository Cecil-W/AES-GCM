#include "gcm.h"
#include "aes-128.h"
#include <stdint.h>

static __uint8_t expanded_key[4*Nb*(Nr+1)];


void xor_block(uint8_t *X, uint8_t *Y, uint8_t *Out, uint32_t len){
    for(uint32_t i=0; i<len; i++){
        Out[i] = X[i] ^ Y[i];
    }
}


void rshift_string(uint8_t *X){
    uint8_t flag=0;
    for(uint8_t i=0; i<16; i++){
        if(flag==1){
            (X[i]&0x01) ? (flag = 1) : (flag = 0);
            X[i] >>= 1;
            X[i] |= 0x80;
        }else{
            (X[i]&0x01) ? (flag = 1) : (flag = 0);
            X[i] >>= 1;
        }
    }
}


void int_to_byte(uint32_t x, uint8_t *X, uint32_t index_X, uint8_t len_X){
    //size of X is 4bytes
//     for(uint32_t i=0; i<len_X; i++){
//         X[index_X+i] = (x>>(56-(i<<3))) & 0xFF;
//     }
    X[index_X+3] = (uint8_t)x;
    X[index_X+2] = (uint8_t)(x>>=8);
    X[index_X+1] = (uint8_t)(x>>=8);
    X[index_X]   = (uint8_t)(x>>=8);
}


void gcm_inc(uint8_t *Y){
    //only first 32 bits = 4xBytes
    for(uint32_t i=15; i>11; i--){
        uint8_t mask = 1;
        while(Y[i] & mask){
            Y[i] &= ~mask;
            mask <<= 1;
        }
        Y[i] |= mask;
        if(Y[i] != 0) break; //if inc goes through these 4 bits ==> next round
    }
    if((Y[12] == 0)&&(Y[13] == 0)&&(Y[14] == 0)&&(Y[15] == 0)) Y[15] = 0x01; // overflow
}


//inspired by gcm by Jouni Malinen
//https://github.com/michaeljclark/aes-gcm
void gcm_block_mul(const uint8_t *X, const uint8_t *H, uint8_t *Y)
{
    uint8_t V[16];
    uint8_t Z[16];


    memset(Z, 0x00, 16); /* Z_0 = 0^128 */
    memcpy(V, H, 16); /* V_0 = Y */

    for(uint32_t i = 0; i < 16; i++) {
        for(uint32_t j = 0; j < 8; j++) {
            if(X[i] & (0x01 << (7 - j))){
                /* Z_(i + 1) = Z_i XOR V_i */
                xor_block(Z, V, Z, 16);
                //xor_block2(Z, (uint8_t*)H);
            }else{
                /* Z_(i + 1) = Z_i */
            }

            if (V[15] & 0x01) {
                /* V_(i + 1) = (V_i >> 1) XOR R */
                rshift_string(V);
                /* R = 11100001 || 0^120 */
                V[0] ^= 0xe1;
            } else {
                /* V_(i + 1) = V_i >> 1 */
                rshift_string(V);
            }
        }
    }
    memcpy(Y, Z, 16); // return Z
}


//len P = (n-1)*128 + u
//len A = (m-1)*128 + v
void gcm_ghash(uint8_t *H, uint8_t *A, uint8_t *C, uint32_t n, uint32_t m, uint32_t v, uint32_t u, uint8_t *X){
    //step 1
    memset(X, 0x00, 16);

    //step 2
    //for(int i=1; i<=m-1; i++)
    for(uint32_t i=1; i<m; i++){
        xor_block(X, &A[(i-1)<<4], X, 16);
        gcm_block_mul(X, H, X);
    }

    //step 3
    uint8_t tmp[16];
    uint32_t tmp_len;
    if(m>1 || v>0){ //A has entries
        memset(tmp, 0x00, 16);
        tmp_len = v/8;
        memcpy(tmp, &A[(m-1)<<4], tmp_len);
        memset(&tmp[tmp_len], 0x00, 16-tmp_len);
        xor_block(X, tmp, X, 16);
        gcm_block_mul(X, H, X);
    }

    //step 4
    //for(int i=m+1; i<=m+n-1; i++){
    for(uint32_t i=m+1; i<m+n; i++){
        xor_block(X, (uint8_t*)&C[(i-m-1)<<4], X, 16);
        gcm_block_mul(X, H, X);
    }

    //step 5
    memset(tmp, 0x00, 16);
    tmp_len = u/8;
    memcpy(tmp, &C[(n-1)<<4], tmp_len);
    memset(&tmp[tmp_len], 0x00, 16-tmp_len);
    xor_block(X, tmp, X, 16);
    gcm_block_mul(X, H, X);

    //step 6
    uint8_t len_ca[16];
    memset(len_ca, 0x00, 16);
    int_to_byte((n-1)*128 + u, len_ca, 12, 4);
    int_to_byte((m-1)*128 + v, len_ca, 4, 4);
    xor_block(X, len_ca, X, 16);
    gcm_block_mul(X, H, X); //return this
}


// void gcm_robo_ghash(uint8_t *A, uint8_t *C, uint8_t *H, uint8_t *Y){
//     memset(Y, 0x00, 16); //Y_0 = 0^128;
//     //lenA = 8=64, lenC = 21=128+40
//     //TMP = A||0^64||C_128||C_40||0^88||0...01000000||0...010101000
//     //TMP = A|0x00^8    ||  C_16    ||  C_5,0x00^11 ||  0x00^7|0x40|0x00^7|0xA8
//     uint8_t TMP[16*4];
//     memcpy(TMP, A, 8);
//     int ptr = 8;
//     memset(TMP+ptr, 0x00, 8);
//     ptr += 8;
//     memcpy(TMP+ptr, C, 21);
//     ptr += 21;
//     memset(TMP+ptr, 0x00, 11+7);
//     ptr += 18;
//     memset(TMP+ptr, 0x40, 1);
//     ptr += 1;
//     memset(TMP+ptr, 0x00, 7);
//     ptr += 7;
//     memset(TMP+ptr, 0xa8, 1);

//     printf("\nTMP=");
//     for(int i=0; i<64; i++){
//         printf(", 0x%02x", TMP[i]);
//     }

//     for(int i=0; i<4; i++){
//         //xor_block2(Y, TMP+i*16);
//         xor_block(Y, TMP+16*i, Y, 16);
//         gcm_block_mul(Y, H, Y);
//     }
// }


//all lenghts in #bits !!!
//Input: key, init vec (#bits = 1-2^64), plain text (#bits = 0- (2^39-256)), additional auth data AAD (#bits = 0-2^64)
//Output: cypher txt C (#bits = #bits_P), auth tag T (#bits=0-128=t)
void gcm_encrypt(uint8_t *key, uint8_t *IV, uint32_t len_IV,
                 uint8_t *P, uint32_t len_P, uint8_t *A, uint32_t len_A,
                 uint8_t *C, uint8_t *T, uint32_t len_T){
    //setup
    aes_key_expansion(key, expanded_key);

    uint32_t u=len_P%128;
    uint32_t n, m, v, n_IV, u_IV;
    // uint32_t n, n_IV, u_IV;
    if(u==0){
        n=len_P/128;
        u=128;
    }else{
        n=len_P/128+1;
    }
    v=len_A%128;
    if(v==0){
       m=len_A/128;
       v=128;
    }else{
        m=len_A/128+1;
    }
    if(len_A == 0){
        v=0;
        m=1;
    }
    if(len_P==0){
        u=0;
        n=1;
    }
    u_IV=len_IV%128;
    if(u_IV==0){
       n_IV=len_IV/128;
       u_IV=128;
    }else{
        n_IV=len_IV/128+1;
    }
    if(len_IV == 0){
        u_IV=0;
        n_IV=1;
    }

    //step 1
    uint8_t H[16];
    memset(H, 0x00, 16);
    aes_cipher((state_t*)H, expanded_key);

    //step 2
    uint8_t Y[16];
    if(len_IV == 96){
        memcpy(Y, IV, len_IV/8);
        //Y = IV||0000...01
        Y[12] = 0x00;
        Y[13] = 0x00;
        Y[14] = 0x00;
        Y[15] = 0x01;
    }else{
        gcm_ghash(H, (uint8_t*)"", IV, n_IV, 1, 0, u_IV, Y);
    }

    //step 3
    uint8_t Q[16];
    uint8_t S[16];
    memcpy(Q, Y, 16);
    aes_cipher((state_t*)Q, expanded_key);

    //step 4
    //actually i=1 -> i<n
    for(uint32_t i=0; i<n-1; i++){
        gcm_inc(Y);
        memcpy(S, Y, 16);
        aes_cipher((state_t*)S, expanded_key);
        xor_block(&P[i<<4], S, &C[i<<4], 16);
    }
    gcm_inc(Y);
    memcpy(S, Y, 16);
    //step 5
    aes_cipher((state_t*)S, expanded_key);
    memset(&C[(n-1)<<4], 0x00, 16);
    xor_block(&P[(n-1)<<4], S, &C[(n-1)<<4], u/8);
    //step 6
    memset(Y, 0x00, 16);    //reset Y
    // gcm_robo_ghash(A, C, H, Y);
    gcm_ghash(H, A, C, n, m, v, u, Y);
    //debug

    xor_block(Y, Q, Y, 16);
    uint32_t x = len_T/8;
    memcpy(T, &Y[16-x], x);

    return;
}


//all lenghts in #bits !!!
//Input: key, init vec (#bits = 1-2^64), plain text (#bits = 0- (2^39-256)), additional auth data AAD (#bits = 0-2^64)
//Output: cypher txt C (#bits = #bits_P), auth tag T (#bits=0-128=t)
uint8_t gcm_decrypt(uint8_t *key, uint8_t *IV, uint32_t len_IV,
                 uint8_t *P, uint32_t len_P, uint8_t *A, uint32_t len_A,
                 uint8_t *C, uint8_t *T, uint32_t len_T){
    uint8_t T_prime[len_T/8];

    //setup
    aes_key_expansion(key, expanded_key);

    uint32_t u=len_P%128;
    uint32_t n, m, v, n_IV, u_IV;
    if(u==0){
        n=len_P/128;
        u=128;
    }else{
        n=len_P/128+1;
    }
    v=len_A%128;
    if(v==0){
       m=len_A/128;
       v=128;
    }else{
        m=len_A/128+1;
    }
    if(len_A == 0){
        v=0;
        m=1;
    }
    if(len_P==0){
        u=0;
        n=1;
    }
    u_IV=len_IV%128;
    if(u_IV==0){
       n_IV=len_IV/128;
       u_IV=128;
    }else{
        n_IV=len_IV/128+1;
    }
    if(len_IV == 0){
        u_IV=0;
        n_IV=1;
    }
    //printf("\n\nsetup: u=%d, n=%d, v=%d, m=%d\n", u, n, v, m);

    //step 1
    uint8_t H[16];
    memset(H, 0x00, 16);
    aes_cipher((state_t*)H, expanded_key);


    //step 2
    uint8_t Y[16];
    if(len_IV == 96){
        memcpy(Y, IV, len_IV/8);
        //Y = IV||0000...01
        Y[12] = 0x00;
        Y[13] = 0x00;
        Y[14] = 0x00;
        Y[15] = 0x01;
    }else{
        gcm_ghash(H, (uint8_t*)"", IV, n_IV, 1, 0, u_IV, Y);
    }
    //step 3
    uint8_t Q[16];
    uint8_t S[16];
    memcpy(Q, Y, 16);
    aes_cipher((state_t*)Q, expanded_key);
    //step 4
    gcm_ghash(H, A, C, n, m, v, u, T_prime);
    xor_block(T_prime, Q, T_prime, 16);
    //step 5
    //actually i=1 -> i<n
    for(uint32_t i=0; i<n-1; i++){
        gcm_inc(Y);
        memcpy(S, Y, 16);
        aes_cipher((state_t*)S, expanded_key);
        xor_block((uint8_t*)&C[i<<4], S, &P[i<<4], 16);
    }
    gcm_inc(Y);
    memcpy(S, Y, 16);
    //step 5
    aes_cipher((state_t*)S, expanded_key);
    memset(&P[(n-1)<<4], 0x00, 16);
    xor_block((uint8_t*)&C[(n-1)<<4], S, &P[(n-1)<<4], u/8); //return this P

    for(uint32_t i=0; i<len_T/8; i++){
        if(T_prime[i] != T[i]){
            return 0x00;
        }
    }
    return 0x01;
}


void IV_construct(uint8_t *device_ID, uint64_t msg_cnt, uint8_t *IV){
    memcpy(IV, device_ID, 4);
    for(uint8_t i=0; i<8; i++){
        IV[4+i] = (msg_cnt>>(56-(i<<3))) & 0xFF;
    }
}



