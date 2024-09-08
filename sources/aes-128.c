#include "aes-128.h"

// size Nb * (Nr+1) in 32bit words so 4* as we use bytes
// Nb: Number of bytes in the key
// Nr: Number of rounds(10 in the case of aes 128)
static uint8_t expanded_key[4*Nb*(Nr+1)];

/*expand key test 
int main(int argc, char const *argv[]) {
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 
            0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    KeyExpansion(key, expanded_key);
    return 0;
}*/

void aes_cipher(state_t *state, uint8_t *RoundKey) {
    #ifdef PRINT_STATE
    printf("round[0].input\t");
    print_state(state);
    #endif
    aes_add_round_key(state, RoundKey, 0);
    #ifdef PRINT_STATE
    printf("round[0].k_sch\t");
    print_key(RoundKey, 0);
    #endif
    // Round 1 -> 9
    for (uint8_t i = 1; i < 10; i++) {
        #ifdef PRINT_STATE
        printf("round[%d].start\t", i);
        print_state(state);
        #endif
        aes_sub_bytes(state);
        #ifdef PRINT_STATE
        printf("round[%d].s_box\t", i);
        print_state(state);
        #endif
        aes_shift_rows(state);
        #ifdef PRINT_STATE
        printf("round[%d].s_row\t", i);
        print_state(state);
        #endif
        aes_mix_columns(state);
        #ifdef PRINT_STATE
        printf("round[%d].m_col\t", i);
        print_state(state);
        #endif
        aes_add_round_key(state, RoundKey, i);
        #ifdef PRINT_STATE
        printf("round[%d].k_sch\t", i);
        print_key(RoundKey, i);
        #endif
    }
    
    // Round 10, final round
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, RoundKey, 10);
    #ifdef PRINT_STATE
    printf("round[10].k_sch\t");
    print_key(RoundKey, 10);
    printf("round[10].out\t");
    print_state(state);
    #endif
}

void aes_inv_cipher(state_t *state, uint8_t *Roundkey) {
    aes_add_round_key(state, Roundkey, Nr);
    for (uint8_t i = Nr-1; i > 0; i--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, Roundkey, i);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, Roundkey, 0);
}

void aes_key_expansion(uint8_t *key, uint8_t *RoundKey) {
    // i is for iteration, j to index the bytes in each 32bit word 
    uint8_t i, j, k;
    // one word(32bit)
    uint8_t temp[4] = {0};
    // temp value needed in RotWord
    uint8_t shift_tmp;

    // first Round key is the key itself(first 16 bytes/ 4 words)
    for (i = 0; i < 4; i++) {
        j = 4 * i;
        RoundKey[j] = key[j];
        RoundKey[j+1] = key[j+1];
        RoundKey[j+2] = key[j+2];
        RoundKey[j+3] = key[j+3];
    }
    // 192 == size of the expanded key in bytes
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        //copy the last 32 bytes of the key
        j = 4 * (i-1);
        temp[0] = RoundKey[j];
        temp[1] = RoundKey[j+1];
        temp[2] = RoundKey[j+2];
        temp[3] = RoundKey[j+3];
        if (i % 4 == 0) {
            //first rotate word and then use S-Box
            //RotWord() shifts the bytes in the word left by 1
            shift_tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = shift_tmp;

            //SubWord applies the S Box
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];

            // Rcon[i] is {rc_i, 00, 00, 00} so we only need to XOR the first byte
            temp[0] ^= Rcon[i/4];
        }
        // w[i] = w[i-Nk]; Nk == 4 in aes128
        j = i * 4;//== w[i] as we address the bytes individualy
        k = (i - 4) * 4;//== i-Nk
        RoundKey[j] = RoundKey[k] ^ temp[0];
        RoundKey[j+1] = RoundKey[k+1] ^ temp[1];
        RoundKey[j+2] = RoundKey[k+2] ^ temp[2];
        RoundKey[j+3] = RoundKey[k+3] ^ temp[3];
    }
}

void aes_sub_bytes(state_t *state) {
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            (*state)[i][j] = s_box[(*state)[i][j]];
        }
    }    
}

void aes_inv_sub_bytes(state_t *state) {
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            (*state)[i][j] = inv_s_box[(*state)[i][j]];
        }
    }
}

void aes_shift_rows(state_t *state) {
    uint8_t temp;
    //rotate second row by 1
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;
    //rotate third row by 2 by first swaping 0 and 2
    // and then 1 and 3
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;
    //rotate 4th row by 3
    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[0][3];
    (*state)[0][3] = temp;
}

void aes_inv_shift_rows(state_t *state) {
    uint8_t temp;
    //row 1
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;
    
    //row 2 same as in the non inv variant
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    //row 3
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

void aes_mix_columns(state_t *state) {
    //previous states
    uint8_t s0, s1, s2, s3;
    for (uint8_t i = 0; i < 4; i++) {// for each Collumns
        s0 = (*state)[i][0];
        s1 = (*state)[i][1];
        s2 = (*state)[i][2];
        s3 = (*state)[i][3];
        (*state)[i][0] = xtime(s0) ^ gf_multiply(s1, 3) ^ s2 ^ s3;
        (*state)[i][1] = s0 ^ xtime(s1) ^ gf_multiply(s2, 3) ^ s3;
        (*state)[i][2] = s0 ^ s1 ^ xtime(s2) ^ gf_multiply(s3, 3);
        (*state)[i][3] = gf_multiply(s0, 3) ^ s1 ^ s2 ^ xtime(s3);
    }
}

void aes_inv_mix_columns(state_t *state) {
    //previous states
    uint8_t s0, s1, s2, s3;
    for (uint8_t i = 0; i < 4; i++) {// for each Collumns
        s0 = (*state)[i][0];
        s1 = (*state)[i][1];
        s2 = (*state)[i][2];
        s3 = (*state)[i][3];
        (*state)[i][0] = gf_multiply(s0, 0x0e) ^ gf_multiply(s1, 0x0b) ^ gf_multiply(s2, 0x0d) ^ gf_multiply(s3, 0x09);
        (*state)[i][1] = gf_multiply(s0, 0x09) ^ gf_multiply(s1, 0x0e) ^ gf_multiply(s2, 0x0b) ^ gf_multiply(s3, 0x0d);
        (*state)[i][2] = gf_multiply(s0, 0x0d) ^ gf_multiply(s1, 0x09) ^ gf_multiply(s2, 0x0e) ^ gf_multiply(s3, 0x0b);
        (*state)[i][3] = gf_multiply(s0, 0x0b) ^ gf_multiply(s1, 0x0d) ^ gf_multiply(s2, 0x09) ^ gf_multiply(s3, 0x0e);
    }
}

void aes_add_round_key(state_t *state, uint8_t *roundKey, uint8_t round) {
    uint8_t round_offset = round * 16;
    for (uint8_t i = 0; i < 4; i++) {//for each through collumns
        for (uint8_t j = 0; j < 4; j++) {//for each through elemtents
            //add key
            (*state)[i][j] ^= roundKey[(i*4)+j+round_offset];
        }        
    }    
}

uint8_t xtime(uint8_t x) {
    uint8_t result = 0;
    // x>>7 & 0b1 is the same as "if(bit7 == 1) x ^ 0x1b" => conditional xor with 0x1b
    // also avoids timing side channels there are no branches or conditional execution
    result = x<<1 ^ (((x >> 7 ) & 0b1) * 0x1b);
    return result;
}

uint8_t gf_multiply(uint8_t a, uint8_t b) {
    //calls xtime() n times on x if bit n is 1 and XOR everthing together
    //works because A*0x08 == xtime(xtime(xtime(A)))
    uint8_t result = 0;
    //if bit n in b==1 we use xtime n times and add(XOR in GF) the results
    //only need to check the first 4 bits as (Inv)MixColumns uses no larger numbers
    result = ((b & 1) * a) ^ 
             ((b>>1 & 1) * xtime(a)) ^ 
             ((b>>2 & 1) * xtime(xtime(a))) ^
             ((b>>3 & 1) * xtime(xtime(xtime(a)))) ^
             ((b>>4 & 1) * xtime(xtime(xtime(xtime(a)))));
    return result;
}



void print_state(state_t *state) {
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            printf("%02x", (*state)[i][j]);
        }
    }
    printf("\n");
}

void print_key(uint8_t *roundKey, uint8_t round) {
    uint8_t round_offset = round * 16;
    for (uint8_t i = 0; i < 4; i++) {//for each through collumns
        for (uint8_t j = 0; j < 4; j++) {//for each through elemtents
            //add key
            printf("%02x",roundKey[(i*4)+j+round_offset]);
        }        
    }
    printf("\n");
}

void test_xtime() {
    printf("Test xtime()\n");

    printf("input: 57, output: %02x, expected: ae\n", xtime(0x57));
    printf("input: ae, output: %02x, expected: 47\n", xtime(0xae));
    printf("input: 47, output: %02x, expected: 8e\n", xtime(0x47));
    printf("input: 8e, output: %02x, expected: 07\n", xtime(0x8e));
}

void test_gfmul() {
    printf("Test gf_multiply\n");
    printf("input: 57, 13, output: %02x, expected: fe\n", gf_multiply(0x57, 0x13));
    printf("gf_multiply(0x63,0x3)= %02x, xtime(0x63)^0x63= %02x\n",gf_multiply(0x63,0x3), xtime(0x63)^0x63);
}
