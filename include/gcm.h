#ifndef GCM
#define GCM
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#ifndef INFO_DEBUG
    #define INFO_DEBUG 0x01
#endif
//flag = 0x01 means high log lvl
void debug_print(uint8_t *block, uint32_t size, char *name, uint32_t index, uint8_t flag);

/**
 * @brief XOR of to blocks (X^Y), with length len
 *
 * @param X, pointer to first block
 * @param Y, pointer to second block
 * @param Out, pointer to address for storing result
 * @param len, lenght of blocks
 */
void xor_block(uint8_t *X, uint8_t *Y, uint8_t *Out, uint32_t len);

//len x = 128
/**
 * @brief right shift of a block length 128bits
 *
 * @param X, pointer to the block
 */
void rshift_string(uint8_t *X);

/**
 * @brief converts integer value x to bit block X
 *
 * @param x, integer value to convert
 * @param X, pointer to address for storing result
 */
void int_to_byte(uint32_t x, uint8_t *X, uint32_t index_X, uint8_t len_X);

/**
 * @brief get the len MSB of block X
 *
 * @param X, pointer to the block
 * @param Out, pointer to address for storing result
 * @param len, lenght of MSBs (#MSB)
 */
void get_msb(uint8_t *X, uint8_t *Out, uint32_t len);

// gcm inc only used with s=32
/**
 * @brief increment the first 32 LSBs of a block
 *
 * @param Y, pointer to the block
 */
void gcm_inc(uint8_t *Y);

/**
 * @brief gcm block multiply function
 *
 * @param X, pointer to the first block
 * @param Y, ponter to the second block
 * @param Out, pointer to address for storing result
 */
void gcm_block_mul(const uint8_t *X, const uint8_t *H, uint8_t *Y);

/**
 * @brief gcm hash function
 *
 * @param H, pointer to the hash subkey
 * @param A, pointer to the additional authentication data
 * @param C, pointer to the ciphertext
 * @param n, plaintext P is size of (n-1)*128+u
 * @param m, A is size of (m-1)*128+v
 * @param u, plaintext P is size of (n-1)*128+u
 * @param v, A is size of (m-1)*128+v
 * @param X, pointer to address for storing result
 */
void gcm_ghash(uint8_t *H, uint8_t *A, uint8_t *C, uint32_t n, uint32_t m, uint32_t v, uint32_t u, uint8_t *X);

/**
 * @brief gcm encryption function (gcm-spec.pdf p.4)
 *
 * @param key, pointer to the key
 * @param IV, pointer to the init vector
 * @param len_IV, lenght of the IV block
 * @param P, pointer to the plaintext P
 * @param len_P, lenght of the P block
 * @param A, pointer to the additional authentication data
 * @param len_A lenght of the A block
 * @param C, pointer to the ciphertext
 * @param T, pointer to the T block
 * @param t, lenght of the T block
 */
void gcm_encrypt(uint8_t *key, uint8_t *IV, uint32_t len_IV,
                 uint8_t *P, uint32_t len_P, uint8_t *A, uint32_t len_A,
                 uint8_t *C, uint8_t *T, uint32_t len_T);

/**
 * @brief gcm decryption function (gcm-spec.pdf p.7)
 *
 * @param key, pointer to the key
 * @param IV, pointer to the init vector
 * @param len_IV, lenght of the IV block in bits
 * @param P, pointer to the plaintext P, result gets written into this array
 * @param len_P, lenght of the P block in bits
 * @param A, pointer to the additional authentication data
 * @param len_A lenght of the A block in bits
 * @param C, pointer to the ciphertext
 * @param T, pointer to the T block
 * @param t, lenght of the T block in bits
 * @return 0x01 if success (T' == T) else return 0x00
 */
uint8_t gcm_decrypt(uint8_t *key, uint8_t *IV, uint32_t len_IV,
                 uint8_t *P, uint32_t len_P, uint8_t *A, uint32_t len_A,
                 uint8_t *C, uint8_t *T, uint32_t len_T);

/**
 * @brief gcm IV contruct function
 *
 * @param deviceID, id of the device
 * @param msg_cnt, counter for the amount of messages send
 * @param IV, pointer to the IV, this is returned
 */
void IV_construct(uint8_t *device_ID, uint64_t msg_cnt, uint8_t *IV);



#endif // GCM
