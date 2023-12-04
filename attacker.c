/* Distinguishing attack on reduced round AES
 *
 * Attacker:  [TODO: INSERT NAME HERE]
 */

#include <stdlib.h>
#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint-gcc.h>

#include "game.h"

#define RED "\033[0;31m"
#define RESET "\033[0m"
#define NTEXTS 4
#define PTGROUP_SIZE (MAXBLOCKS/NTEXTS)

typedef struct
{
    u16 counts[PTGROUP_SIZE];
    u8 isUnique[PTGROUP_SIZE];
}Uniques;

Uniques findUniques(void *texts,u16 startingBlock, u16 endingBlock);


Uniques findUniques(void *_text, u16 startingBlock, u16 endingBlock) {
    Uniques ret;
    memset(ret.counts,  0, sizeof(ret.counts));
    memset(ret.isUnique,1, sizeof(ret.isUnique));
    u8 *text = _text;
    u16 off = startingBlock;
    for (u16 i = startingBlock; i < endingBlock; ++i) {
        if(ret.isUnique[i -off]){
            for (u16 j = i+1; j < endingBlock; ++j) {
                if (memcmp(&text[i * BLOCKSIZE],&text[j * BLOCKSIZE], BLOCKSIZE) == 0) {
                    ret.counts[i-off]++;
                    ret.isUnique[j-off] = 0;
                }
            }
        }
    }
    return ret;
}

//fill Challenge.pt with at most MAXBLOCKS plaintext blocks of BLOCKSIZE bytes
//     store number of blocks in Challenge.nblocks
void attacker_generate_pt(int n)
{

    for (int i = 0; i < 768; i++){
        Challenge.pt[i*BLOCKSIZE+0] = 1;
        if (i >= 256){
            Challenge.pt[i*BLOCKSIZE+1] = 1;
            if (i >= 512){
                Challenge.pt[i*BLOCKSIZE+2] = 1;
            }
        }

    }

    Challenge.nblocks = 1024;
}


void get_keys(Uniques uniq, u8* kekes, int offset){

    int max = 0;
    int idx = 0;
    for (int i = 0; i < PTGROUP_SIZE; i++){
        if (uniq.counts[i] > max){
            max = uniq.counts[i];
            idx = i;
        }
    }

    // correct ct
    u8* ct =  &Challenge.ct[(offset + idx) * BLOCKSIZE + 0];

    // blocks with one byte difference in 0 position
    u8 bytes[BLOCKSIZE * PTGROUP_SIZE];
    for (int i = 0; i < PTGROUP_SIZE; i++){
        u8* tmp = &Challenge.ct[(offset + i)*BLOCKSIZE + 0];
        for (int j = 0; j < BLOCKSIZE; j++){
            bytes[(i*BLOCKSIZE) + j] = ct[j] ^ tmp[j];
        }
    }

    int foundBlocks[PTGROUP_SIZE];
    int counter = 0;
    for (int i = 0; i < PTGROUP_SIZE*BLOCKSIZE; i+=BLOCKSIZE){
        int diff = 0;
            for (int j = 0; j < BLOCKSIZE; j++) {
                if (bytes[i + j] != 0) {
                    diff++;
                }
            }
            if (diff == 1){
                foundBlocks[counter] = i;
                counter +=1;
            }
    }

    u32 f[PTGROUP_SIZE] = {0};
    int fc = 0;
    for (int i = 0; i < counter; i++){
        u8 y = Challenge.ct[(offset*BLOCKSIZE) + foundBlocks[i] + 0];
        if (ct[0] ^ y){
            f[fc] = foundBlocks[i];
            fc++;
        }
    }

    // key hypothesis
    // T^-1(x_1 xor k) xor T^-1(x_1' xor k) = 0

    u8 x = ct[0];
    u8 xors[fc*256];
    u8 keys[fc*256];
    u16 ct_ = 0;

    for (int i = 0; i < fc; i++){
        u8 y = Challenge.ct[offset + f[i] + 0];
        for (u16 k = 0; k < 256; k++){
            xors[ct_] = Td4[x^k]^Td4[y^k];
            keys[ct_] = k;
            ct_ += 1;
        }
    }

    int kekes_counter = 0;

    for (int i = 0; i < ct_; i++){
        if (xors[i] == 1){
            kekes[kekes_counter] = keys[i];
            kekes_counter ++;
        }
    }
}

uint8_t findMostCommonElement(const uint8_t *arr1, int size1,
                              const uint8_t *arr2, int size2,
                              const uint8_t *arr3, int size3,
                              const uint8_t *arr4, int size4) {
    // Assuming u8 is an alias for uint8_t

    // Calculate the total size after concatenation
    int totalSize = size1 + size2 + size3 + size4;

    // Allocate memory for the concatenated array
    uint8_t *concatenatedArray = (uint8_t *)malloc(totalSize * sizeof(uint8_t));

    // Copy the elements from the first array
    for (int i = 0; i < size1; i++) {
        concatenatedArray[i] = arr1[i];
    }

    // Copy the elements from the second array
    for (int i = 0; i < size2; i++) {
        concatenatedArray[size1 + i] = arr2[i];
    }

    // Copy the elements from the third array
    for (int i = 0; i < size3; i++) {
        concatenatedArray[size1 + size2 + i] = arr3[i];
    }

    // Copy the elements from the fourth array
    for (int i = 0; i < size4; i++) {
        concatenatedArray[size1 + size2 + size3 + i] = arr4[i];
    }

    // Initialize an array to store the frequency of each element
    int frequency[256] = {0};

    // Iterate through the concatenated array and update the frequency array
    for (int i = 0; i < totalSize; i++) {
        frequency[concatenatedArray[i]]++;
    }

    // Find the element with the highest frequency
    uint8_t mostCommonElement = 0;
    int maxFrequency = 0;

    for (int i = 0; i < 256; i++) {
        if (frequency[i] > maxFrequency) {
            maxFrequency = frequency[i];
            mostCommonElement = (uint8_t)i;
        }
    }

    // Free the allocated memory
    free(concatenatedArray);

    return mostCommonElement;
}


int get_keys2(Uniques uniq, u8* kekes, u8* text){

    int max = 0;
    int idx = 0;
    for (int i = 0; i < 256; i++){
        if (uniq.counts[i] > max){
            max = uniq.counts[i];
            idx = i;
        }
    }

    // correct ct
    u8* ct =  &text[idx*BLOCKSIZE + 0];

    // blocks with one byte difference in 0 position
    u8 bytes[BLOCKSIZE * 256];
    for (int i = 0; i < 256*BLOCKSIZE; i += BLOCKSIZE){
        u8* tmp = &text[i + 0];
        for (int j = 0; j < BLOCKSIZE; j++){
            bytes[i + j] = ct[j] ^ tmp[j];
        }
    }

    int foundBlocks[256];
    int counter = 0;
    for (int i = 0; i < 256*BLOCKSIZE; i+=BLOCKSIZE){
        bool more = 0;
        if (bytes[i] != 0){
            for (int j = 1; j < BLOCKSIZE; j++){
                if (bytes[i + j] != 0){
                    more = 1;
                    break;
                }
            }
            if (more == 0){
                foundBlocks[counter] = i;
                counter +=1;
            }
        }
    }

    // key hypothesis
    // T^-1(x_1 xor k) xor T^-1(x_1' xor k) = 0

    u8 x = ct[0];
    u8 xors[counter*256];
    u8 keys[counter*256];
    u16 ct_ = 0;

    for (int i = 0; i < counter; i++){
        u8 y = text[foundBlocks[i] + 0];
        for (u16 k = 0; k < 256; k++){
            xors[ct_] = Td4[x^k]^Td4[y^k];
            keys[ct_] = k;
            ct_ += 1;
        }
    }

    int kekes_counter = 0;

    for (int i = 0; i < ct_; i++){
        if (xors[i] == 1){
            kekes[kekes_counter] =  (u8)i;
            kekes_counter ++;
        }
    }
    return kekes_counter;
}

//guess the number of rounds that were used to encrypt the challenge PT
const u8 attacker_guess()
{
    u8 keyguess = 0;
    Uniques uniq1  = findUniques(Challenge.ct,0,256);
    u8 kekes1[256] = {0};
    u8 *text = &Challenge.ct[0];
    int size1 = get_keys2(uniq1,kekes1, text);

    Uniques uniq2  = findUniques(Challenge.ct,256,512);
    u8 kekes2[256] = {0};
    u8 *text2 = &Challenge.ct[256*BLOCKSIZE];
    int size2 = get_keys2(uniq2,kekes2, text2);


    Uniques uniq3  = findUniques(Challenge.ct,512,768);
    u8 kekes3[256] = {0};
    u8 *text3 = &Challenge.ct[512*BLOCKSIZE];
    int size3 = get_keys2(uniq3,kekes3, text3);

    Uniques uniq4  = findUniques(Challenge.ct,768,1024);
    u8 kekes4[256] = {0};
    u8 *text4 = &Challenge.ct[768*BLOCKSIZE];
    int size4 = get_keys2(uniq4,kekes4, text4);


    keyguess = findMostCommonElement(kekes1, size1, kekes2, size2, kekes3, size3, kekes4, size4 );
    // overlap

    return keyguess;
}
