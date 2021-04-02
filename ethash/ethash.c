#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <math.h>  // pow
#include <string.h>
#include <inttypes.h> // uint64
#include "lib/sha3.h" // Credit: https://github.com/brainhub/SHA3IUF/blob/master/sha3.h
#include "lib/mt64.h" // http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt64.html

// change this for testing
#define CACHE_SIZE 1024     // cache size (should be around 16MB)
#define DATASET_SIZE 300*1024*1024  // dataset size (shoule be around 1GB)
#define TIME_LIMIT  100     // maximum times of mining, will give up if reach this limit
// #define PRINT_RESULT        // if define, will print result of each try on mining


// fixed parameter in spec
#define WORD_BYTES 4  // bytes in word
#define DATASET_BYTES_INIT (1 << 30)  // bytes in dataset at genesis
#define DATASET_BYTES_GROWTH (1 << 23)  // dataset growth per epoch
#define CACHE_BYTES_INIT (1 << 24)  // bytes in cache at genesis
#define CACHE_BYTES_GROWTH (1 << 17)  // cache growth per epoch
#define CACHE_MULTIPLIER 1024  // Size of the DAG relative to the cache
#define EPOCH_LENGTH 30000  // blocks per epoch
#define MIX_BYTES 128  // width of mix
#define HASH_BYTES 64  // hash length in bytes
#define DATASET_PARENTS 256  // number of parents of each dataset element
#define CACHE_ROUNDS  3  // number of rounds in cache production
#define ACCESSES 64  // number of accesses in hashimoto loop
#define FNV_PRIME 0x01000193  // fnv() parameter


// Credit: https://stackoverflow.com/questions/8534274/is-the-_strrev-function-not-available-in-linux
//char *_strrev(char *str)
//{
//    if (!str || ! *str)
//        return str;
//
//    int i = strlen(str) - 1, j = 0;
//
//    char ch;
//    while (i > j)
//    {
//        ch = str[i];
//        str[i] = str[j];
//        str[j] = ch;
//        i--;
//        j++;
//    }
//    return str;
//}

// convert a byte array to int
// input: byte array
// output: corresponding int
int decode_int(char* s) {
    if (!s) {
        return 0;
    }

    char hex[9];

    // convert byte array to hex string
    // here consider little endian
    snprintf(hex, 9, "%02x%02x%02x%02x", (unsigned char)s[3],
        (unsigned char)s[2], (unsigned char)s[1], (unsigned char)s[0]);
    int number = (int)strtol(hex, NULL, 16);

    return number;
}


// encode int to byte array
// input: s : int to covert
//        pad_length : = length to pad by '\0' (should not < 4)
// output: byte array
// note: will malloc string
char* encode_int(int s, int pad_length) {
    if (s == 0) {
        return "";
    }

    char hex[8];

    // convert s to hex string
    int hex_len = snprintf(hex, 9, "%x", s);


    // pad 0 at begin to make len be even
    char padded_hex[8];

    // fix bug here: use strcat or strcpy leads to core dump in gem5
    if (hex_len % 2 == 1) {
        padded_hex[0] = '0';
        for (int i = 0; i < hex_len; i++) {
            padded_hex[i + 1] = hex[i];
        }
        hex_len += 1;
    }
    else {
        for (int i = 0; i < hex_len; i++) {
            padded_hex[i] = hex[i];
        }
    }

    // convert hex string to bytearray, little endian
    char* bytearray = malloc(pad_length);
    char* pos = padded_hex;

    int num_pad = pad_length - (hex_len / 2);

    for (int count = 1; count <= (hex_len / 2); count++) {
        sscanf((unsigned char*)pos, "%2hhx", &bytearray[pad_length - num_pad - count]);
        pos += 2;
    }

    // pad '0/'
    for (int count = (hex_len / 2) + 1; count <= pad_length; count++) {
        bytearray[count] = '\0';
    }

    return bytearray;
}


// encode uint64 to byte array (padded to 8 bytes)
// input: s : uint64 to covert
// output: 8 bytes char array
// note: will malloc string
char* encode_int64(uint64_t s) {
    if (s == 0) {
        return "";
    }

    char hex[16];

    // convert s to hex string
    int hex_len = snprintf(hex, 17, "%lx", s);


    // pad 0 at begin to make len be even
    char padded_hex[16];

    // fix bug here: use strcat or strcpy leads to core dump in gem5
    if (hex_len % 2 == 1) {
        padded_hex[0] = '0';
        for (int i = 0; i < hex_len; i++) {
            padded_hex[i + 1] = hex[i];
        }
        hex_len += 1;
    }
    else {
        for (int i = 0; i < hex_len; i++) {
            padded_hex[i] = hex[i];
        }
    }

    // convert hex string to bytearray, little endian
    char* bytearray = malloc(8);
    char* pos = padded_hex;

    int num_pad = 8 - (hex_len / 2);

    for (int count = 1; count <= (hex_len / 2); count++) {
        sscanf((unsigned char*)pos, "%2hhx", &bytearray[8 - num_pad - count]);
        pos += 2;
    }

    // pad '0/'
    for (int count = (hex_len / 2) + 1; count <= 8; count++) {
        bytearray[count] = '\0';
    }

    return bytearray;
}


// convert given int array to a long hex encoded byte array
// input: int array and its length
// output: byte array
char* serialize_hash(int* h, int length) {
    char* hash = (char*)malloc(4 * length);

    for (int i = 0; i < length; i++) {
        char* temp = encode_int(h[i], 4);

        strcat(hash, temp);
    }

    return hash;
}


// convert a long hex encoded byte array to int array
// input: byte array and its length
// output int array
// note: will malloc int array
int* deserialize_hash(char* h, int length) {
    // each int correspoding to 4 bytes in bytes array
    int* hash = (int*)malloc(length * sizeof(int));

    // convert each 4 bytes to int
    char* pos = h;

    for (int i = 0; i < strlen(h) / 4; i++) {
        char temp[4];
        strncpy(temp, pos, 4);

        hash[i] = decode_int(temp);
    }

    return hash;
}


// hash the int array by function h
// size is the size of x
// h is a function pointer to hash function
// will return int array
// l is a pointer for returned array, compute by this function
// TODO: check malloc and free
int* hash_words(char* h(char*, int), int size, char* x) {
    char* y = h(x, size);
    return deserialize_hash(y, 16);
}


// same as hash_words(), but x is a int array
int* hash_words_list(char* h(char*, int), int size, int* x) {
    char* temp = serialize_hash(x, size);
    char* y = h(temp, size);
    return deserialize_hash(y, 16);
}


// A warpper for sha3_HashBuffer() in lib/sha3.h
// will be used by sha3 as a function pointer
char* sha3_512_wrapper(char* x, int size) {
    char* out = malloc(512);
    sha3_HashBuffer(512, SHA3_FLAGS_KECCAK, x, size, out, 512);
    return out;
}


// A warpper for sha3_HashBuffer() in lib/sha3.h
// will be used by sha3 as a function pointer
char* sha3_256_wrapper(char* x, int size) {
    char* out = malloc(256);
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, x, size, out, 256);
    return out;
}


// sha3 hash function, outputs 32/64 bytes
// input: x: char * or int *
//        is: if is_256 != 0, it means sha3_512, otherwise sha3_256
//        is_list: if is_list != 0, it means x is a int array
//        size: size of x
int* sha3(int is_256, void* x, int is_list, int size) {
    if (is_256) {
        if (is_list != 0) {
            return hash_words_list(sha3_256_wrapper, size, (int*)x);
        }
        return hash_words(sha3_256_wrapper, size, (char*)x);
    }
    else {
        if (is_list != 0) {
            return hash_words_list(sha3_512_wrapper, size, (int*)x);
        }
        return hash_words(sha3_512_wrapper, size, (char*)x);
    }
}


struct Block {
    int number;
};

int fnv(int v1, int v2) {
    return v1 * FNV_PRIME ^ v2;
}

// generate one element in dataset
// input: cache: int array, generated by mkcache
//        len: length of cache
//        i: index of this element in dataset
// output: int array
unsigned int* calc_dataset_item(unsigned int** cache, int len, int i) {
    int r = HASH_BYTES / WORD_BYTES;
    // initialize the mix
    unsigned int mix[16];
    memcpy(mix, cache[i % len], 64);
    mix[0] ^= i;

    // sha3 malloc int array, so need to free it
    unsigned int* temp = sha3(0, mix, 1, 64);
    memcpy(mix, temp, 64);
    free(temp);

    // fnv it with a lot of random cache nodes based on i
    for (int j = 0; j < DATASET_PARENTS; j++) {
        int cache_index = fnv(i ^ j, mix[j % r]);

        for (int k = 0; k < 16; k++) {
            mix[k] = fnv(mix[k], cache[cache_index % len][k]);
        }

    }

    return sha3(0, mix, 1, 64);
}

// generate (typically 1GB) dataset based on (typically 16MB) cache
// input: full_size: dataset size
//        cache: int array, generated by mkcache
//        cache_size: size of cache
// output: int array
unsigned int** calc_dataset(int full_size, unsigned int** cache, int cache_size) {
    int loop_times = full_size / HASH_BYTES;
    unsigned int** o = malloc(sizeof(int*) * loop_times);

    for (int i = 0; i < loop_times; i++) {
        o[i] = calc_dataset_item(cache, cache_size / 64, i);
    }

    return o;
}


// generate cache
// input: cache size and seed
// output: int array
unsigned int** mkcache(int cache_size, char* seed) {
    int n = cache_size / HASH_BYTES;

    // Sequentially produce the initial dataset
    unsigned int** o = malloc(sizeof(int*) * n);
    o[0] = sha3(0, seed, 0, 32);

    for (int i = 1; i < n; i++) {
        o[i] = sha3(0, o[i - 1], 1, 64);
    }

    // Use a low - round version of randmemohash
    for (int i = 0; i < CACHE_ROUNDS; i++) {
        for (int j = 0; j < n; j++) {
            unsigned int v = o[j][0] % n;

            // map xor over o[(i - 1 + n) % n], o[v]
            unsigned int temp[16];
            for (int k = 0; k < 16; k++) {
                temp[k] = o[(j - 1 + n) % n][k] ^ o[v][k];
            }
            o[j] = sha3(0, temp, 1, 64);
        }
    }

    return o;
}

// aggregate data from the full dataset 
// to produce final result for given header and nonce
// main loop of the algorithm
// if dataset is NULL, will use file "dataset" instead
char* hashimoto_full(int full_size, unsigned int** dataset, char* header, int header_size, 
                     uint64_t nonce, FILE* fp) {
    int n = full_size / HASH_BYTES;
    int w = MIX_BYTES / WORD_BYTES;
    int mixhashes = MIX_BYTES / HASH_BYTES;

    // combine header + nonce into a 64 byte seed
    char* nonce_encoded = encode_int64(nonce);
    char seed[header_size + 8];
    for (int i = 0; i < header_size; i++) {
        seed[i] = header[i];
    }

    for (int i = 0; i < 8; i++) {
        seed[header_size + i] = nonce_encoded[8 - 1 - i];
    }

    int* s = sha3(0, seed, 0, header_size + 8);

    // start the mix with replicated s
    int mix[w];
    for (int i = 0; i < mixhashes; i++) {
        for (int j = 0; j < 16; j++) {
            mix[i*16 + j] = s[j];
        }
    }

    // mix in random dataset nodes
    for (int i = 0; i < ACCESSES; i++) {
        int p = fnv(i ^ s[0], mix[i % w]) % (n / mixhashes) * mixhashes;

        int newdata[w];

        for (int j = 0; j < mixhashes; j++) {
            // look up 64 bytes in dataset
            if (!dataset) {
                fseek(fp, (p + j) * 64, SEEK_SET);
                if (fread(newdata + (j * 16), sizeof(int), 16, fp) != 16) {
                    printf("File read error.");
                    exit(0);
                }
            }
            else {
                int* slices = dataset[p + j];
                for (int k = 0; k < 16; k++) {
                    newdata[j * 16 + k] = slices[k];
                }
            }
        }

        // map(fnv, mix, newdata)
        for (int j = 0; j < w; j++) {
            mix[j] = fnv(mix[j], newdata[j]);
        }
    }

    // compress mixs
    // header_size + 8 is the size of s
    // which will be combined with cmix
    // so researve space in advance
    int offset = header_size + 8;
    int cmix[offset + (w / 4)];
    for (int i = 0; i < w/4; i++) {
        int k = i * 4;
        cmix[offset + i] = fnv(fnv(fnv(mix[k], mix[k + 1]), mix[k + 2]), mix[k + 3]);
    }

    // copy s to cmix
    for (int i = 0; i < offset; i++) {
        cmix[i] = s[i];
    }
    free(s);

    int *temp = sha3(1, cmix, 1, offset + (w / 4));
    char *result = serialize_hash(temp, 8);
    free(temp);

    return result;
}



// generate seedhash based on block number
// input: block struct
char* get_seedhash(struct Block block) {
    char* s = malloc(32);
    for (int i = 0; i < 32; i++) {
        s[i] = '\0';
    }

    // no need to implement this for block.number = 1
    // for (int i = 0; i < block.number / EPOCH_LENGTH; i++) {
    //     s = 
    // }
    return s;
}


// mine a block
// input: full_size: size of dataset
//        dataset: int array, it is it null, will looking for file "dataset"
//        header: header of the block
//        difficulty: difficulty to mine the block
// output: nonce, if not found in given times, return 0
// Note: difficulty is acutally a fixed number in this function, see comment below
uint64_t mine(int full_size, unsigned int** dataset, char* header, int header_size, int difficulty) {
    // in python: "2 ** 256 // difficulty"
    // no int256 support in C, so difficulty actually is fixed in this program
    // TODO: should be fixed in the future
    // currently can only do this calculation by hand
    int target = 1;

    // randint(0, 2 ** 64)
    init_genrand64(0);
    uint64_t nonce = genrand64_int64();

    int i = 0;
    unsigned int result;

    // exisiting dataset will be used if dataset = NULL
    FILE* fp = NULL;
    if (!dataset) {
        if ((fp = fopen("dataset", "rb")) == NULL) {
            printf("Cannot open file.\n");
            return 0;
        }
    }

    do {
        if (i >= TIME_LIMIT) {
            printf("tried %d times without finding solution, give up.\n", i);
            return 0;
        }

        result = decode_int(hashimoto_full(full_size, dataset, header, header_size, nonce, fp));
        // in python "nonce = (nonce + 1) % 2 ** 64"
        // no need to do the mod by exploiting the overflow in uint64_t
        nonce += 1;
        i += 1;

#ifdef PRINT_RESULT
        printf("%x\n", result);
#endif
    } while (1);

    printf("tried %d times. Found solution with nonce = %lx\n", i, nonce);

    if (!dataset) {
        fclose(fp);
    }
    return nonce;
}


// Run the whole algorithm
// gen cache -> gen dataset -> mine on dataset
void test_whole_algortihm() {
    int header_size = 508 + 8 * 5;

    struct Block block = { 1 };

    // create byte array with header_size
    char* header = malloc(header_size);
    for (int i = 0; i < header_size; i++) {
        header[i] = '\0';
    }

    // difficulty in genesis block
    // Credit: https://lightrains.com/blogs/setup-local-ethereum-blockchain-private-testnet
    int difficulty = 0x4000;

    int cache_size = CACHE_SIZE;
    int full_size = DATASET_SIZE;
    char* seedhash = get_seedhash(block);
    printf("Target: make dataset and mine it.\n");
    printf("Step (1/3): Make cache (around 16MB)... \n");
    unsigned int** cache = mkcache(cache_size, seedhash);
    printf("Step (1/3) finished.\n");
    printf("Step (2/3): Make dataset (around 1GB)... May takes several hours to do so\n");
    unsigned int** dataset = calc_dataset(full_size, cache, cache_size);
    printf("Step (2/3) finished.\n");
    printf("Step (3/3) mine a block...\n");
    uint64_t nonce = mine(full_size, dataset, header, header_size, difficulty);
    printf("Step (3/3) finished.\n");
    printf("\nProgram ends.\n");
}


// generate and save dataset to file "dataset" for future use
void save_dataset() {
    int header_size = 508 + 8 * 5;

    struct Block block = { 1 };

    // create byte array with header_size
    char* header = malloc(header_size);
    for (int i = 0; i < header_size; i++) {
        header[i] = '\0';
    }

    int cache_size = CACHE_SIZE;
    int full_size = DATASET_SIZE;
    int loop_times = full_size / HASH_BYTES;

    char* seedhash = get_seedhash(block);
    printf("Target: make dataset and save it to a file.\n");
    printf("Step (1/3): Make cache (around 16MB)... \n");
    unsigned int** cache = mkcache(cache_size, seedhash);
    printf("Step (1/3) finished.\n");
    printf("Step (2/3): Make dataset (around 1GB)... May takes several hours to do so\n");
    unsigned int** dataset = calc_dataset(full_size, cache, cache_size);
    printf("Step (2/3) finished.\n");
    printf("Step (3/3) save dataset to file.\n");
    FILE* fp;
    
    /* Open file for writing */
    if ((fp = fopen("dataset", "w")) == NULL) {
        printf("Cannot open file.\n");
        return;
    }

    /* write int array to the file*/
    for (int i = 0; i < loop_times; i++) {
        if (fwrite(dataset[i], sizeof(int), 16, fp) != 16) {
            printf("File read error.");
            return;
        }
    }

    fclose(fp);

    printf("Step (3/3) finished.\n");
    printf("\nProgram ends.\n");
}


// read file "dataset" as
// size of dataset should match parameter in this program, error otherwise.
void test_with_dataset() {
    int header_size = 508 + 8 * 5;

    // create byte array with header_size
    char* header = malloc(header_size);
    for (int i = 0; i < header_size; i++) {
        header[i] = '\0';
    }

    char* hashed_header = serialize_hash(sha3(1, header, 0, header_size), 8);

    // difficulty in genesis block
    // Credit: https://lightrains.com/blogs/setup-local-ethereum-blockchain-private-testnet
    int difficulty = 0x4000;

    int cache_size = CACHE_SIZE;
    int full_size = DATASET_SIZE;
    printf("Target: use existing dataset and mine it.\n");
    printf("Start mining...\n");
    uint64_t nonce = mine(full_size, NULL, header, 32, difficulty);
    printf("Finished.\n");
    printf("\nProgram ends.\n");
}

int main() {
#ifdef GEN_DATASET
    save_dataset();
    return 0;
#endif
#ifdef USE_DATASET
    test_with_dataset();
    return 0;
#endif
    test_whole_algortihm();
    return 0;
}