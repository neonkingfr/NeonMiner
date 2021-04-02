/*********************************************************************
 * Maxeler Technologies : Hybrid Coin Miner                          *
 *                                                                   *
 * Version: 1.0                                                      *
 * Date:    13th March 2014                                          *
 *                                                                   *
 * CPU code source file                                              *
 *                                                                   *
 *********************************************************************/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <omp.h>

#include "../common/timer.h"
#include "../common/json_wrapper.h"
#include "../common/logging.h"
#include "../common/data_struct.h"
#include "../common/worker.h"

#include "../common/sha2.h"
#include "../common/dfe.h"

#include "Maxfiles.h"
#include "MaxSLiCInterface.h"

#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
const int SCRYPT_SCRATCHPAD_SIZE = 131072 + 63;

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12, 7); x09 ^= ROTL(x05 + x01, 7);
		x14 ^= ROTL(x10 + x06, 7); x03 ^= ROTL(x15 + x11, 7);

		x08 ^= ROTL(x04 + x00, 9); x13 ^= ROTL(x09 + x05, 9);
		x02 ^= ROTL(x14 + x10, 9); x07 ^= ROTL(x03 + x15, 9);

		x12 ^= ROTL(x08 + x04, 13); x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13); x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18); x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18); x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03, 7); x06 ^= ROTL(x05 + x04, 7);
		x11 ^= ROTL(x10 + x09, 7); x12 ^= ROTL(x15 + x14, 7);

		x02 ^= ROTL(x01 + x00, 9); x07 ^= ROTL(x06 + x05, 9);
		x08 ^= ROTL(x11 + x10, 9); x13 ^= ROTL(x12 + x15, 9);

		x03 ^= ROTL(x02 + x01, 13); x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13); x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18); x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18); x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}



static inline void HMAC_SHA256_80_init(const uint32_t *key, uint32_t *tstate, uint32_t *ostate){
  	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy(pad, key + 16, 16);
	memcpy(pad + 4, keypad, 48);
	sha256_transform(tstate, pad, 0);
	memcpy(ihash, tstate, 32);

	sha256_init(ostate);
	for (i = 0; i < 8; i++)
			pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
			pad[i] = 0x5c5c5c5c;
	sha256_transform(ostate, pad, 0);

	sha256_init(tstate);
	for (i = 0; i < 8; i++)
			pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
			pad[i] = 0x36363636;
	sha256_transform(tstate, pad, 0);

}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
        const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
        uint32_t istate[8], ostate2[8];
        uint32_t ibuf[16], obuf[16];
        int i, j;

        memcpy(istate, tstate, 32);
        sha256_transform(istate, salt, 0);

        memcpy(ibuf, salt + 16, 16);
        memcpy(ibuf + 5, innerpad, 44);
        memcpy(obuf + 8, outerpad, 32);

        for (i = 0; i < 4; i++) {
                memcpy(obuf, istate, 32);
                ibuf[4] = i + 1;
                sha256_transform(obuf, ibuf, 0);

                memcpy(ostate2, ostate, 32);
                sha256_transform(ostate2, obuf, 0);
                for (j = 0; j < 8; j++)
                        output[8 * i + j] = swab32(ostate2[j]);
        }
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
        const uint32_t *salt, uint32_t *output)
{
        uint32_t buf[16];
        int i;

        sha256_transform(tstate, salt, 1);
        sha256_transform(tstate, salt + 16, 1);
        sha256_transform(tstate, finalblk, 0);
        memcpy(buf, tstate, 32);
        memcpy(buf + 8, outerpad, 32);

        sha256_transform(ostate, buf, 0);
        for (i = 0; i < 8; i++)
                output[i] = swab32(ostate[i]);
}



static void SHA256_before(uint32_t *tstate, uint32_t *ostate, uint32_t *input, uint32_t* X){

	HMAC_SHA256_80_init(input, tstate, ostate);
	PBKDF2_SHA256_80_128(tstate, ostate, input, X);
}

static void SHA256_after(uint32_t *tstate, uint32_t *ostate, uint32_t *output, uint32_t* X){

	PBKDF2_SHA256_128_32(tstate, ostate, X, output);

}

/**
 * \brief   Callback function called when CURL receives a response
 * \param   ptr         The data received
 * \param   size        Size of an element in bytes
 * \param   nmemb       Number of element received
 * \param   userdata    User data specified when setting the callback
 */
static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
	LOG_DEBUG_ENTER();

	gbuf_t *gbuf = (gbuf_t *) userdata;
	size_t message_size = size * nmemb;

	int ret = gbuf_cat(gbuf, ptr, message_size);

	return ret == 0 ? message_size : 0;
}

/**
 * \brief   Fetch work from the Bitcoin server
 * \param   worker  Worker
 * \param   work    Work returned by the Bitcoin server
 */
void scrypt_send_getwork(scrypt_worker_t *worker, bc_work_t *work) {
	LOG_DEBUG_ENTER();

	int retry = 1;
	int tries = 0;

	char *json_request = create_json_getwork(worker->id);
	if (NULL == json_request) {
		LOG_FATAL("Could not create JSON request");
	}

	while (retry){
		retry = 0;

		CURLcode curl_ret;
		LOG_DEBUG("Getwork request: %s", json_request);

		fflush(stdout);
		curl_ret = curl_easy_setopt(worker->curl, CURLOPT_POSTFIELDS, json_request);
		if (CURLE_OK != curl_ret) {
			LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
		}

		gbuf_reset(&worker->gbuf);

		curl_ret = curl_easy_perform(worker->curl);
		if (CURLE_OK != curl_ret) {
			LOG_INFO("Error with getwork(Scrypt) : curl_easy_perform: %s", curl_easy_strerror(curl_ret));
			if(tries < 5){
				LOG_INFO("Retrying in 30s...");
				retry = 1;
				sleep(30);
			}
			else{
				free(json_request);
				LOG_FATAL("curl_easy_perform: %s, failed 5 retries.", curl_easy_strerror(curl_ret));
			}

		}
		else{

			if(parse_json_getwork_decode(worker->gbuf.data, work) != 0){
				if(tries < 5){
					LOG_INFO("Parsing JSON packet failed... trying again in 30s...");
					retry = 1;
					sleep(30);
				}
				else{
					free(json_request);
					LOG_FATAL("Failed to parse JSON packet after 5 tries.");
				}
			}



		}

		tries++;
	}

	free(json_request);
	if (work->id != worker->id) {
		LOG_FATAL("Request ID mismatch");
	}
}

/**
 * \brief   Send completed work to Bitcoin
 * \param   worker      Worker
 * \param   work        Work returned from previous 'getwork' command
 * \param   nonce       Nonce that satisfies target
 * \param   work_comp   Bitcoin response
 */
static void send_getwork_completion(scrypt_worker_t *worker, const bc_work_t *work, uint32_t nonce, bc_work_comp_t *work_comp) {
	LOG_DEBUG_ENTER();

	char *json_request = create_json_getwork_completion_encode(work, nonce);
	if (NULL == json_request) {
		LOG_FATAL("Could not create JSON request");
	}

	CURLcode curl_ret;
	curl_ret = curl_easy_setopt(worker->curl, CURLOPT_POSTFIELDS, json_request);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
	}

	gbuf_reset(&worker->gbuf);

	curl_ret = curl_easy_perform(worker->curl);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_perform: %s", curl_easy_strerror(curl_ret));
	}

	free(json_request);

	parse_json_getwork_completion(worker->gbuf.data, work_comp);

	if (work_comp->id != worker->id) {
		LOG_FATAL("Request ID mismatch");
	}
}

/**
 * \brief   Initialise a worker
 * \param   worker      Worker
 * \param   net_config  Network configuration
 */
static void worker_init(scrypt_worker_t *worker, const net_config_t *net_config) {
	LOG_DEBUG_ENTER();

	worker->id = 1;

	worker->curl = curl_easy_init();
	if (NULL == worker->curl) {
		LOG_FATAL("Could not init Curl");
	}

	if (gbuf_init(&worker->gbuf, 1024)) {
		LOG_FATAL("Could not create worker buffer");
	}

	CURLcode curl_ret;
	curl_ret = curl_easy_setopt(worker->curl, CURLOPT_WRITEFUNCTION, write_cb);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
	}

	curl_ret = curl_easy_setopt(worker->curl, CURLOPT_WRITEDATA, &worker->gbuf);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
	}

	curl_ret = curl_easy_setopt(worker->curl, CURLOPT_URL, net_config->url);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
	}

	curl_ret = curl_easy_setopt(worker->curl, CURLOPT_USERPWD, net_config->usr_pwd);
	if (CURLE_OK != curl_ret) {
		LOG_FATAL("curl_easy_setopt: %s", curl_easy_strerror(curl_ret));
	}

	worker->state.stats.matches = 0;
	worker->state.stats.none = 0;
	worker->state.stats.nhash = 0;
}


/**
 * \brief   Prepare the data and run the Scrypt kernel.
 * \param   work  data received from getwork.
 * \return	boolean - if nonce has been found.
 */
void scrypt_prepare_run(scrypt_worker_t *worker, bc_work_t work){
	uint32_t word_per_scrypt = 20;
	uint32_t start_nonce = 0;
	//get starting nonce from the data. (last 4 bytes in data)
	uint32_t* data_32bit = (uint32_t*) work.result.data;

	uint32_t nscrypt = dfe_get_num_scrypt(worker->dfe);


	uint32_t midstate[8];

	sha256_init(midstate);
	sha256_transform(midstate, data_32bit, 0);

	uint32_t *input = calloc(nscrypt, word_per_scrypt*sizeof(uint32_t));

	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_scrypt;
		memcpy(input + index, data_32bit, sizeof(uint32_t)*word_per_scrypt);
	}

	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_scrypt;
		input[index+word_per_scrypt-1] = start_nonce + i;
	}

	uint32_t* X = worker->dfe_buffer;
	uint32_t* tstates = worker->tstate_buffer;
	uint32_t* ostates = worker->ostate_buffer;

#pragma omp parallel for
	for (int64_t i = 0; i < (int64_t)nscrypt; i++) {
		memcpy(&tstates[i*8], midstate, 32);
		SHA256_before(&tstates[i*8], &ostates[i*8], &input[20*i], &X[i*32]);
	}

	free(input);
}

void scrypt_process_result_and_send_work(scrypt_worker_t *worker, bc_work_t work){
	uint32_t word_per_hash = 8;
	uint32_t* X = worker->dfe_buffer;
	uint32_t* tstates = worker->tstate_buffer;
	uint32_t* ostates = worker->ostate_buffer;
	uint32_t nscrypt = dfe_get_num_scrypt(worker->dfe);
	uint32_t start_nonce = 0;

	uint32_t *output = calloc(nscrypt, word_per_hash*sizeof(uint32_t));


	uint32_t *target = (uint32_t*) work.result.target;

//	worker->state.stats.nhash = nscrypt;

#pragma omp parallel for
	for (int64_t i = 0; i < (int64_t)nscrypt; i++) {
		SHA256_after(&tstates[i*8], &ostates[i*8], &output[i*8], &X[i*32]);
	}

	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_hash;
		uint32_t *hash = &output[index];
		int smaller = 1;
		for(int ihash = word_per_hash-1; ihash >= 0; ihash--){
			if(hash[ihash] != target[ihash]){
				smaller = hash[ihash] < target[ihash];
				break;
			}
		}

		if(smaller){
			bc_work_comp_t work_comp;
			memset(&work_comp, 0, sizeof(bc_work_comp_t));
			uint32_t result_nonce = start_nonce+i;
			send_getwork_completion(worker, &work, result_nonce, &work_comp);
			if(!work_comp.result){
				//result rejected
				worker->state.stats.reject ++;
				break;
			}
			else{
				worker->state.stats.matches ++;
			}

		}
	}

	if(0 == worker->state.stats.reject + worker->state.stats.matches){
		worker->state.stats.none ++;
	}
	free(output);
}

void dfescrypt_cpu(uint32_t n, uint32_t *input, uint32_t *output, uint32_t *midstate) {
	uint32_t* X = (uint32_t*) malloc(sizeof(uint32_t)*32*n);
	uint32_t* tstates = (uint32_t*) malloc(sizeof(uint32_t)*8*n);
	uint32_t* ostates = (uint32_t*) malloc(sizeof(uint32_t)*8*n);
	uint32_t *V;
	uint32_t i, j, k;
	uint32_t iterations = HybridcoinMiner_Scrypt_Iterations;
	char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
	if(NULL == X || NULL == tstates || NULL == ostates){
		LOG_FATAL("unable to allocate buffer for Scrypt input!\n");
	}

#pragma omp parallel for
	for (int64_t i = 0; i < (int64_t)n; i++) {
		memcpy(&tstates[i*8], midstate, 32);
		SHA256_before(&tstates[i*8], &ostates[i*8], &input[20*i], &X[i*32]);
	}

	//SCRYPT CORE
	for (int64_t p = 0; p < (int64_t)n; p++) {
		uint32_t *Y = &X[p*32];
		for (i = 0; i < iterations; i++) {
			memcpy(&V[i * 32], Y, 128);
			xor_salsa8(&Y[0], &Y[16]);
			xor_salsa8(&Y[16], &Y[0]);
		}

		for (i = 0; i < iterations; i++) {
			j = 32 * (Y[16] & (iterations-1));

			for (k = 0; k < 32; k++)
				Y[k] ^= V[j + k];
			xor_salsa8(&Y[0], &Y[16]);
			xor_salsa8(&Y[16], &Y[0]);
		}
	}

#pragma omp parallel for
	for (int64_t i = 0; i < (int64_t)n; i++) {
		SHA256_after(&tstates[i*8], &ostates[i*8], &output[i*8], &X[i*32]);
	}

	free(X);
	free(tstates);
	free(ostates);
}

uint32_t* run_cpu_new(bc_work_t work, uint64_t nscrypt){
	uint32_t word_per_scrypt = 20;
	uint32_t word_per_hash = 8;
	//get starting nonce from the data. (last 4 bytes in data)

	uint32_t* data_32bit = (uint32_t*) work.result.data;

	uint32_t start_nonce = data_32bit[word_per_scrypt-1];

	uint32_t midstate[8];

	sha256_init(midstate);
	sha256_transform(midstate, data_32bit, 0);


	//Initialise input and outputs - 80 bytes per scrypt for inputs, 32bytes outputs
	uint32_t *input = calloc(nscrypt, word_per_scrypt*sizeof(uint32_t));
	uint32_t *output = calloc(nscrypt, word_per_hash*sizeof(uint32_t));

	if(NULL == input || NULL == output){
		LOG_FATAL("Cannot allocate memory for input/output buffers.\n");
	}

	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_scrypt;
		memcpy(input + index, data_32bit, sizeof(uint32_t)*word_per_scrypt);
	}

	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_scrypt;
		input[index+word_per_scrypt-1] = start_nonce + i;
	}

	dfescrypt_cpu(nscrypt, input, output, midstate);


	free(input);
	return output;

}

void scrypt_process_test_result(scrypt_worker_t *worker, bc_work_t work){
	uint32_t word_per_hash = 8;
	uint32_t* X = worker->dfe_buffer;
	uint32_t* tstates = worker->tstate_buffer;
	uint32_t* ostates = worker->ostate_buffer;
	uint32_t nscrypt = dfe_get_num_scrypt(worker->dfe);
	uint32_t *output = calloc(nscrypt, word_per_hash*sizeof(uint32_t));

	for (int64_t i = 0; i < (int64_t)nscrypt; i++) {
		SHA256_after(&tstates[i*8], &ostates[i*8], &output[i*8], &X[i*32]);
	}

	//Run CPU version
	uint32_t *cpu_out = run_cpu_new(work, nscrypt);
	for(uint32_t i = 0; i < nscrypt; i++){
		uint64_t index = i*word_per_hash;
		uint32_t *hash = &output[index];
		uint32_t *cpu_hash = &cpu_out[index];
		for(int ihash = word_per_hash-1; ihash >= 0; ihash--){
			if(hash[ihash] != cpu_hash[ihash]){
				LOG_INFO("Mismatch! -> index %d,hash[%d]  \tdfe :%x, \tcpu :%x\n", i, ihash, hash[ihash], cpu_hash[ihash]);
			}
		}

	}

}

void scrypt_generate_test_work(bc_work_t *work){
	work->id = 1;
	static const uint8_t midstate[32] = { 0x33, 0x9A, 0x90, 0xBC, 0xF0, 0xBF,
			0x58, 0x63, 0x7D, 0xAC, 0xCC, 0x90, 0xA8, 0xCA, 0x59, 0x1E, 0xE9,
			0xD8, 0xC8, 0xC3, 0xC8, 0x03, 0x01, 0x4F, 0x36, 0x87, 0xB1, 0x96,
			0x1B, 0xF9, 0x19, 0x47 };
	static const uint8_t target[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			0x00, 0x00, 0x00, 0x00 };
	static const uint32_t data[20] = { 0x1000000,0xb68536db,0x6c8c0888,0x9df6b121,0x5b01a561,0x30c81528,0x98efaebb,0xf40326ad,0xbba5e7bb,0xe9c3401,0xc32d98ad,0x733db88e,0xae8efaa2,0x94aaad2b,0x52656b54,0x602cfb37,0x53a6030f,0xdcdafb51,0x3df5011c,0 };
	memcpy(work->result.midstate, midstate, 32);
	memcpy(work->result.target, target, 32);
	memcpy(work->result.data , data, 20*4);
}

void scrypt_init_test(scrypt_worker_t *worker, dfe_context *dfe, uint32_t *dfe_buffer){
	memset(worker, 0, sizeof(*worker));

	worker->state.stats.matches = 0;
	worker->state.stats.none = 0;
	worker->state.stats.nhash = 0;

	worker->dfe = dfe;

	worker->dfe_buffer = dfe_buffer;

	uint32_t nscrypt = dfe_get_num_scrypt(dfe);
	worker->ostate_buffer = malloc(sizeof(uint32_t)* 8 * nscrypt);
	worker->tstate_buffer = malloc(sizeof(uint32_t)* 8 * nscrypt);

}



void scrypt_init(scrypt_worker_t *worker, net_config_t *netconf, dfe_context *dfe, uint32_t *dfe_buffer){
	memset(worker, 0, sizeof(*worker));

	worker_init(worker, netconf);

	worker->dfe = dfe;
	worker->dfe_buffer = dfe_buffer;
	uint32_t nscrypt = dfe_get_num_scrypt(dfe);
	worker->ostate_buffer = malloc(sizeof(uint32_t)* 8 * nscrypt);
	worker->tstate_buffer = malloc(sizeof(uint32_t)* 8 * nscrypt);

}


