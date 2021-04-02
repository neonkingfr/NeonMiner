/*********************************************************************
 * Maxeler Technologies : Hybrid Coin Miner                          *
 *                                                                   *
 * Version: 1.0                                                      *
 * Date:    13th March 2014                                          *
 *                                                                   *
 * CPU code source file                                              *
 *                                                                   *
 *********************************************************************/

#ifndef SCRYPT_H_
#define SCRYPT_H_
#include "../common/worker.h"

int scrypt_classic(int argc, char **argv);
void scrypt_init(scrypt_worker_t *worker, net_config_t *netconf, dfe_context *dfe, uint32_t *dfe_buffer);
void scrypt_send_getwork(scrypt_worker_t *worker, bc_work_t *work);
void scrypt_prepare_run(scrypt_worker_t *worker, bc_work_t work);
void scrypt_process_result_and_send_work(scrypt_worker_t *worker, bc_work_t work);
void scrypt_init_test(scrypt_worker_t *worker, dfe_context *dfe, uint32_t *dfe_buffer);
void scrypt_generate_test_work(bc_work_t *scrypt_work);
void scrypt_process_test_result(scrypt_worker_t *worker, bc_work_t work);

#endif /* SCRYPT_H_ */
