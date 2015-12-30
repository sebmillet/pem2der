/*
 * =====================================================================================
 *
 *       Filename:  ppem.h
 *
 *    Description:  Header file of ppem.c
 *
 *        Version:  1.0
 *        Created:  28/12/2015 13:53:10
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#include <stdlib.h>

enum {
	PEM_NO_PEM_INFORMATION,
	PEM_PARSE_ERROR,
	PEM_UNMANAGED_PROC_TYPE,
	PEM_MISSING_ENCRYPTION_INFORMATION,
	PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO,
	PEM_EMPTY_DATA,
	PEM_BAD_BASE64_CONTENT,
	PEM_ENCRYPTED_DATA,
	PEM_CLEAR_DATA,
	PEM_TERMINATED
};

struct pem_ctrl_t;
typedef struct pem_ctrl_t pem_ctrl_t;

const char *pem_errorstring(int e);

pem_ctrl_t *pem_construct_pem_ctrl(const unsigned char *data_in);
void pem_destruct_pem_ctrl(pem_ctrl_t *ctrl);
int pem_next(pem_ctrl_t *ctrl);
int pem_has_data(const pem_ctrl_t *ctrl);
int pem_has_encrypted_data(const pem_ctrl_t *ctrl);
int pem_had_nothing_at_all(const pem_ctrl_t *ctrl);

int pem_status(const pem_ctrl_t *ctrl);
const char *pem_header(const pem_ctrl_t *ctrl);
const char *pem_cipher(const pem_ctrl_t *ctrl);
const char *pem_salt(const pem_ctrl_t *ctrl);
const unsigned char *pem_bin(const pem_ctrl_t *ctrl);
size_t pem_bin_len(const pem_ctrl_t *ctrl);

