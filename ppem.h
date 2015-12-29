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
	PEM_ENCRYPTED_DATA,
	PEM_BLANK_DATA
};

typedef struct pem_ctrl_t {
	int remanent_index;
	unsigned char *remanent_data_in;
	int status;
	char *header;
	char *cipher;
	char *salt;
	unsigned char *b64_start;
	size_t b64_len;
//    unsigned char *data_next;
} pem_ctrl_t;

const char *pem_errorstring(int e);

pem_ctrl_t *pem_construct_pem_ctrl_t(unsigned char *data_in);
int pem_next(pem_ctrl_t *ctrl);

int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len);
int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len);

