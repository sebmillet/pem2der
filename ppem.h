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

enum {PEM_COULD_NOT_PARSE, PEM_NO_PEM_INFORMATION, PEM_ENCRYPTED_DATA, PEM_BLANK_DATA};

unsigned char *strleftis(unsigned char *buf, const char *left);
unsigned char *strrightis(unsigned char *buf, unsigned char **buf_nextline, const char *right);

int pem_next(unsigned char *b, unsigned char **bstart, size_t *blen, char **pem_header,
			char **cipher, char **salt, unsigned char **bnext, int *status);

int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len);
int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len);

