/*
 * =====================================================================================
 *
 *       Filename:  ppem.c
 *
 *    Description:  Parse a PEM file
 *
 *        Version:  1.0
 *        Created:  28/12/2015 13:52:33
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#include "ppem.h"

#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define UNUSED(x) (void)(x)

	/*
	 * Needed by FATAL_ERROR macro
	 * */

#define FATAL_ERROR(...) \
{ \
	fprintf(stderr, "File %s line %d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
	exit(1); \
}

unsigned char *strleftis(unsigned char *buf, const char *left)
{
	while (*left != '\0' && toupper(*left) == toupper(*buf)) {
		++buf;
		++left;
	}
	if (*left == '\0')
		return buf;
	return NULL;
}

unsigned char *strrightis(unsigned char *buf, unsigned char **buf_nextline, const char *right)
{
	unsigned char *p = buf;
	while (*p != '\0' && *p != '\n' && (*p != '\r' || p[1] != '\n'))
		++p;
	if (*p == '\0')
		*buf_nextline = NULL;
	else if (p[0] == '\r' && p[1] == '\n')
		*buf_nextline = p + 2;
	else if (p[0] == '\n')
		*buf_nextline = p + 1;

	if (p > buf)
		--p;

	int l = strlen(right);
	if (l <= 0)
		return p + 1;
	const char *r = right + l - 1;
	while (r >= right && p >= buf && toupper(*p) == toupper(*r)) {
		--p;
		--r;
	}
	if (r < right)
		return p + 1;
	return NULL;
}

int pem_next(unsigned char *b, unsigned char **bstart, size_t *blen, char **pem_header,
			char **cipher, char **salt, unsigned char **bnext, int *status)
{
	*pem_header = NULL;
	*bstart = NULL;
	*blen = 0;
	*cipher = NULL;
	*salt = NULL;

	unsigned char *nextline;
	do {
		unsigned char *header = strleftis(b, "-----begin ");
		unsigned char *fin = strrightis(b, &nextline, "-----");
		b = nextline;
		if (header != NULL && fin != NULL && header < fin) {
			*fin = '\0';
			*pem_header = (char *)header;
			break;
		}
	} while (nextline != NULL);
	if (nextline == NULL) {
		*status = (*pem_header != NULL ? PEM_COULD_NOT_PARSE : PEM_NO_PEM_INFORMATION);
		return 0;
	}

	int has_proc_type_header = 0;
	int has_proc_type_header_set_for_encryption = 0;
	unsigned char *header = strleftis(b, "proc-type:");
	if (header != NULL) {
		has_proc_type_header = 1;
		while (isblank(*header))
			++header;
		if (*header == '4') {
			++header;
			while (isblank(*header))
				++header;
			if (*header == ',') {
				++header;
				while (isblank(*header))
					++header;
				unsigned char *fin = strrightis(header, &nextline, "encrypted");
				b = nextline;
				if (header == fin && nextline != NULL) {
					has_proc_type_header_set_for_encryption = 1;
					unsigned char *h2;
					if ((h2 = strleftis(b, "dek-info:")) != NULL) {
						while (isblank(*h2))
							++h2;
						*cipher = (char *)h2;
						while (*h2 != '\0' && *h2 != ',' && !isblank(*h2))
							++h2;
						unsigned char *cipher_set0 = h2;
						unsigned char *salt_set0 = NULL;
						while (isblank(*h2))
							++h2;
						int with_salt = (*h2 == ',');
						if (*h2 != '\0') {
							if (with_salt) {
								++h2;
								while (isblank(*h2))
									++h2;
								*salt = (char *)h2;
								while (isxdigit(*h2))
									++h2;
								salt_set0 = h2;
								while (isblank(*h2))
									++h2;
							}
							if (*h2 == '\n' && h2[1] == '\n') {
								h2 += 2;
							} else if (*h2 == '\r' && h2[1] == '\n' && h2[2] == '\r' && h2[3] == '\n') {
								h2 += 4;
							} else {
								*salt = NULL;
								salt_set0 = NULL;
							}
							if (cipher_set0 != NULL) {
								*cipher_set0 = '\0';
								if (salt_set0 != NULL)
									*salt_set0 = '\0';
								*bstart = h2;
							}
						}
					}
				}
			}
		}
	} else {
		*bstart = b;
	}

	if (has_proc_type_header && !has_proc_type_header_set_for_encryption && *bstart == NULL) {
		*cipher = NULL;
		*salt = NULL;
		while (*header != '\0') {
			if (*header == '\n' && header[1] == '\n') {
				*bstart = header + 2;
				break;
			} else if (*header == '\r' && header[1] == '\n' && header[2] == '\r' && header[3] == '\n') {
				*bstart = header + 4;
				break;
			}
			++header;
		}
	}

	unsigned char *bend = (*bstart == NULL ? b : *bstart);

	unsigned char *h3;
	do {
		h3 = strleftis(bend, "-----end ");
		unsigned char *fin = strrightis(bend, &nextline, "-----");
		if (h3 != NULL && fin != NULL && h3 < fin) {
			*fin = '\0';
			break;
		}
		bend = nextline;
	} while (nextline != NULL);
	if (h3 == NULL) {
		*status = PEM_COULD_NOT_PARSE;
		return 0;
	}

	*bnext = nextline;
	if (*bstart != NULL) {
			/*
			 * Not a typo.
			 * Normally blen is 'arrival - beginning + 1' but here,
			 * arrival is 'bend - 1' so -1 + 1 => no '+ 1' term.
			 * */
		*blen = bend - *bstart;
		*status = (*cipher != NULL ? PEM_ENCRYPTED_DATA : PEM_BLANK_DATA);
	} else {
		*status = PEM_COULD_NOT_PARSE;
	}
	return 1;
}

int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len)
{
UNUSED(b64msg);

		/* Very loose approximation (we ignore newlines and padding) */
	return (b64msg_len * 3 + 3) / 4 + 1;
}

int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len)
{
	BIO *bio;
	BIO *b64;

	size_t allocated_len = *binbuf_len;
	if (*binbuf == NULL) {
		allocated_len = pem_base64_estimate_decoded_data_len(b64msg, b64msg_len);
		*binbuf = (unsigned char*)malloc(allocated_len);
	}

	bio = BIO_new_mem_buf((void *)b64msg, b64msg_len);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	*binbuf_len = BIO_read(bio, *binbuf, b64msg_len);

	if (*binbuf_len > allocated_len)
		FATAL_ERROR("Estimation of BASE64 decoded size was incorrect!");

	BIO_free_all(bio);
	if (*binbuf_len <= 0)
		return 0;
	return 1;
}
