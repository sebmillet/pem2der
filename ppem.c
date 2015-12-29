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

/*#define DEBUG*/

#include "ppem.h"

#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define UNUSED(x) (void)(x)

#ifdef DEBUG
#define DBG(...) \
{\
	fprintf(stderr, "%s[%d]\t", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
}
#else
#define DBG(...)
#endif

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

static const char *errorstrings[] = {
	"no PEM information",					/* PEM_NO_PEM_INFORMATION */
	"PEM parsing error",					/* PEM_PARSE_ERROR */
	"unmanaged PEM format",					/* PEM_UNMANAGED_PROC_TYPE */
	"missing encryption information"	,	/* PEM_MISSING_ENCRYPTION_INFORMATION */
	"non standard encryption information",	/* PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO */
	"empty data",							/* PEM_EMPTY_DATA */
	"encrypted data",						/* PEM_ENCRYPTED_DATA */
	"blank data"							/* PEM_BLANK_DATA */
};

static unsigned char *strleftis(unsigned char *buf, const char *left)
{
	while (*left != '\0' && toupper(*left) == toupper(*buf)) {
		++buf;
		++left;
	}
	if (*left == '\0')
		return buf;
	return NULL;
}

static unsigned char *strrightis(unsigned char *buf, unsigned char **buf_nextline, const char *right)
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

const char *pem_errorstring(int e)
{
	if ((size_t)e >= sizeof(errorstrings) / sizeof(*errorstrings))
		return NULL;
	else
		return errorstrings[e];
}

pem_ctrl_t *pem_construct_pem_ctrl_t(unsigned char *data_in)
{
	pem_ctrl_t *ctrl = malloc(sizeof(pem_ctrl_t));
	ctrl->remanent_index = 0;
	ctrl->remanent_data_in = data_in;
	return ctrl;
}

int pem_next(pem_ctrl_t *ctrl)
{

	DBG("pem_next(): start")

	DBG("Index = %d", ctrl->remanent_index);

	unsigned char *b = ctrl->remanent_data_in;

	ctrl->status = -1;
	ctrl->header = NULL;
	ctrl->cipher = NULL;
	ctrl->salt = NULL;
	ctrl->b64_start = NULL;
	ctrl->b64_len = 0;

	unsigned char *cipher_set0 = NULL;
	unsigned char *salt_set0 = NULL;

	unsigned char *nextline;
	do {
		unsigned char *header = strleftis(b, "-----begin ");
		unsigned char *fin = strrightis(b, &nextline, "-----");
		b = nextline;
		if (header != NULL && fin != NULL && header < fin) {
			*fin = '\0';
			ctrl->header = (char *)header;

			DBG("Found header opening '%s'", ctrl->header)

			break;
		}
	} while (nextline != NULL);

	if (nextline == NULL) {
		if (ctrl->header == NULL) {
			DBG("Status set to PEM_NO_PEM_INFORMATION")
			ctrl->status = PEM_NO_PEM_INFORMATION;
		} else {
			DBG("Status set to PEM_PARSE_ERROR")
			ctrl->status = PEM_PARSE_ERROR;
		}
		DBG("pem_next(): returning 0")
		return 0;
	}

	unsigned char *header = strleftis(b, "proc-type:");
	int has_proc_type = 0;
	int proc_type_is_set_for_encryption = 0;

	if (header == NULL) {
		DBG("No Proc-Type in the line next to header: assuming blank data")
	} else {
		DBG("Found Proc-Type in the line next to header")
		has_proc_type = 1;
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
				if (header == fin && nextline != NULL) {
					proc_type_is_set_for_encryption = 1;

					DBG("Proc-Type content is set for encryption ('4,ENCRYPTED')")

					b = nextline;
					unsigned char *h2;
					if ((h2 = strleftis(b, "dek-info:")) != NULL) {

						DBG("Found Dek-Info")

						while (isblank(*h2))
							++h2;
						ctrl->cipher = (char *)h2;
						while (*h2 != '\0' && *h2 != ',' && !isblank(*h2) && *h2 != '\r' && *h2 != '\n')
							++h2;
						cipher_set0 = h2;
						while (isblank(*h2))
							++h2;
						if (*h2 == ',') {
							++h2;
							while (isblank(*h2))
								++h2;
							ctrl->salt = (char *)h2;
							while (*h2 != '\0' && *h2 != '\r' && *h2 != '\n')
								++h2;
							--h2;
							while (isblank(*h2) && (char *)h2 >= ctrl->salt)
								--h2;
							salt_set0 = h2 + 1;

							DBG("Found salt")

						}
					}
				}
			}
		}
	}

/*    DBG("A- b: [%c] %d, [%c] %d, [%c] %d, [%c] %d, [%c] %d", b[0], b[0], b[1], b[1], b[2], b[2], b[3], b[3], b[4], b[4])*/

	int got_empty_line_after_dek_info = 0;
	if (has_proc_type && ctrl->cipher != NULL) {
		strrightis(b, &nextline, "");
		if (nextline != NULL) {
			b = nextline;
			if (b[0] == '\n') {
				got_empty_line_after_dek_info = 1;
				DBG("Empty line (as expected) after Dek-Info")
				b += 1;
			} else if (b[0] == '\r' && b[1] == '\n') {
				got_empty_line_after_dek_info = 1;
				DBG("Empty line (as expected) after Dek-Info (CR-LF format)")
				b += 2;
			} else {
				DBG("Missing empty line after Dek-Info")
			}
		}
	}

	if (ctrl->cipher != NULL) {
		*cipher_set0 = '\0';
		if (!strlen(ctrl->cipher))
			ctrl->cipher = NULL;
		if (ctrl->salt != NULL) {
			*salt_set0 = '\0';
			if (!strlen(ctrl->salt))
				ctrl->salt = NULL;
		}
	}

	while (*b == '\n' || (*b == '\r' && b[1] == '\n'))
		b += (*b == '\n' ? 1 : 2);
	ctrl->b64_start = b;

	int got_closed = 0;
	do {
		unsigned char *h = strleftis(b, "-----end ");
		unsigned char *fin = strrightis(b, &nextline, "-----");
		if (h != NULL && fin != NULL && h < fin) {
			*fin = '\0';
			got_closed = 1;
			DBG("Found header closure '%s'", h)
			break;
		}
		b = nextline;
	} while (nextline != NULL);
	ctrl->remanent_data_in = nextline;

	int retval = got_closed;

	if (got_closed) {
		ctrl->remanent_index++;
		DBG("Increasing index. New value = %d", ctrl->remanent_index);

			/*
			 * Not a typo.
			 * Normally blen is 'arrival - beginning + 1' but here,
			 * arrival is 'b - 1' so -1 + 1 => no '+ 1' term.
			 * */
		ctrl->b64_len = b - ctrl->b64_start;
		if (has_proc_type && ctrl->cipher == NULL) {

			if (proc_type_is_set_for_encryption) {
				DBG("Status set to PEM_MISSING_ENCRYPTION_INFORMATION")
				ctrl->status = PEM_MISSING_ENCRYPTION_INFORMATION;
			} else {
				DBG("Status set to PEM_UNMANAGED_PROC_TYPE")
				ctrl->status = PEM_UNMANAGED_PROC_TYPE;
			}
		} else if (ctrl->cipher == NULL) {
			if (ctrl->b64_len == 0) {
				DBG("Status set to PEM_EMPTY_DATA")
				ctrl->status = PEM_EMPTY_DATA;
			} else {
				DBG("Status set to PEM_BLANK_DATA")
				ctrl->status = PEM_BLANK_DATA;
			}
		} else {
			if (ctrl->b64_len == 0) {
				DBG("Status set to PEM_EMPTY_DATA")
				ctrl->status = PEM_EMPTY_DATA;
			} else if (got_empty_line_after_dek_info) {
				DBG("Status set to PEM_ENCRYPTED_DATA")
				ctrl->status = PEM_ENCRYPTED_DATA;
			} else {
				DBG("Status set to PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO")
				ctrl->status = PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO;
			}
		}
	} else {
		DBG("Status set to PEM_PARSE_ERROR")
		ctrl->status = PEM_PARSE_ERROR;
	}

	DBG("ctrl->b64_start = %lu, ctrl->b64_len = %lu, ctrl->remanent_data_in = %lu",
			(long unsigned int)ctrl->b64_start, (long unsigned int)ctrl->b64_len, (long unsigned int)ctrl->remanent_data_in)

	DBG("pem_next(): returning %d", retval)

	return retval;
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
