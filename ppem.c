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

static void reset_round(pem_ctrl_t *ctrl);
static int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len);
static int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len);

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
	"no PEM information",                  /* PEM_NO_PEM_INFORMATION */
	"PEM parsing error",                   /* PEM_PARSE_ERROR */
	"unmanaged PEM format",                /* PEM_UNMANAGED_PROC_TYPE */
	"missing encryption information"    ,  /* PEM_MISSING_ENCRYPTION_INFORMATION */
	"non standard encryption information", /* PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO */
	"empty data",                          /* PEM_EMPTY_DATA */
	"bad base64 content",                  /* PEM_BAD_BASE64_CONTENT */
	"encrypted data",                      /* PEM_ENCRYPTED_DATA */
	"clear data"                           /* PEM_CLEAR_DATA */
};

struct pem_ctrl_t {
	int remanent_index;
	const unsigned char *remanent_data_current;
	int status;
	char *alloc_header;
	char *alloc_cipher;
	char *alloc_salt;
	unsigned char *alloc_bin;
	size_t bin_len;
};

static const unsigned char *str_leftis(const unsigned char *buf, const char *left)
{
	while (*left != '\0' && toupper(*left) == toupper(*buf)) {
		++buf;
		++left;
	}
	if (*left == '\0')
		return buf;
	return NULL;
}

static const unsigned char *str_rightis(const unsigned char *buf, const unsigned char **buf_nextline, const char *right)
{
	const unsigned char *p = buf;
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

pem_ctrl_t *pem_construct_pem_ctrl(const unsigned char *data_in)
{
	pem_ctrl_t *ctrl = malloc(sizeof(pem_ctrl_t));
	ctrl->remanent_index = 0;
	ctrl->remanent_data_current = data_in;

	ctrl->alloc_header = NULL;
	ctrl->alloc_cipher = NULL;
	ctrl->alloc_salt = NULL;
	ctrl->alloc_bin = NULL;

	DBG("pem_construct_pem_ctrl(): constructed one pem_ctrl_t*: %lu", (long unsigned int)ctrl)
	return ctrl;
}

void pem_destruct_pem_ctrl(pem_ctrl_t *ctrl)
{
	reset_round(ctrl);
	free(ctrl);
	DBG("pem_destruct_pem_ctrl(): destructed one pem_ctrl_t*: %lu", (long unsigned int)ctrl)
}

static void reset_round(pem_ctrl_t *ctrl)
{
	if (ctrl->alloc_header != NULL) {
		free(ctrl->alloc_header);
		ctrl->alloc_header = NULL;
	}
	if (ctrl->alloc_cipher != NULL) {
		free(ctrl->alloc_cipher);
		ctrl->alloc_cipher = NULL;
	}
	if (ctrl->alloc_salt != NULL) {
		free(ctrl->alloc_salt);
		ctrl->alloc_salt = NULL;
	}
	if (ctrl->alloc_bin != NULL) {
		free(ctrl->alloc_bin);
		ctrl->alloc_bin = NULL;
	}
	ctrl->bin_len = 0;

	ctrl->status = -1;
}

int pem_status(const pem_ctrl_t *ctrl)                { return ctrl->status; }
const char *pem_header(const pem_ctrl_t *ctrl)        { return ctrl->alloc_header; }
const char *pem_cipher(const pem_ctrl_t *ctrl)        { return ctrl->alloc_cipher; }
const char *pem_salt(const pem_ctrl_t *ctrl)          { return ctrl->alloc_salt; }
const unsigned char *pem_bin(const pem_ctrl_t *ctrl)  { return ctrl->alloc_bin; }
size_t pem_bin_len(const pem_ctrl_t *ctrl)            { return ctrl->bin_len; }

	/*
	 * Copy a string.
	 * The target of the copy (return value) is allocated (malloc) and later
	 * it will have to be freed by the caller.
	 *
	 * The source string is *NOT* represented by a unique char *.
	 * It is represented by a pointer to the first character (begin) and a
	 * pointer next to the last character (end). Thus it allows to copy a
	 * source string that *DOES NOT HAVE* a terminating null character.
	 *
	 * On the other hand, the target string returned by this function is
	 * regular, it *DOES HAVE* a terminating null character.
	 *
	 * The case begin == end corresponds to an empty string.
	 * if end is not >= begin, then consider source being an empty string.
	 *
	 * */
static char *s_alloc_and_copy(const unsigned char *begin, const unsigned char *end)
{
	if (begin == NULL || end == NULL)
		FATAL_ERROR("begin or end is NULL!");

	ssize_t len;
	if (begin <= end)
		len = end - begin;
	else
		len = 0;
	unsigned char *s0 = (unsigned char *)malloc(len + 1);
	unsigned char *s = s0;
	while (begin < end) {
		*(s++) = *(begin++);
	}
	if (s - s0 != len)
		FATAL_ERROR("Man, what is going on here?");
	*s = '\0';

	return (char *)s0;
}

int pem_next(pem_ctrl_t *ctrl)
{
	DBG("pem_next(): start")
	DBG("Index = %d", ctrl->remanent_index)

	reset_round(ctrl);

	if (ctrl->remanent_data_current == NULL) {
		ctrl->status = PEM_TERMINATED;
		DBG("Status set to PEM_TERMINATED")
		DBG("pem_next(): returning 0")
		return 0;
	}

/*
 * * ****** *
 * * PART I *
 * * ****** *
 *
 *   Parse PEM text to identify BASE64 inner content
 *
 * */


	DBG("pem_next() part 1: parse PEM tags to find inner BASE64-encoded content")
	const unsigned char *b = ctrl->remanent_data_current;
	const unsigned char *nextline;
	do {
		const unsigned char *header = str_leftis(b, "-----begin ");
		const unsigned char *fin = str_rightis(b, &nextline, "-----");
		b = nextline;
		if (header != NULL && fin != NULL && header < fin) {
			ctrl->alloc_header = s_alloc_and_copy(header, fin);

			DBG("Found header opening '%s'", ctrl->alloc_header)

			break;
		}
	} while (nextline != NULL);

	if (nextline == NULL) {
		if (ctrl->alloc_header == NULL) {
			ctrl->alloc_header = malloc(1);
			ctrl->alloc_header[0] = '\0';
			DBG("Status set to PEM_NO_PEM_INFORMATION")
			ctrl->status = PEM_NO_PEM_INFORMATION;
		} else {
			DBG("Status set to PEM_PARSE_ERROR")
			ctrl->status = PEM_PARSE_ERROR;
		}
		ctrl->remanent_data_current = NULL;
		DBG("pem_next(): returning 1")
		return 1;
	}

	const unsigned char *header = str_leftis(b, "proc-type:");
	int has_proc_type = 0;
	int proc_type_is_set_for_encryption = 0;

	const unsigned char *cipher_begin = NULL;
	const unsigned char *cipher_end = NULL;
	const unsigned char *salt_begin = NULL;
	const unsigned char *salt_end = NULL;

	if (header == NULL) {
		DBG("No Proc-Type in the line next to header: assuming clear data")
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
				const unsigned char *fin = str_rightis(header, &nextline, "encrypted");
				if (header == fin && nextline != NULL) {
					proc_type_is_set_for_encryption = 1;

					DBG("Proc-Type content is set for encryption ('4,ENCRYPTED')")

					b = nextline;
					const unsigned char *h2;
					if ((h2 = str_leftis(b, "dek-info:")) != NULL) {

						DBG("Found Dek-Info")

						while (isblank(*h2))
							++h2;
						cipher_begin = h2;
						while (*h2 != '\0' && *h2 != ',' && !isblank(*h2) && *h2 != '\r' && *h2 != '\n')
							++h2;
						cipher_end = h2;
						while (isblank(*h2))
							++h2;
						if (*h2 == ',') {
							++h2;
							while (isblank(*h2))
								++h2;
							salt_begin = h2;
							while (*h2 != '\0' && *h2 != '\r' && *h2 != '\n')
								++h2;
							--h2;
							while (isblank(*h2) && h2 >= salt_begin)
								--h2;
							salt_end = h2 + 1;

							DBG("Found salt")

						}
					}
				}
			}
		}
	}

/*    DBG("A- b: [%c] %d, [%c] %d, [%c] %d, [%c] %d, [%c] %d", b[0], b[0], b[1], b[1], b[2], b[2], b[3], b[3], b[4], b[4])*/

	int got_empty_line_after_dek_info = 0;
	if (has_proc_type && cipher_begin != NULL) {
		str_rightis(b, &nextline, "");
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

	if (cipher_begin != NULL) {
		if (cipher_end > cipher_begin)
			ctrl->alloc_cipher = s_alloc_and_copy(cipher_begin, cipher_end);
		if (salt_begin != NULL) {
			if (salt_end > salt_begin)
				ctrl->alloc_salt = s_alloc_and_copy(salt_begin, salt_end);
		}
	}

	while (*b == '\n' || (*b == '\r' && b[1] == '\n'))
		b += (*b == '\n' ? 1 : 2);
	const unsigned char *b64_start = b;
	size_t b64_len = 0;

	int got_closed = 0;
	do {
		const unsigned char *h = str_leftis(b, "-----end ");
		const unsigned char *fin = str_rightis(b, &nextline, "-----");
		if (h != NULL && fin != NULL && h < fin) {
			char *header_closure = s_alloc_and_copy(h, fin);
			got_closed = 1;
			DBG("Found header closure '%s'", header_closure)
			free(header_closure);
			break;
		}
		b = nextline;
	} while (nextline != NULL);

	if (nextline != NULL) {
		while (isblank(*nextline) || *nextline == '\n' || *nextline == '\r')
			++nextline;
		if (*nextline == '\0')
			nextline = NULL;
	}

	if (nextline != NULL) {
		DBG("nextline[0] = '%c' (%d)", nextline[0], nextline[0])
	} else {
		DBG("nextline is NULL")
	}

	ctrl->remanent_data_current = nextline;

	if (got_closed) {
		ctrl->remanent_index++;
		DBG("Increasing index. New value = %d", ctrl->remanent_index)

			/*
			 * Not a typo.
			 * Normally blen is 'arrival - beginning + 1' but here,
			 * arrival is 'b - 1' so -1 + 1 => no '+ 1' term.
			 * */
		b64_len = b - b64_start;
		if (has_proc_type && ctrl->alloc_cipher == NULL) {
			if (proc_type_is_set_for_encryption) {
				DBG("Status set to PEM_MISSING_ENCRYPTION_INFORMATION")
				ctrl->status = PEM_MISSING_ENCRYPTION_INFORMATION;
			} else {
				DBG("Status set to PEM_UNMANAGED_PROC_TYPE")
				ctrl->status = PEM_UNMANAGED_PROC_TYPE;
			}
		} else if (b64_len == 0) {
			DBG("Status set to PEM_EMPTY_DATA")
			ctrl->status = PEM_EMPTY_DATA;
		} else if (ctrl->alloc_cipher == NULL) {
			DBG("Status set to PEM_CLEAR_DATA")
			ctrl->status = PEM_CLEAR_DATA;
		} else if (got_empty_line_after_dek_info) {
			DBG("Status set to PEM_ENCRYPTED_DATA")
			ctrl->status = PEM_ENCRYPTED_DATA;
		} else {
			DBG("Status set to PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO")
			ctrl->status = PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO;
		}
	} else {
		ctrl->remanent_data_current = NULL;
		DBG("Status set to PEM_PARSE_ERROR")
		ctrl->status = PEM_PARSE_ERROR;
	}


/*
 * * ******* *
 * * PART II *
 * * ******* *
 *
 *   Decode BASE64 data
 *
 * */


	DBG("pem_next() part 2: decode BASE64-encoded content found")
	if (pem_has_data(ctrl)) {
		if (!pem_base64_decode(b64_start, b64_len, &ctrl->alloc_bin, &ctrl->bin_len)) {
			DBG("Status set to PEM_BAD_BASE64_CONTENT")
			ctrl->status = PEM_BAD_BASE64_CONTENT;
		}
	}

	DBG("pem_next(): returning 1")

	return 1;
}

int pem_has_data(const pem_ctrl_t *ctrl)
{
	return ctrl->status == PEM_ENCRYPTED_DATA || ctrl->status == PEM_CLEAR_DATA;
}

int pem_has_encrypted_data(const pem_ctrl_t *ctrl)
{
	return ctrl->status == PEM_ENCRYPTED_DATA;
}

int pem_had_nothing_at_all(const pem_ctrl_t *ctrl)
{
	if (ctrl->remanent_data_current != NULL)
		FATAL_ERROR("pem_had_nothing_at_all() *must* be called when pem_next() loops are over");
	return ctrl->remanent_index == 0;
}

static int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len)
{
UNUSED(b64msg);

		/* Very loose approximation (we ignore newlines and padding) */
	return (b64msg_len * 3 + 3) / 4 + 1;
}

static int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len)
{
	BIO *bio;
	BIO *b64;

	size_t allocated_len = pem_base64_estimate_decoded_data_len(b64msg, b64msg_len);
	*binbuf = (unsigned char*)malloc(allocated_len);

	bio = BIO_new_mem_buf((void *)b64msg, b64msg_len);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	*binbuf_len = BIO_read(bio, *binbuf, b64msg_len);

	if (*binbuf_len > allocated_len)
		FATAL_ERROR("Estimation of BASE64 decoded size was incorrect!");

	BIO_free_all(bio);

	if (*binbuf_len <= 0) {
		free(*binbuf);
		*binbuf = NULL;
		*binbuf_len = 0;
		return 0;
	} else if (allocated_len != *binbuf_len) {
		*binbuf = (unsigned char *)realloc(*binbuf, *binbuf_len);
	}
	return 1;
}
