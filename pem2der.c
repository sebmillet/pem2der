/*
 * =====================================================================================
 *
 *       Filename:  pem2der.c
 *
 *    Description:  Crypto : convert PEM to DER format
 *
 *        Version:  1.0
 *        Created:  27/12/2015 10:38:44
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

/*#define DEBUG*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#include "ppem.h"

#define PACKAGE_NAME "pem2der"

#define FALSE 0
#define TRUE  1

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

char *file_in = NULL;
char *file_out = NULL;

char *opt_password = NULL;

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "./pem2der [OPTIONS]... FILE\n");
	fprintf(stderr, "Decode and decrypt PEM files.\n");
	fprintf(stderr, "  -h  --help          print this help and exit\n");
	fprintf(stderr, "  -v  --version       print version information and exit\n");
	fprintf(stderr, "  -o  --out FILE      output to FILE instead of stdout\n");
	exit(-1);
}

void version()
{
	fprintf(stderr, "pem2der 0.1\n");
	fprintf(stderr, "Copyright 2015 Sébastien Millet\n");
	exit(-2);
}

char *s_strncpy(char *dest, const char *src, size_t n)
{
		strncpy(dest, src, n);
		dest[n - 1] = '\0';
		return dest;
}
	/* The define below triggers an error if usual strncpy is used */
#define strncpy(a, b, c) ErrorDontUse_strncpy_Use_s_strncpy_Instead

	/*
	 * Returns a copied, allocated string. Uses s_strncpy for the string
	 * copy (see comment above).
	 * dst can be null, in which case the new string is to be retrieved
	 * by the function return value.
	 */
char *s_alloc_and_copy(char **dst, const char *src)
{
	unsigned int s = strlen(src) + 1;
	char *target = (char *)malloc(s);
	s_strncpy(target, src, s);
	if (dst != NULL)
		*dst = target;
	return target;
}

void error_stop(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(-1);
}

ssize_t file_size(const char* filename)
{
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}

static void opt_check(unsigned int n, const char *opt)
{
	static int defined_options[2] = {0, 0};

	assert(n < sizeof(defined_options) / sizeof(*defined_options));

	if (defined_options[n]) {
		fprintf(stderr, "Option %s already set\n", opt);
		exit(-2);
	} else
		defined_options[n] = TRUE;
}

static void parse_options(int argc, char **argv)
{
#define OPT_WITH_VALUE_CHECK \
if (shortopt_nb >= 1 && shortopt_i < shortopt_nb - 1) { \
	missing_option_value = argv_a_short + 1; \
	a = -1; \
	break; \
} \
if (++a >= argc) { \
	missing_option_value = argv[a - 1] + 1; \
	a = -1; \
	break; \
}

	char *missing_option_value = NULL;

	int a = 1;
	char *argv_a_short;
	char shortopt[3];
	int shortopt_nb = 0;
	int shortopt_i = -1;
	while (a < argc) {
		if (shortopt_nb == 0) {
			if (strlen(argv[a]) >= 2 && argv[a][0] == '-' && argv[a][1] != '-') {
				shortopt_nb = strlen(argv[a]) - 1;
				shortopt_i = 0;
			}
		}
		if (shortopt_nb >= 1) {
			assert(shortopt_i <= shortopt_nb);
			shortopt[0] = '-';
			shortopt[1] = argv[a][shortopt_i + 1];
			shortopt[2] = '\0';
			argv_a_short = shortopt;
		} else {
			argv_a_short = argv[a];
		}

		if (!strcmp(argv[a], "--help") || !strcmp(argv_a_short, "-h")) {
			usage();
		} else if (!strcmp(argv[a], "--version") || !strcmp(argv_a_short, "-v")) {
			version();
			exit(0);
		} else if (!strcmp(argv[a], "--out") || !strcmp(argv_a_short, "-o")) {
			opt_check(0, argv[a]);
			OPT_WITH_VALUE_CHECK
			file_out = argv[a];
		} else if (!strcmp(argv[a], "--password")) {
			opt_check(1, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_password = argv[a];
		} else if (argv[a][0] == '-') {
			if (strcmp(argv[a], "--")) {
				fprintf(stderr, "%s: invalid option -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			} else {
				++a;
				break;
			}
		} else {
			if (file_in == NULL) {
				file_in = argv[a];
			} else {
				fprintf(stderr, "%s: invalid argument -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			}
		}
		if (shortopt_nb >= 1) {
			if (++shortopt_i >= shortopt_nb)
				shortopt_nb = 0;
		}
		if (shortopt_nb == 0)
			++a;
	}
	if ((a >= 1 && a < argc - 1) || (a >= 1 && a == argc - 1 && file_in != NULL)) {
		fprintf(stderr, "%s: trailing options.\n", PACKAGE_NAME);
		a = -1;
	} else if (a >= 1 && a == argc - 1) {
		file_in = argv[a];
	} else if (missing_option_value != NULL) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option_value);
	}
	if (a < 0)
		usage();
	if (file_in == NULL) {
		fprintf(stderr, "%s: you must specify the input file\n", PACKAGE_NAME);
		usage();
	}
}

int hexchar_to_int(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return (c - 'A') + 10;
	else if (c >= 'a' && c <= 'f')
		return (c - 'a') + 10;
	else
		return -1;
}

	/*
	 * Read a hex string (like "A0F23BB1") and convert into
	 * a binary block corresponding to the hex string.
	 * Hex characters can be lower or upper case letters.
	 *
	 * The target binary block is allocated and the caller will
	 * later have to manage freeing it.
	 *
	 * If there is an issue in the conversion (illegal characters),
	 * no allocation is done and *buf and *buf_len are zeroed.
	 *
	 * Return 1 if success (meaning, the binary block got allocated
	 * and contains the binary corresponding to hex string), return 0
	 * otherwise.
	 *
	 * *WARNING*
	 *   The returned block is *NOT* a string (it is not null-character
	 *   terminated).
	 *
	 */
int alloc_and_read_hexa(const char *s, unsigned char **buf, size_t *buf_len)
{
	*buf = NULL;
	*buf_len = 0;

	if (s == NULL)
		return 0;

	int n = strlen(s);
	if (n <= 1 || n % 2 != 0)
		return 0;

	*buf_len = n / 2;
	*buf = malloc(*buf_len);
	int i;
	int j = 0;
	for (i = 0; i < n; i += 2) {
		int code_hi = hexchar_to_int(s[i]);
		int code_lo = hexchar_to_int(s[i + 1]);
		if (code_hi < 0 || code_lo < 0) {
			free(*buf);
			*buf = NULL;
			*buf_len = 0;
			return 0;
		}
		(*buf)[j] = (unsigned char)((code_hi << 4) + code_lo);
		++j;
	}
	assert(j == (int)*buf_len);
	return 1;
}

char *get_password()
{
	char *password;

	char *readpwd;
	if (opt_password == NULL) {
		fprintf(stderr, "Please type in the password:\n");
		readpwd = NULL;
		size_t s = 0;
		if (getline(&readpwd, &s, stdin) < 0) {
			if (readpwd != NULL)
				free(readpwd);
			return NULL;
		}
		password = readpwd;
	} else {
		password = s_alloc_and_copy(NULL, opt_password);
	}

	int i;
	for (i = 0; i < 2; ++i) {
		int n = strlen(password);
		if (n >= 1 && (password[n - 1] == '\n' || password[n - 1] == '\r'))
			password[n - 1] = '\0';
	}

	DBG("Password: '%s'", password)

	return password;
}

int do_decrypt(const char *cipher, const unsigned char *salt, const unsigned char *in, int in_len,
		unsigned char **out, int *out_len, const char **errmsg)
{
	*out = NULL;
	*out_len = 0;
	*errmsg = NULL;

	const EVP_CIPHER *evp_cipher;
	if ((evp_cipher = EVP_get_cipherbyname(cipher)) == NULL) {
		*errmsg = "unable to acquire cipher by its name";
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		return 0;
	}

	char *password;
	if ((password = get_password()) == NULL) {
		*errmsg = "no password";
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		return 0;
	}

	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		*errmsg = "unable to initialize cipher context";
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		free(password);
		return 0;
	}

	unsigned char *key = malloc(evp_cipher->key_len);
	unsigned char *iv = malloc(evp_cipher->iv_len);

	do {

		int nb_bytes;
		if ((nb_bytes = EVP_BytesToKey(evp_cipher, EVP_md5(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) < 1) {
			*errmsg = "could not derive KEY and IV from password and salt";
			break;
		}

		if (EVP_DecryptInit_ex(ctx, evp_cipher, NULL, key, (unsigned char *)salt) != 1) {
			*errmsg = "unable to initialize decryption";
			break;
		}

		int outl;
		*out = malloc(in_len + 256);
		if (EVP_DecryptUpdate(ctx, *out, &outl, in, in_len) != 1) {
			*errmsg = "unable to perform decryption";
			break;
		}
		int final_outl;
		if (EVP_DecryptFinal_ex(ctx, *out + outl, &final_outl) != 1) {
			*errmsg = "decryption error";
			break;
		}
		*out_len = outl + final_outl;

	} while (FALSE);

	free(iv);
	free(key);
	free(password);
	EVP_CIPHER_CTX_free(ctx);

	if (*errmsg != NULL) {
		if (*out != NULL) {
			free(*out);
			*out = NULL;
			*out_len = 0;
		}
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		return 0;
	}

	DBG("do_decrypt(): returning 1 (SUCCESS)")
	return 1;
}

void openssl_start()
{
	OpenSSL_add_all_algorithms();
}

	/*
	 * the list of functions to call was found here:
	 *   https://wiki.openssl.org/index.php/Library_Initialization
	 *
	 * */
void openssl_terminate()
{
	FIPS_mode_set(0);
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
}

void pem_walker(const unsigned char *data_in, unsigned char **data_out, size_t *data_out_len)
{
	openssl_start();

	*data_out = NULL;
	*data_out_len = 0;

	pem_ctrl_t *ctrl = pem_construct_pem_ctrl(data_in);
	while (pem_next(ctrl)) {
		if (!pem_has_data(ctrl)) {
			DBG("pem_walker(): [%s] (skipped: %s)", pem_header(ctrl), pem_errorstring(pem_status(ctrl)))
			fprintf(stderr, "[%s] (skipped: %s)\n", pem_header(ctrl), pem_errorstring(pem_status(ctrl)));
			continue;
		}

		if (pem_has_encrypted_data(ctrl)) {
			DBG("pem_walker(): [%s] (encrypted: '%s', salt: '%s')",
					pem_header(ctrl), pem_cipher(ctrl), pem_salt(ctrl) == NULL ? "(none)" : pem_salt(ctrl))
			fprintf(stderr, "[%s] (encrypted with %s", pem_header(ctrl), pem_cipher(ctrl));
			if (pem_salt(ctrl) == NULL)
				fprintf(stderr, ", no salt)\n");
			else
				fprintf(stderr, ", salt: %s)\n", pem_salt(ctrl));
		} else {
			fprintf(stderr, "[%s]\n", pem_header(ctrl));
		}

		unsigned char *data_src;
		size_t data_src_len;
		int data_src_is_readonly;
		if (!pem_has_encrypted_data(ctrl)) {
			DBG("pem_walker(): data is clear")
			data_src = (unsigned char *)pem_bin(ctrl);
			data_src_len = pem_bin_len(ctrl);
			data_src_is_readonly = TRUE;
		} else {
			DBG("pem_walker(): data is encrypted")
			data_src = NULL;
			data_src_len = 0;

			unsigned char *salt = NULL;
			size_t salt_len;
			alloc_and_read_hexa(pem_salt(ctrl), &salt, &salt_len);
			if (pem_salt(ctrl) != NULL && (salt == NULL)) {
				DBG("pem_walker(): incorrect salt")
				DBG("pem_walker(): salt: '%s'", pem_salt(ctrl))
				fprintf(stderr, "Incorrect salt: '%s'\n", pem_salt(ctrl));
			} else {
				unsigned char *out;
				int out_len;
				const char *errmsg;
				if (do_decrypt(pem_cipher(ctrl), salt, pem_bin(ctrl), pem_bin_len(ctrl), &out, &out_len, &errmsg) == 1) {
					DBG("pem_walker(): decrypt successful")
					data_src = out;
					data_src_len = out_len;
					data_src_is_readonly = FALSE;
				} else {
					DBG("pem_walker(): decrypt error: %s", errmsg)
					fprintf(stderr, "%s\n", errmsg);
				}
			}
			if (salt != NULL)
				free(salt);
		}

		if (data_src != NULL) {
			DBG("data (was clear or got decrypted) to add to buffer")
			unsigned char *target;
			if (*data_out == NULL) {
				*data_out = malloc(data_src_len);
				target = *data_out;
				*data_out_len = 0;
			} else {
				*data_out = realloc(*data_out, *data_out_len + data_src_len);
				target = *data_out + *data_out_len;
			}
			memcpy(target, data_src, data_src_len);
			*data_out_len += data_src_len;
			if (!data_src_is_readonly)
				free(data_src);
		}
	}
	pem_destruct_pem_ctrl(ctrl);

	openssl_terminate();
}

int main(int argc, char **argv)
{
	unsigned char *bufin = NULL;
	unsigned char *bufout = NULL;

	parse_options(argc, argv);

	do {
		ssize_t bufin_len = file_size(file_in);
		if (bufin_len < 0) {
			fprintf(stderr, "Unable to get size of file %s", file_in);
			break;
		}

		bufin = malloc(bufin_len + 1);
		FILE *fin;
		if ((fin = fopen(file_in, "rb")) == NULL) {
			fprintf(stderr, "Unable to open file %s for input", file_in);
			break;
		}

		if ((ssize_t)fread(bufin, 1, bufin_len, fin) != bufin_len) {
			fprintf(stderr, "Could not read all data of file %s", file_in);
			break;
		}
		bufin[bufin_len] = '\0';

		fclose(fin);

		size_t bufout_len = 0;

		pem_walker(bufin, &bufout, &bufout_len);

		fprintf(stderr, "Output data length: %lu\n", bufout_len);

		FILE *fout;
		if (file_out == NULL)
			fout = stdout;
		else if ((fout = fopen(file_out, "wb")) == NULL) {
			fprintf(stderr, "Unable to open file %s for output", file_out);
			break;
		}
		if (fwrite(bufout, 1, bufout_len, fout) != bufout_len) {
			error_stop("Could not write all data to file %s", file_out == NULL ? "(stdout)" : file_out);
			break;
		}
		if (file_out != NULL)
			fclose(fout);
	} while (FALSE);

	free(bufout);
	free(bufin);
}

