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

char *file_in = NULL;
char *file_out = NULL;

	/* Length in BYTES */
#define SALT_LEN 8
char *opt_salt = NULL;

const char *opt_cipher = NULL;

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

unsigned char *read_hexa(const char *s, unsigned char **buf, size_t *buf_len)
{
	if (s == NULL)
		return NULL;
	assert(*buf == NULL);
	int n = strlen(s);
	if (n <= 1 || n % 2 != 0)
		return NULL;
	*buf_len = n / 2;
	*buf = malloc(*buf_len);
	int i;
	int j = 0;
	for (i = 0; i < n; i += 2) {
		int code_hi = hexchar_to_int(s[i]);
		int code_lo = hexchar_to_int(s[i + 1]);
		if (code_hi < 0) {
			free(*buf);
			*buf = NULL;
			return NULL;
		}
		if (code_lo < 0) {
			free(*buf);
			*buf = NULL;
			return NULL;
		}
		(*buf)[j] = (unsigned char)((code_hi << 4) + code_lo);
		++j;
	}
	assert(j == (int)*buf_len);
	return *buf;
}

int manage_password(const unsigned char *salt, const char *cipher,
			unsigned char **key, unsigned char **iv,
			const EVP_CIPHER **evp_cipher)
{
	const char *errmsg;
	char *password = NULL;
	*key = NULL;
	*iv = NULL;
	*evp_cipher = NULL;

	char *readpwd;
	if (opt_password == NULL) {
		fprintf(stderr, "Please type in the password:\n");
		readpwd = NULL;
		size_t s = 0;
		if (getline(&readpwd, &s, stdin) < 0) {
			errmsg = "password read";
			goto error;
		}
	} else {
		readpwd = opt_password;
	}
	int n = strlen(readpwd);
	password = malloc(n + 1);
	s_strncpy(password, readpwd, n + 1);
	if (n >= 2 && (password[n - 1] == '\n' || password[n - 1] == '\r'))
		password[n - 1] = '\0';
	n = strlen(readpwd);
	if (n >= 2 && (password[n - 1] == '\n' || password[n - 1] == '\r'))
		password[n - 1] = '\0';

/*    fprintf(stderr, "Cipher:      %s\n", opt_cipher);*/
/*    fprintf(stderr, "Salt:        ");*/
/*    if (bin_salt == NULL) {*/
/*        fprintf(stderr, "(none)");*/
/*    } else {*/
/*        int ii;*/
/*        for (ii = 0; ii < SALT_LEN; ++ii)*/
/*            fprintf(stderr, "%02X", (unsigned char)bin_salt[ii]);*/
/*    }*/
/*    fprintf(stderr, "\n");*/
/*    fprintf(stderr, "Password:    %s\n", password);*/

	OpenSSL_add_all_algorithms();

	if ((*evp_cipher = EVP_get_cipherbyname(cipher)) == NULL) {
		errmsg = "Could not initialize cipher";
		goto error;
	}

	*key = malloc((*evp_cipher)->key_len);
	*iv = malloc((*evp_cipher)->iv_len);

	int nb_bytes;
	if ((nb_bytes = EVP_BytesToKey(*evp_cipher, EVP_md5(), (unsigned char *)salt,
			(unsigned char *)password, strlen(password), 1, *key, *iv)) < 1) {
		errmsg = "Could not derive KEY and IV from password and salt";
		goto error;
	}

/*    fprintf(stderr, "Key:         ");*/
/*    int i;*/
/*    for (i = 0; i < cipher->key_len; ++i) {*/
/*        fprintf(stderr, "%02X", key[i]);*/
/*    }*/
/*    fprintf(stderr, "\n");*/
/*    fprintf(stderr, "IV:          ");*/
/*    for (i = 0; i < cipher->iv_len; ++i) {*/
/*        fprintf(stderr, "%02X", iv[i]);*/
/*    }*/
/*    fprintf(stderr, "\n");*/

	return 1;

error:
	if (password != NULL) {
		free(password);
	}
	if (*key != NULL) {
		free(*key);
		*key = NULL;
	}
	if (*iv != NULL) {
		free(*iv);
		*iv = NULL;
	}
	*evp_cipher = NULL;
	fprintf(stderr, "Error: %s\n", errmsg);
	return 0;
}

void manage_pem(unsigned char *data_in, const unsigned char *usalt,
		unsigned char **data_out, size_t *data_out_len)
{
	*data_out = NULL;
	*data_out_len = 0;

	size_t blen;
	char *pem_header;
	char *str_cipher;
	char *str_salt;
	unsigned char *data_next;
	int status;
	int pem_index = 0;
	while (pem_next(data_in, &data_in, &blen, &pem_header, &str_cipher, &str_salt, &data_next, &status)) {
		++pem_index;
		if (status != PEM_ENCRYPTED_DATA && status != PEM_BLANK_DATA) {
			fprintf(stderr, "[%s] (skipped due to PEM analyzis error)", pem_header);
			data_in = data_next;
			continue;
		}

		data_in[blen] = '\0';
		if (status == PEM_ENCRYPTED_DATA) {
			fprintf(stderr, "[%s] (encrypted with %s", pem_header, str_cipher);
			if (str_salt == NULL)
				fprintf(stderr, ", no salt)\n");
			else
				fprintf(stderr, ", salt: %s)\n", str_salt);
		} else {
			fprintf(stderr, "[%s]\n", pem_header);
		}

		size_t der_len = pem_base64_estimate_decoded_data_len(data_in, blen);
		unsigned char *der = (unsigned char *)malloc(der_len);
		if (!pem_base64_decode(data_in, blen, &der, &der_len))
			error_stop("Error decoding BASE64");

		unsigned char *data_src = der;
		size_t data_src_len = der_len;

		if (status == PEM_ENCRYPTED_DATA) {
			if (opt_cipher != NULL)
				fprintf(stderr, "Warning: ignoring cipher provided as an option, using PEM's\n");
			if (usalt != NULL && str_salt != NULL)
				fprintf(stderr, "Warning: ignoring salt provided as an option, using PEM's\n");
			const unsigned char *salt = NULL;
			unsigned char *pem_salt = NULL;
			size_t pem_salt_len;
			pem_salt = read_hexa(str_salt, &pem_salt, &pem_salt_len);
			if (str_salt != NULL && (pem_salt == NULL || pem_salt_len != SALT_LEN))
				error_stop("Incorrect salt found in PEM: %s", str_salt);
			salt = pem_salt;
			if (usalt != NULL && salt == NULL)
				salt = usalt;

			unsigned char *key;
			unsigned char *iv;
			const EVP_CIPHER *cipher;

			if (manage_password(salt, str_cipher, &key, &iv, &cipher)) {
				EVP_CIPHER_CTX *ctx;
				if (!(ctx = EVP_CIPHER_CTX_new()))
					error_stop("manage_pem(): EVP_CIPHER_CTX_new() returned NULL");

				unsigned char *out = malloc(der_len + 256);

				if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, (unsigned char *)salt) != 1)
					error_stop("ECP_DecryptInit_ex() did not return 1");

				int outl;
				int out_len;

				if (EVP_DecryptUpdate(ctx, out, &outl, der, der_len) != 1)
					error_stop("EVP_DecryptUpdate() did not return 1");
				int final_outl;
				if (EVP_DecryptFinal_ex(ctx, out + outl, &final_outl) != 1)
					error_stop("EVP_DecryptFinal_ex() did not return 1");
				out_len = outl + final_outl;

				fprintf(stderr, "Decrypted data length: %i\n", out_len);
				EVP_CIPHER_CTX_free(ctx);
				free(key);
				free(iv);

				data_src = out;
				data_src_len = out_len;

			} else {
				data_src = NULL;
			}
		}
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

		data_in = data_next;
	}
	if (pem_index == 0) {
		if (status == PEM_NO_PEM_INFORMATION)
			error_stop("No PEM information in file %s", file_in);
		else
			error_stop("Unable to parse PEM information in file %s", file_in);
	}
}

int main(int argc, char **argv)
{
	parse_options(argc, argv);

	unsigned char *salt = NULL;
	size_t salt_len;
	salt = read_hexa(opt_salt, &salt, &salt_len);
	if (opt_salt != NULL && (salt == NULL || salt_len != SALT_LEN))
		error_stop("Incorrect salt: %s", opt_salt);

	ssize_t bufin_len = file_size(file_in);
	if (bufin_len < 0)
		error_stop("Unable to get size of file %s", file_in);

	unsigned char *bufin = malloc(bufin_len + 1);
	FILE *fin;
	if ((fin = fopen(file_in, "rb")) == NULL)
		error_stop("Unable to open file %s for input", file_in);

	if ((ssize_t)fread(bufin, 1, bufin_len, fin) != bufin_len)
		error_stop("Could not read all data of file %s", file_in);
	bufin[bufin_len] = '\0';

	fclose(fin);

	unsigned char *bufout;
	size_t bufout_len = 0;

	manage_pem(bufin, salt, &bufout, &bufout_len);

	fprintf(stderr, "Output data length: %lu\n", bufout_len);

	FILE *fout;
	if (file_out == NULL)
		fout = stdout;
	else if ((fout = fopen(file_out, "wb")) == NULL)
		error_stop("Unable to open file %s for output", file_out);
	if (fwrite(bufout, 1, bufout_len, fout) != bufout_len)
		error_stop("Could not write all data to file %s", file_out == NULL ? "(stdout)" : file_out);
	if (file_out != NULL)
		fclose(fout);

	free(bufout);
	free(bufin);
}

