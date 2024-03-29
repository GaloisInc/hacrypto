/* $OpenBSD: ressl.h,v 1.16 2014/09/28 15:08:01 jsing Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEADER_RESSL_H
#define HEADER_RESSL_H

#define RESSL_READ_AGAIN	-2
#define RESSL_WRITE_AGAIN	-3

struct ressl;
struct ressl_config;

int ressl_init(void);

const char *ressl_error(struct ressl *ctx);

struct ressl_config *ressl_config_new(void);
void ressl_config_free(struct ressl_config *config);

int ressl_config_set_ca_file(struct ressl_config *config, const char *ca_file);
int ressl_config_set_ca_path(struct ressl_config *config, const char *ca_path);
int ressl_config_set_cert_file(struct ressl_config *config,
    const char *cert_file);
int ressl_config_set_cert_mem(struct ressl_config *config, const uint8_t *cert,
    size_t len);
int ressl_config_set_ciphers(struct ressl_config *config, const char *ciphers);
int ressl_config_set_ecdhcurve(struct ressl_config *config, const char *name);
int ressl_config_set_key_file(struct ressl_config *config,
    const char *key_file);
int ressl_config_set_key_mem(struct ressl_config *config, const uint8_t *key,
    size_t len);
void ressl_config_set_verify_depth(struct ressl_config *config,
    int verify_depth);

void ressl_config_clear_keys(struct ressl_config *config);
void ressl_config_insecure_no_verify(struct ressl_config *config);
void ressl_config_verify(struct ressl_config *config);

struct ressl *ressl_client(void);
struct ressl *ressl_server(void);
int ressl_configure(struct ressl *ctx, struct ressl_config *config);
void ressl_reset(struct ressl *ctx);
void ressl_free(struct ressl *ctx);

int ressl_accept(struct ressl *ctx, struct ressl **cctx);
int ressl_accept_socket(struct ressl *ctx, struct ressl **cctx, int socket);
int ressl_connect(struct ressl *ctx, const char *host, const char *port);
int ressl_connect_socket(struct ressl *ctx, int s, const char *hostname);
int ressl_listen(struct ressl *ctx, const char *host, const char *port, int af);
int ressl_read(struct ressl *ctx, void *buf, size_t buflen, size_t *outlen);
int ressl_write(struct ressl *ctx, const void *buf, size_t buflen,
    size_t *outlen);
int ressl_close(struct ressl *ctx);

#endif /* HEADER_RESSL_H */
