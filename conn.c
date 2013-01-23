#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <polarssl/ssl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

struct conn {
	int fd;
	ssl_context ssl;
	ssl_session ssn;
	ctr_drbg_context ctr_drbg;
	x509_cert cert;
};

static int ps_send(void *ctx, const unsigned char *buf, size_t len)
{
	return write(*(int *) ctx, buf, len);
}

static int ps_recv(void *ctx, unsigned char *buf, size_t len)
{
	return read(*(int *) ctx, buf, len);
}

int conn_read(struct conn *conn, char *buf, int len)
{
	return ssl_read(&conn->ssl, (unsigned char *) buf, sizeof(buf));
}

int conn_write(struct conn *conn, char *buf, int len)
{
	return ssl_write(&conn->ssl, (unsigned char *) buf, len);
}

static int conns_init(struct conn *conn, char *certfile)
{
	entropy_context entropy;
	entropy_init(&entropy);
	ctr_drbg_init(&conn->ctr_drbg, entropy_func, &entropy, NULL, 0);
	if (ssl_init(&conn->ssl))
		return 1;
	ssl_set_endpoint(&conn->ssl, SSL_IS_CLIENT);
	if (certfile) {
		x509parse_crtfile(&conn->cert, certfile);
		ssl_set_ca_chain(&conn->ssl, &conn->cert, NULL, NULL);
		ssl_set_authmode(&conn->ssl, SSL_VERIFY_REQUIRED);
	} else{
		ssl_set_authmode(&conn->ssl, SSL_VERIFY_NONE);
	}
	ssl_set_rng(&conn->ssl, ctr_drbg_random, &conn->ctr_drbg);
	ssl_set_bio(&conn->ssl, ps_recv, &conn->fd, ps_send, &conn->fd);
	ssl_set_ciphersuites(&conn->ssl, ssl_default_ciphersuites);
	ssl_set_session(&conn->ssl, &conn->ssn);
	return ssl_handshake(&conn->ssl);
}

struct conn *conn_connect(char *addr, char *port, char *certfile)
{
	struct addrinfo hints, *addrinfo;
	struct conn *conn;
	int fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(addr, port, &hints, &addrinfo))
		return NULL;
	fd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
			addrinfo->ai_protocol);

	if (connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
		close(fd);
		freeaddrinfo(addrinfo);
		return NULL;
	}
	freeaddrinfo(addrinfo);

	conn = malloc(sizeof(*conn));
	memset(conn, 0, sizeof(conn));
	conn->fd = fd;
	if (conns_init(conn, certfile)) {
		free(conn);
		return NULL;
	}
	return conn;
}

int conn_close(struct conn *conn)
{
	ssl_close_notify(&conn->ssl);
	x509_free(&conn->cert);
	ssl_free(&conn->ssl);

	close(conn->fd);
	free(conn);
	return 0;
}
