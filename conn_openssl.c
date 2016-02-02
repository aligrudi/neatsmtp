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

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct conn {
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
};

int conn_read(struct conn *conn, char *buf, int len)
{
	if (conn->ssl)
		return SSL_read(conn->ssl, buf, len);
	return read(conn->fd, buf, len);
}

int conn_write(struct conn *conn, char *buf, int len)
{
	if (conn->ssl)
		return SSL_write(conn->ssl, buf, len);
	return write(conn->fd, buf, len);
}

int conn_tls(struct conn *conn, char *certfile)
{
	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
	conn->ctx = SSL_CTX_new(SSLv23_method());
	if (!conn->ctx)
		return 1;
	conn->ssl = SSL_new(conn->ctx);
	if (!conn->ssl)
		return 1;
	if (certfile) {
		SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_load_verify_locations(conn->ctx, certfile, NULL);
	}
	SSL_set_fd(conn->ssl, conn->fd);
	if (SSL_connect(conn->ssl) != 1)
		return 1;
	if (certfile && SSL_get_verify_result(conn->ssl) != X509_V_OK)
		return 1;
	return 0;
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
	memset(conn, 0, sizeof(*conn));
	conn->fd = fd;
	return conn;
}

int conn_close(struct conn *conn)
{
	if (conn->ssl) {
		SSL_shutdown(conn->ssl);
		SSL_free(conn->ssl);
		SSL_CTX_free(conn->ctx);
	}
	close(conn->fd);
	free(conn);
	return 0;
}
