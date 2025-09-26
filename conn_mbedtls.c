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
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>

struct conn {
	int fd;
	int tls;
	char *hostname;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_session ssn;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt cert;
	mbedtls_ssl_config conf;
};

int conn_read(struct conn *conn, char *buf, int len)
{
	if (conn->tls)
		return mbedtls_ssl_read(&conn->ssl, (unsigned char *) buf, len);
	return read(conn->fd, buf, len);
}

int conn_write(struct conn *conn, char *buf, int len)
{
	if (conn->tls)
		return mbedtls_ssl_write(&conn->ssl, (unsigned char *) buf, len);
	return write(conn->fd, buf, len);
}

int conn_tls(struct conn *conn, char *certfile)
{
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&conn->ctr_drbg);
	mbedtls_ssl_init(&conn->ssl);
	mbedtls_ssl_config_init(&conn->conf);
	mbedtls_ctr_drbg_seed(&conn->ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->ctr_drbg);
	if (certfile) {
		mbedtls_x509_crt_parse_file(&conn->cert, certfile);
		mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->cert, NULL);
		mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->cert, NULL);
		mbedtls_ssl_set_hostname(&conn->ssl, conn->hostname);
	} else {
		mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_NONE);
	}
	if (mbedtls_ssl_setup(&conn->ssl, &conn->conf))
		return 1;
	mbedtls_ssl_set_bio(&conn->ssl, &conn->fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	conn->tls = 1;
	return mbedtls_ssl_handshake(&conn->ssl);
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
	conn->hostname = addr;
	return conn;
}

int conn_close(struct conn *conn)
{
	if (conn->tls) {
		mbedtls_ssl_close_notify(&conn->ssl);
		mbedtls_x509_crt_free(&conn->cert);
		mbedtls_ssl_free(&conn->ssl);
		mbedtls_ssl_config_free(&conn->conf);
		mbedtls_ctr_drbg_free(&conn->ctr_drbg);
	}
	close(conn->fd);
	free(conn);
	return 0;
}
