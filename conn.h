struct conn *conn_connect(char *addr, char *port);
int conn_tls(struct conn *conn, char *certfile);
int conn_write(struct conn *conn, char *buf, int len);
int conn_read(struct conn *conn, char *buf, int len);
int conn_close(struct conn *conn);
