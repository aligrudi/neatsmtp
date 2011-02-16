struct conn *conn_connect(char *addr, char *port, char *certfile);
int conn_write(struct conn *conn, char *buf, int len);
int conn_read(struct conn *conn, char *buf, int len);
int conn_close(struct conn *conn);
