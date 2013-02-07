#define MAILLEN			(1 << 24)
#define HOSTNAME		"hostname"
#define DPRINT(msg, len)

/* the account whose from attribute appears in mail's from header is used */
struct account {
	char *from;	/* the from address to match */
	char *server;
	char *port;
	char *user;
	char *pass;
	char *cert;	/* server certificate to verify */
} accounts [] = {
	{"me@myserver.sth", "smtp.myserver.sth", "465", "me", "pass"},
};
