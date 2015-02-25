#define HOSTNAME		"hostname"
#define DPRINT(msg, len)

/* mails are matched against these accounts based on their from addresses */
struct account {
	char *from;	/* the from address to match */
	char *server;
	char *port;
	char *user;
	char *pass;
	char *cert;	/* root certificates PEM file */
} accounts [] = {
	{"me@myserver.sth", "smtp.myserver.sth", "465", "me", "pass"},
};
