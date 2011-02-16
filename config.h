#define MAILLEN			(1 << 21)
#define HOSTNAME		"hostname"
#define DPRINT(msg, len)

struct account {
	char *from;
	char *server;
	char *port;
	char *user;
	char *pass;
	char *cert;
} accounts [] = {
	{"me@myserver.sth", "smtp.myserver.sth", "465", "me", "pass"},
};
