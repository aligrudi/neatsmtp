#define MAILLEN			(1 << 21)
#define HOSTNAME		"hostname"
#define SSL

struct account {
	char *from;
	char *server;
	char *port;
	char *user;
	char *pass;
} accounts [] = {
	{"me@myserver.sth", "smtp.myserver.sth", "465", "me", "pass"},
};
