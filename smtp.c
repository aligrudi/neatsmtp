/*
 * a simple smtp mail sender
 *
 * Copyright (C) 2010-2013 Ali Gholami Rudi
 *
 * This program is released under the modified BSD license.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "conn.h"

#define BUFFSIZE		(1 << 12)
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)		((a) < (b) ? (a) : (b))

static char buf[BUFFSIZE];
static int buf_len;
static int buf_pos;
static char mail[MAILLEN];
static int mail_len;
static struct conn *conn;

static char *b64 =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_num(char *s, unsigned long num)
{
	s[3] = b64[num & 0x3f];
	num >>= 6;
	s[2] = b64[num & 0x3f];
	num >>= 6;
	s[1] = b64[num & 0x3f];
	num >>= 6;
	s[0] = b64[num & 0x3f];
}

static char *putb64(char *dst, char *src, int len)
{
	int n = len / 3;
	int i;
	if (n * 3 != len)
		n++;
	for (i = 0; i < n; i++) {
		char *s = src + 3 * i;
		unsigned c0 = (unsigned) s[0];
		unsigned c1 = s + 1 < src + len ? (unsigned) s[1] : 0;
		unsigned c2 = s + 2 < src + len ? (unsigned) s[2] : 0;
		unsigned long word = (c0 << 16) | (c1 << 8) | c2;
		b64_num(dst + 4 * i, word);
	}
	if (len % 3)
		for (i = len % 3; i < 3; i++)
			dst[4 * len - 3 + i] = '=';
	dst[n * 4] = '\0';
	return dst + n * 4;
}

static char *putstr(char *dst, char *src)
{
	int len = strchr(src, '\0') - src;
	memcpy(dst, src, len + 1);
	return dst + len;
}

static char *cutaddr(char *dst, char *s, int len)
{
	static char *addrseps = "<>()%!~* \t\r\n,\"'%";
	char *end = s + len;
	while (s < end && *s && strchr(addrseps, *s))
		s++;
	while (s < end && *s && !strchr(addrseps, *s))
		*dst++ = *s++;
	*dst = '\0';
	return s;
}

static char *find_hdr(char *hdr)
{
	char *s = mail;
	int len = strlen(hdr);
	char *end = mail + mail_len - len;
	while (s < end) {
		char *r;
		if (!strncasecmp(s, hdr, len))
			return s;
		r = memchr(s, '\n', end - s);
		if (!r || r == s)
			return NULL;
		s = r + 1;
	}
	return s;
}

static int hdr_len(char *hdr)
{
	char *s = hdr;
	while (*s) {
		char *r = strchr(s, '\n');
		if (!r)
			return strchr(s, '\0') - hdr;
		s = r + 1;
		if (!isspace(*s))
			return s - hdr;
	}
	return 0;
}

static int xread(int fd, char *buf, int len)
{
	int nr = 0;
	while (nr < len) {
		int ret = read(fd, buf + nr, len - nr);
		if (ret == -1 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret <= 0)
			break;
		nr += ret;
	}
	return nr;
}

static int smtp_read(void)
{
	if (buf_pos == buf_len) {
		buf_len = conn_read(conn, buf, sizeof(buf));
		buf_pos = 0;
	}
	return buf_pos < buf_len ? (unsigned char) buf[buf_pos++] : -1;
}

static int smtp_line(char *dst, int len)
{
	int i = 0;
	int c;
	while (i < len) {
		c = smtp_read();
		if (c < 0)
			return -1;
		dst[i++] = c;
		if (c == '\n')
			break;
	}
	DPRINT(dst, i);
	return i;
}
static int smtp_xwrite(char *buf, int len)
{
	int nw = 0;
	while (nw < len) {
		int ret = conn_write(conn, buf + nw, len - nw);
		if (ret == -1 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret < 0)
			break;
		DPRINT(buf + nw, ret);
		nw += ret;
	}
	return nw;
}

static void send_cmd(char *cmd)
{
	conn_write(conn, cmd, strlen(cmd));
	DPRINT(cmd, strlen(cmd));
}

static int is_eoc(char *s, int len)
{
	return len > 3 && isdigit(s[0]) && isdigit(s[1]) &&
			isdigit(s[2]) && isspace(s[3]);
}

static int ehlo(void)
{
	char line[BUFFSIZE];
	int len;
	len = smtp_line(line, sizeof(line));
	send_cmd("EHLO " HOSTNAME "\r\n");
	do {
		len = smtp_line(line, sizeof(line));
	} while (len > 0 && !is_eoc(line, len));
	return len <= 0;
}

static int login(char *user, char *pass)
{
	char line[BUFFSIZE];
	char *s = line;
	send_cmd("AUTH LOGIN\r\n");
	smtp_line(line, sizeof(line));
	s = putb64(s, user, strlen(user));
	s = putstr(s, "\r\n");
	send_cmd(line);
	smtp_line(line, sizeof(line));
	s = line;
	s = putb64(s, pass, strlen(pass));
	s = putstr(s, "\r\n");
	send_cmd(line);
	return smtp_line(line, sizeof(line)) <= 0;
}

static int write_mail(struct account *account)
{
	char line[BUFFSIZE];
	char *to_hdrs[] = {"to:", "cc:", "bcc:"};
	int i;
	sprintf(line, "MAIL FROM:<%s>\r\n", account->from);
	send_cmd(line);
	smtp_line(line, sizeof(line));

	for (i = 0; i < ARRAY_SIZE(to_hdrs); i++) {
		char *hdr, *end, *s;
		char addr[BUFFSIZE];
		if (!(hdr = find_hdr(to_hdrs[i])))
			continue;
		end = hdr + hdr_len(hdr);
		s = hdr;
		while ((s = cutaddr(addr, s, end - s)) && s < end) {
			char *at = strchr(addr, '@');
			if (at && at > addr && *(at + 1)) {
				sprintf(line, "RCPT TO:<%s>\r\n", addr);
				send_cmd(line);
				smtp_line(line, sizeof(line));
			}
		}
	}

	send_cmd("DATA\r\n");
	if (smtp_line(line, sizeof(line)) <= 0)
		return 1;
	if (smtp_xwrite(mail, mail_len) != mail_len)
		return 1;
	send_cmd("\r\n.\r\n");
	if (smtp_line(line, sizeof(line)) <= 0)
		return 1;
	send_cmd("QUIT\r\n");
	smtp_line(line, sizeof(line));
	return 0;
}

static struct account *choose_account(void)
{
	char *from = find_hdr("from:");
	char *end = from + hdr_len(from);
	int i;
	for (i = 0; i < ARRAY_SIZE(accounts) && from; i++) {
		char *pat = accounts[i].from;
		int len = strlen(pat);
		char *s = from;
		while (s + len < end && (s = memchr(s, pat[0], end - s)))
			if (!strncmp(pat, s++, len))
				return &accounts[i];
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct account *account;
	mail_len = xread(STDIN_FILENO, mail, sizeof(mail));
	if (mail_len < 0 || mail_len >= sizeof(mail))
		return 1;
	account = choose_account();
	if (!account)
		return 1;
	conn = conn_connect(account->server, account->port, account->cert);
	if (!conn)
		return 1;
	if (ehlo())
		goto fail;
	if (login(account->user, account->pass))
		goto fail;
	if (write_mail(account))
		goto fail;
	conn_close(conn);
	return 0;
fail:
	conn_close(conn);
	return 1;
}
