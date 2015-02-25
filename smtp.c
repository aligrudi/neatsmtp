/*
 * A simple SMTP mail sender
 *
 * Copyright (C) 2010-2015 Ali Gholami Rudi <ali at rudi dot ir>
 *
 * This program is released under the Modified BSD license.
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

#define LNLEN			(1 << 12)
#define HDLEN			(1 << 15)
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))
#define MIN(a, b)		((a) < (b) ? (a) : (b))

static char buf[LNLEN];		/* SMTP reply buffer */
static int buf_len;
static int buf_pos;
static char mail[HDLEN];	/* the first HDLEN bytes of the mail */
static int mail_len;
static struct conn *conn;	/* the SMTP connection */

static char *b64_chr =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* encode 3 bytes in base64 */
static void b64_word(char *s, unsigned num)
{
	s[3] = b64_chr[num & 0x3f];
	num >>= 6;
	s[2] = b64_chr[num & 0x3f];
	num >>= 6;
	s[1] = b64_chr[num & 0x3f];
	num >>= 6;
	s[0] = b64_chr[num & 0x3f];
}

/* base64 encoding; returns a static buffer */
static char *b64(char *src, int len)
{
	static char dst[LNLEN];
	int n = (len + 2) / 3;
	int i;
	for (i = 0; i < n; i++) {
		char *s = src + 3 * i;
		unsigned c0 = (unsigned char) s[0];
		unsigned c1 = s + 1 < src + len ? (unsigned char) s[1] : 0;
		unsigned c2 = s + 2 < src + len ? (unsigned char) s[2] : 0;
		b64_word(dst + 4 * i, (c0 << 16) | (c1 << 8) | c2);
	}
	if (len % 3 >= 1)
		dst[4 * n - 1] = '=';
	if (len % 3 == 1)
		dst[4 * n - 2] = '=';
	dst[n * 4] = '\0';
	return dst;
}

/* copy the address in s to dst */
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

static char *hdr_val(char *hdr)
{
	char *s = mail;
	int len = strlen(hdr);
	char *end = mail + mail_len - len;
	while (s < end && strncasecmp(s, hdr, len)) {
		char *r = memchr(s, '\n', end - s);
		if (!r || r == s)
			return NULL;
		s = r + 1;
	}
	return s < end ? s : NULL;
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

/* read one character from the SMTP server */
static int smtp_read(void)
{
	if (buf_pos == buf_len) {
		buf_len = conn_read(conn, buf, sizeof(buf));
		buf_pos = 0;
	}
	return buf_pos < buf_len ? (unsigned char) buf[buf_pos++] : -1;
}

/* read a line from the SMTP server; returns a static buffer */
static char *smtp_line(void)
{
	static char dst[LNLEN];
	int i = 0;
	int c;
	while (i < sizeof(dst)) {
		c = smtp_read();
		if (c < 0)
			return NULL;
		dst[i++] = c;
		if (c == '\n')
			break;
	}
	dst[i] = '\0';
	DPRINT(dst, i);
	return dst;
}

/* check the error code of an SMTP reply */
static int smtp_ok(char *s)
{
	return s && atoi(s) < 400;
}

/* check if s is the last line of an SMTP reply */
static int smtp_eoc(char *s)
{
	return isdigit((unsigned char) s[0]) && isdigit((unsigned char) s[1]) &&
			isdigit((unsigned char) s[2]) && isspace((unsigned char) s[3]);
}

static int smtp_xwrite(char *buf, int len)
{
	int nw = 0;
	while (nw < len) {
		int ret = conn_write(conn, buf + nw, len - nw);
		if (ret < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret < 0)
			break;
		DPRINT(buf + nw, ret);
		nw += ret;
	}
	return nw;
}

/* send a command to the SMTP server */
static void smtp_cmd(char *cmd)
{
	conn_write(conn, cmd, strlen(cmd));
	DPRINT(cmd, strlen(cmd));
}

static int ehlo(void)
{
	char *ret;
	if (!smtp_ok(smtp_line()))
		return 1;
	smtp_cmd("EHLO " HOSTNAME "\r\n");
	do {
		ret = smtp_line();
	} while (ret && !smtp_eoc(ret));
	return !smtp_ok(ret);
}

static int login(char *user, char *pass)
{
	char cmd[LNLEN];
	smtp_cmd("AUTH LOGIN\r\n");
	if (!smtp_ok(smtp_line()))
		return 1;
	sprintf(cmd, "%s\r\n", b64(user, strlen(user)));
	smtp_cmd(cmd);
	if (!smtp_ok(smtp_line()))
		return 1;
	sprintf(cmd, "%s\r\n", b64(pass, strlen(pass)));
	smtp_cmd(cmd);
	return !smtp_ok(smtp_line());
}

static int mail_data(struct account *account)
{
	char buf[HDLEN];
	char cmd[LNLEN];
	char *to_hdrs[] = {"to:", "cc:", "bcc:"};
	int i, buflen;
	sprintf(cmd, "MAIL FROM:<%s>\r\n", account->from);
	smtp_cmd(cmd);
	if (!smtp_ok(smtp_line()))
		return 1;
	for (i = 0; i < ARRAY_SIZE(to_hdrs); i++) {
		char *hdr, *end, *s;
		char addr[LNLEN];
		if (!(hdr = hdr_val(to_hdrs[i])))
			continue;
		end = hdr + hdr_len(hdr);
		s = hdr;
		while ((s = cutaddr(addr, s, end - s)) && s < end) {
			char *at = strchr(addr, '@');
			if (at && at > addr && *(at + 1)) {
				sprintf(cmd, "RCPT TO:<%s>\r\n", addr);
				smtp_cmd(cmd);
				if (!smtp_ok(smtp_line()))
					return 1;
			}
		}
	}
	smtp_cmd("DATA\r\n");
	if (!smtp_ok(smtp_line()))
		return 1;
	memcpy(buf, mail, mail_len);
	buflen = mail_len;
	do {
		if (smtp_xwrite(buf, buflen) != buflen)
			return 1;
	} while ((buflen = xread(0, buf, sizeof(buf))) > 0);
	smtp_cmd("\r\n.\r\n");
	if (!smtp_ok(smtp_line()))
		return 1;
	smtp_cmd("QUIT\r\n");
	smtp_line();
	return 0;
}

static struct account *choose_account(void)
{
	char *from = hdr_val("from:");
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
	mail_len = xread(0, mail, sizeof(mail));
	if (mail_len <= 0)
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
	if (mail_data(account))
		goto fail;
	conn_close(conn);
	return 0;
fail:
	conn_close(conn);
	return 1;
}
