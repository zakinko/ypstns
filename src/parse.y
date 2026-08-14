/*	$SNOWRABBIT: parse.y,v $Format:%h %cs %an$ Exp $	*/

%{
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The grammar for ypstns.conf.
 *
 * This is the parse.y that every daemon in the OpenBSD base system has, with
 * the keywords changed.  Keeping it means ypstns.conf behaves the way an
 * administrator on this system already expects a configuration file to behave:
 * the same comment character, the same line continuations, the same $macro
 * expansion, the same "include", the same insistence that a file holding a
 * secret not be readable by everybody, and the same habit of reporting every
 * error in the file rather than stopping at the first.
 *
 * The lexer and the file handling below are the shared boilerplate and are
 * derived from that common ancestor, which is distributed under the ISC
 * licence; see LICENSE.  The grammar itself starts at "grammar :".
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ypstns.h"

TAILQ_HEAD(files, file);
static struct files files = TAILQ_HEAD_INITIALIZER(files);

static struct file {
	TAILQ_ENTRY(file) entry;
	FILE *stream;
	char *name;
	size_t ungetpos;
	size_t ungetsize;
	u_char *ungetbuf;
	int eof_reached;
	int lineno;
	int errors;
} *file, *topfile;

static struct file *pushfile(const char *, int);
static int popfile(void);
static int yyparse(void);
static int yylex(void);
static int yyerror(const char *, ...) __attribute__((__format__(printf, 1, 2)));
static int kw_cmp(const void *, const void *);
static int lookup(char *);
static int igetc(void);
static int lgetc(int);
static void lungetc(int);
static int findeol(void);
static int check_file_secrecy(int, const char *);

TAILQ_HEAD(symhead, sym) symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym) entry;
	int used;
	int persist;
	char *nam;
	char *val;
};

static int symset(const char *, const char *, int);
static char *symget(const char *);

static struct ypstns_conf *conf;
static int errors;

static int add_acl(const char *);

typedef struct {
	union {
		int64_t number;
		char *string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	DOMAIN INTERVAL USER ALLOW ANY INCLUDE ERROR
%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.string>	string

%%

grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file *nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

string		: string STRING			{
			if (asprintf(&$$, "%s %s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf");
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string		{
			char *s = $1;

			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

main		: DOMAIN STRING			{
			if (strlcpy(conf->domain, $2, sizeof(conf->domain)) >=
			    sizeof(conf->domain)) {
				yyerror("domain name too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| INTERVAL NUMBER		{
			/*
			 * Ten seconds is the floor.  Below that the API server
			 * is being polled rather than consulted, and the maps
			 * cannot usefully be any fresher than the ypbind(8)
			 * and libc caching in front of them anyway.
			 */
			if ($2 < 10 || $2 > 86400) {
				yyerror("interval must be between 10 and "
				    "86400 seconds");
				YYERROR;
			}
			conf->interval = (int)$2;
		}
		| USER STRING			{
			free(conf->user);
			conf->user = $2;
		}
		| ALLOW ANY			{
			/*
			 * An empty access list is the loopback only, so this
			 * is the one way to say "the network", and it has to
			 * be said out loud.
			 */
			free(conf->acl);
			conf->acl = NULL;
			conf->nacl = 0;
			conf->local_only = 0;
		}
		| ALLOW STRING			{
			if (!conf->local_only) {
				yyerror("\"allow any\" has already been given");
				free($2);
				YYERROR;
			}
			if (add_acl($2) == -1) {
				yyerror("\"%s\" is not an address or "
				    "address/prefix", $2);
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

%%

/*
 * Parse "192.0.2.0/24", or a bare address, into an address and a mask.
 *
 * Only IPv4: the YP protocol is Sun RPC over IPv4 and libc's yplib will not
 * ask over anything else, so an IPv6 access list entry could never match
 * anything and would be a promise this daemon cannot keep.
 */
static int
add_acl(const char *s)
{
	struct ypstns_acl *grown;
	struct in_addr addr;
	char buf[INET_ADDRSTRLEN + 8];
	char *slash;
	long prefix = 32;

	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return -1;

	if ((slash = strchr(buf, '/')) != NULL) {
		const char *errstr;

		*slash++ = '\0';
		prefix = strtonum(slash, 0, 32, &errstr);
		if (errstr != NULL)
			return -1;
	}
	if (inet_pton(AF_INET, buf, &addr) != 1)
		return -1;

	if ((grown = reallocarray(conf->acl, conf->nacl + 1,
	    sizeof(*grown))) == NULL)
		fatal("reallocarray");
	conf->acl = grown;

	conf->acl[conf->nacl].addr = addr;
	conf->acl[conf->nacl].mask.s_addr = (prefix == 0) ? 0 :
	    htonl(0xffffffffU << (32 - prefix));
	/* Normalise, so that "192.0.2.7/24" means what it plainly says. */
	conf->acl[conf->nacl].addr.s_addr &= conf->acl[conf->nacl].mask.s_addr;
	conf->nacl++;
	return 0;
}

struct keywords {
	const char *k_name;
	int k_val;
};

static int
yyerror(const char *fmt, ...)
{
	va_list ap;
	char *msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatal("yyerror vasprintf");
	va_end(ap);
	logit(LOG_ERR, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return 0;
}

static int
kw_cmp(const void *k, const void *e)
{
	return strcmp(k, ((const struct keywords *)e)->k_name);
}

static int
lookup(char *s)
{
	/* This table has to stay sorted: it is searched with bsearch(3). */
	static const struct keywords keywords[] = {
		{ "allow",	ALLOW },
		{ "any",	ANY },
		{ "domain",	DOMAIN },
		{ "include",	INCLUDE },
		{ "interval",	INTERVAL },
		{ "user",	USER }
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords) / sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	return (p != NULL) ? p->k_val : STRING;
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int expanding;

static int
igetc(void)
{
	int c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return c;
}

static int
lgetc(int quotec)
{
	int c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return EOF;
			return quotec;
		}
		return c;
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake a newline at the end of the file, so that a last line
		 * without one still parses.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return '\n';
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return EOF;
			c = igetc();
		}
	}
	return c;
}

static void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);

		if (p == NULL)
			fatal("lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = (u_char)c;
}

static int
findeol(void)
{
	int c;

	/* Skip to the end of the line, so that parsing can resume there. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return ERROR;
}

static int
yylex(void)
{
	u_char buf[8096];
	u_char *p, *val;
	int quotec, next, c;
	int token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return 0;

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = (u_char *)symget((char *)buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return findeol();
		}
		p = val + strlen((char *)val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc(*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return 0;
			if (c == '\n') {
				file->lineno++;
				continue;
			}
			if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return 0;
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return findeol();
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			*p++ = c;
		}
		yylval.v.string = strdup((char *)buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
		return STRING;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x == ',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum((char *)buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr != NULL) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return findeol();
			}
			return NUMBER;
		}
nodigits:
		while (p > buf + 1)
			lungetc(*--p);
		c = *--p;
		if (c == '-')
			return c;
	}

#define allowed_in_string(x)						\
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' &&		\
	x != '{' && x != '}' && x != '<' && x != '>' &&			\
	x != '!' && x != '=' && x != '#' && x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup((char *)buf)) == STRING) {
			if ((yylval.v.string = strdup((char *)buf)) == NULL)
				fatal("yylex: strdup");
		}
		return token;
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return 0;
	return c;
}

/*
 * Refuse to read a configuration file anybody else can read.
 *
 * This file names no secrets of its own - the API token is in stns.conf, not
 * here - but it is the same check every other daemon on the system makes, and
 * an administrator who adds one later should not have to discover that this
 * particular file was the exception.
 */
static int
check_file_secrecy(int fd, const char *fname)
{
	struct stat st;

	if (fstat(fd, &st)) {
		log_warn_errno("cannot stat %s", fname);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		logit(LOG_ERR, "%s: owner not root or current user", fname);
		return -1;
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		logit(LOG_ERR, "%s: group writable or world read/writable",
		    fname);
		return -1;
	}
	return 0;
}

static struct file *
pushfile(const char *name, int secret)
{
	struct file *nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn_errno("calloc");
		return NULL;
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn_errno("strdup");
		free(nfile);
		return NULL;
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn_errno("cannot open %s", nfile->name);
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn_errno("malloc");
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return nfile;
}

static int
popfile(void)
{
	struct file *prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;

	return (file != NULL) ? 0 : EOF;
}

int
parse_config(const char *filename, struct ypstns_conf *xconf)
{
	struct sym *sym, *next;

	conf = xconf;
	memset(conf, 0, sizeof(*conf));
	conf->interval = YPSTNS_DEFAULT_INTERVAL;
	conf->local_only = 1;
	if ((conf->user = strdup(YPSTNS_USER)) == NULL)
		fatal("strdup");

	if ((file = pushfile(filename, 1)) == NULL)
		return -1;
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Warn about macros that were set on the command line and never used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((verbose > 1) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not used\n",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	/*
	 * The domain is the one thing with no sensible default.  A YP client
	 * asks for a named domain and a server that guessed the name would
	 * simply never be asked anything.
	 */
	if (conf->domain[0] == '\0') {
		logit(LOG_ERR, "%s: no domain given", filename);
		errors++;
	}

	if (errors) {
		free_config(conf);
		return -1;
	}
	return 0;
}

void
free_config(struct ypstns_conf *xconf)
{
	free(xconf->user);
	free(xconf->acl);
	memset(xconf, 0, sizeof(*xconf));
}

static int
symset(const char *nam, const char *val, int persist)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return 0;
		free(sym->nam);
		free(sym->val);
		TAILQ_REMOVE(&symhead, sym, entry);
		free(sym);
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return -1;

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return -1;
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return -1;
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return 0;
}

int
cmdline_symset(char *s)
{
	char *sym, *val;
	int ret;

	if ((val = strrchr(s, '=')) == NULL)
		return -1;
	sym = strndup(s, val - s);
	if (sym == NULL)
		fatal("%s: strndup", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return ret;
}

static char *
symget(const char *nam)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return sym->val;
		}
	}
	return NULL;
}
