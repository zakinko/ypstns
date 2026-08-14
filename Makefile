#	$SNOWRABBIT: Makefile,v $Format:%h %cs %an$ Exp $
#
# SPDX-License-Identifier: BSD-2-Clause
#
# ypstns - serve an STNS directory to OpenBSD as YP.
#
# Built with bsd.prog.mk, so that everything an OpenBSD port expects is already
# arranged: the yacc rule for parse.y, the manual pages, DESTDIR, the install
# modes, WARNINGS=Yes.  Run it with make(1); nothing here works with GNU make
# and nothing needs to.
#
# The STNS API client - the configuration, the HTTP, the cache, the circuit
# breaker and the marshalling - is in src/ beside the daemon rather than shared
# from anywhere.  It was a library for a while and is not one any more: nothing
# linked it, and an upstream for two programs cost a repository, a manifest and
# a commit in three places to change one line.  The same code is in nss_stns
# and in ldapstns, each owning its copy the way a port owns what it builds.

PROG=		ypstns
SRCS=		ypstns.c parse.y stnsclient.c maps.c yp.c yp_xdr.c
MAN=		ypstns.8 ypstns.conf.5 login_stns.8 stns-key-wrapper.8

PARSON=		${.CURDIR}/external/mit/parson
TOMLC99=	${.CURDIR}/external/mit/tomlc99
LOCALBASE?=	/usr/local
SYSCONFDIR?=	/etc

# This is a port, not part of the base system, so everything it installs lives
# under LOCALBASE - bar the rc.d script, which ports place in /etc/rc.d through
# @rcscript, and the configuration, which hier(7) puts in /etc because it
# describes how this machine resolves its own users.
BINDIR?=	${LOCALBASE}/sbin
MANDIR?=	${LOCALBASE}/man/man

# stns-key-wrapper goes in /usr/local/bin rather than beside the daemon: it is
# run by sshd on behalf of a user, not by root, and hier(7) puts that sort of
# thing under LOCALBASE.
WRAPPERDIR?=	${LOCALBASE}/bin
EXAMPLESDIR?=	${LOCALBASE}/share/examples/ypstns
RCDIR?=		/etc/rc.d

# The API client, which lives here rather than anywhere shared.
SRCS+=		stns_config.c stns_request.c stns_entry.c stns_lookup.c stns_list.c
SRCS+=		stns_crypt.c
SRCS+=		parson.c toml.c

.PATH:		${.CURDIR}/src ${.CURDIR}/man
.PATH:		${PARSON} ${TOMLC99}

CFLAGS+=	-I${.CURDIR}/src -I${.OBJDIR} \
		-I${PARSON} \
		-I${TOMLC99} \
		-I${LOCALBASE}/include \
		-DSTNS_PRODUCT=\"ypstns\" \
		-DSTNS_CONFDIR=\"${SYSCONFDIR}\"

# Every line the library logs is prefixed with STNS_PRODUCT, so an
# administrator reading /var/log/daemon knows which of the three STNS clients
# is complaining.  STNS_CONFDIR is /etc here rather than under LOCALBASE:
# stns.conf describes how the machine resolves its own users, which hier(7)
# puts in /etc, and it is where a file copied from another host already is.

WARNINGS=	Yes
CDIAGFLAGS+=	-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes \
		-Wpointer-arith -Wno-unused-parameter

LDADD+=		-L${LOCALBASE}/lib -lcurl -lutil
DPADD+=		${LIBUTIL}

# bsd.prog.mk knows how to build exactly one program, and there are three here.
# The others are tiny, share every object the first uses, and one of them is
# the same program nss_stns and ldapstns install - so rather than a subdirectory and a
# bsd.subdir.mk for the sake of one link line, it is hung off all: and
# install: below.
WRAPPER=	stns-key-wrapper

# The BSD authentication style.  login(1) looks for it by an absolute path
# fixed in libc, /usr/libexec/auth/login_<style>, which is outside LOCALBASE
# and so somewhere a port may not write.  It is installed under LOCALBASE and
# symlinked into place by the administrator; login_stns(8) says so.
LOGIN=		login_stns
AUTHDIR?=	${LOCALBASE}/libexec/auth

all: ${WRAPPER} ${LOGIN}

${WRAPPER}:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/src/stns_key_wrapper.c \
		${.CURDIR}/src/stns_config.c \
		${.CURDIR}/src/stns_request.c \
		${.CURDIR}/src/stns_entry.c \
		${.CURDIR}/src/stns_lookup.c \
		${.CURDIR}/src/stns_list.c \
		${PARSON}/parson.c \
		${TOMLC99}/toml.c \
		${LDADD}

# bsd.prog.mk and bsd.man.mk install into their directories but do not create
# them: in the base tree those directories are always already there.  A staged
# install into an empty DESTDIR is the case where they are not, which is both
# how a port builds and how tests/check_plist.sh checks the packing list.
# Shares every object the daemon uses, and links against the same library.
${LOGIN}:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/src/login_stns.c \
		${.CURDIR}/src/stns_config.c \
		${.CURDIR}/src/stns_request.c \
		${.CURDIR}/src/stns_entry.c \
		${.CURDIR}/src/stns_lookup.c \
		${.CURDIR}/src/stns_list.c \
		${.CURDIR}/src/stns_crypt.c \
		${PARSON}/parson.c \
		${TOMLC99}/toml.c \
		${LDADD}

beforeinstall:
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${BINDIR}
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${MANDIR}5
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${MANDIR}8
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${EXAMPLESDIR}
	${INSTALL} -o root -g wheel -m 644 ${.CURDIR}/ypstns.conf.example \
		${DESTDIR}${EXAMPLESDIR}/ypstns.conf
	${INSTALL} -o root -g wheel -m 644 ${.CURDIR}/stns.conf.example \
		${DESTDIR}${EXAMPLESDIR}/stns.conf
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${WRAPPERDIR}
	${INSTALL} -o root -g bin -m 555 ${WRAPPER} ${DESTDIR}${WRAPPERDIR}/${WRAPPER}
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${AUTHDIR}
	${INSTALL} -o root -g auth -m 4555 ${LOGIN} ${DESTDIR}${AUTHDIR}/${LOGIN}
	${INSTALL} -d -o root -g wheel -m 755 ${DESTDIR}${RCDIR}
	${INSTALL} -o root -g wheel -m 555 ${.CURDIR}/etc/rc.d/ypstns \
		${DESTDIR}${RCDIR}/ypstns

# The daemon cannot be run here - it needs root, portmap(8) and a domain name -
# so what "make test" checks is everything below that: the configuration
# grammar, and the map handling that every lookup goes through.
test: maps_test stns_test stns_crypt_test ${PROG}
	./maps_test
	./stns_test
	./stns_crypt_test
	sh ${.CURDIR}/tests/check_parse.sh ./${PROG}

maps_test:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/tests/maps_test.c ${.CURDIR}/src/maps.c ${LDADD}

# The API client's own tests.  maps_test and check_parse.sh cover what this
# daemon does with what it fetched; these cover the fetching, and they are the
# half that is the same in all three STNS clients - so the half no daemon test
# of any of them exercises directly.
CLIENT_SRCS=	${.CURDIR}/src/stns_config.c ${.CURDIR}/src/stns_request.c \
		${.CURDIR}/src/stns_entry.c ${.CURDIR}/src/stns_lookup.c \
		${.CURDIR}/src/stns_list.c ${.CURDIR}/src/stns_crypt.c \
		${PARSON}/parson.c ${TOMLC99}/toml.c

stns_test:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/tests/stns_test.c ${CLIENT_SRCS} ${LDADD}

stns_crypt_test:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/tests/crypt_test.c ${CLIENT_SRCS} ${LDADD}

# Runs an authentication style the way authenticate(3) does, for
# tests/integration.sh: the interface is file descriptor 3 and there is no
# shell incantation that provides one which is both readable and writable.
auth_client:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} ${.CURDIR}/tests/auth_client.c

# Speaks YPPROG to a running daemon, for tests/integration.sh.  It links the
# same yp_xdr.c the server does, which is the point: if the encoding were
# wrong in a way both halves agreed on, ypmatch(1) would catch it, and
# integration.sh runs that too.
yp_client:
	${CC} ${CFLAGS} ${CDIAGFLAGS} -o ${.TARGET} \
		${.CURDIR}/tests/yp_client.c ${.CURDIR}/src/yp_xdr.c ${LDADD}

# The daemon, actually running.  Needs root, and says so rather than failing
# obscurely; see the comment at the top of the script.
integration: ${PROG} ${LOGIN} yp_client auth_client
	sh ${.CURDIR}/tests/integration.sh

# Check that the ident lines in the sample configurations survive git archive.
ident:
	sh ${.CURDIR}/tests/check_ident.sh

# Check the bundled third party code against external/MANIFEST.  Add
# --upstream and it also asks github whether the recorded revisions are still
# current, which needs the network.
external:
	sh ${.CURDIR}/tests/check_external.sh

CLEANFILES+=	${WRAPPER} ${LOGIN} maps_test stns_test stns_crypt_test \
		yp_client auth_client

.include <bsd.prog.mk>
