# SPDX-License-Identifier: BSD-2-Clause
#
# An OpenBSD port for ypstns, laid out the way /usr/ports expects so that it
# can be dropped into net/ypstns and built there.
#
# The distfile is a release tarball rather than the archive GitHub generates
# from a tag: libstns is a submodule, and a GitHub tag tarball contains the
# submodule's directory and none of its contents, which would leave the port
# with nothing to compile.  The release tarball is made with the submodule
# unpacked in place, and distinfo below is generated from it in the usual way
# with "make makesum".

COMMENT =	serve an STNS directory to OpenBSD as YP

V =		0.1.0
DISTNAME =	ypstns-${V}
CATEGORIES =	net

HOMEPAGE =	https://github.com/zakinko/ypstns
MAINTAINER =	zakinko <zakinko@snowrabbit.org>

MASTER_SITES =	https://github.com/zakinko/ypstns/releases/download/v${V}/

# BSD-2-Clause, with MIT for the bundled parsers under libstns/external.
PERMIT_PACKAGE =	Yes

WANTLIB =	c curl util

LIB_DEPENDS =	net/curl

# The build is a plain bsd.prog.mk one; LOCALBASE is the only thing it needs
# told, and it takes DESTDIR for the fake install.
MAKE_FLAGS =	LOCALBASE=${LOCALBASE}
FAKE_FLAGS =	DESTDIR=${WRKINST}

# The daemon itself cannot be tested here - it wants root, a YP domain and a
# portmap(8) to register with - but the configuration grammar and the map
# handling every lookup goes through both can be.
TEST_TARGET =	test

NO_TEST =	No

.include <bsd.port.mk>
