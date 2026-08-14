# SPDX-License-Identifier: BSD-2-Clause
#
# An OpenBSD port for ypstns, laid out the way /usr/ports expects so that it
# can be dropped into net/ypstns and built there.
#
# The distfile is the archive GitHub generates from a tag.  libstns is
# vendored into the repository under external/ rather than being a submodule,
# precisely so that this can be an ordinary GH_ port with nothing to explain -
# a tag tarball carries a submodule's directory and none of its contents.

COMMENT =	serve an STNS directory to OpenBSD as YP

V =		0.1.0
CATEGORIES =	net

HOMEPAGE =	https://github.com/zakinko/ypstns
MAINTAINER =	zakinko <zakinko@snowrabbit.org>

GH_ACCOUNT =	zakinko
GH_PROJECT =	ypstns
GH_TAGNAME =	v${V}

# BSD-2-Clause, with MIT for the bundled parsers under external/mit.
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
