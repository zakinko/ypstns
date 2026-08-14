# ypstns

[日本語](README.ja.md)

Serve an [STNS](https://stns.jp) directory to **OpenBSD**, as YP.

```text
getpwnam(3) ─▶ libc ─▶ ypbind(8) ─▶ ypstns ─▶ STNS API
```

## Why YP

OpenBSD has no `nsswitch.conf` and no pluggable directory backend of any other
kind. What it has is YP, which libc has spoken since forever and which
`getpwnam(3)` consults whenever `/etc/master.passwd` holds a `+` line.

That is not an accident of this project; it is the same reason `ypldap(8)` is in
the base system. Nobody wanted YP. YP is the socket the wall provides.

So `ypstns` is a YP server that answers out of an STNS API server, built the way
`ypldap(8)` is built — and for the same reasons.

## How it works

Two processes.

The **privileged** one holds the maps and answers the RPC. It stays root
because a YP server has to: `master.passwd.byname` is served only to a client on
a reserved port, and being able to make that distinction at all is why
`/etc/master.passwd` exists separately from `/etc/passwd`. It parses nothing —
the RPC decoding is libc's, and the text of the maps is assembled elsewhere.

The **fetcher** runs as `_ypstns`, behind `unveil(2)` and `pledge(2)`, does the
HTTP, and sends finished map entries back over a pipe. It is the only process
here that touches the network.

Neither can do the other's job, which is the point.

A refresh is bracketed: entries accumulate in a second set of maps and are only
swapped in when the update completes. A fetch that fails halfway leaves the
previous directory serving — and half a `passwd` map is a machine most of its
users cannot log in to. For the same reason the daemon does not register with
`portmap(8)` until the first fetch has succeeded: a YP server that answers
`YP_NOMAP` while it is starting tells its clients `passwd.byname` does not
exist, and a client that believes that is a machine nobody can log in to at all.

## Maps

| | |
| --- | --- |
| `passwd.byname`, `passwd.byuid` | the directory, password field masked to `*` |
| `master.passwd.byname`, `master.passwd.byuid` | the same, with the hash — **reserved port only** |
| `group.byname`, `group.bygid` | |
| `netid.byname` | every group id a user holds |
| `ypservers` | this machine |

`YPPROC_XFR` and `YPPROC_CLEAR` are refused. Both belong to a world with map
transfers in it, and there is no dbm file here to push or reopen — the maps come
from an HTTP API on a timer, so honouring them would have `yppush(8)` report a
success that did not happen. There are no slave servers.

## Installing

From the port:

```sh
cd /usr/ports/net/ypstns && doas make install
```

or by hand — only libcurl is needed:

```sh
doas pkg_add curl
git clone --recursive https://github.com/zakinko/ypstns.git
cd ypstns
make
doas make install
```

The build is `bsd.prog.mk`, so `parse.y`, the manual pages, `DESTDIR` and the
install modes are all handled the way the ports tree expects.

## Setting it up

`ypstns` is the server half only. The client half is `ypbind(8)`, in the base
system, and the machine has to be told to consult it:

```sh
doas sh -c 'echo stns > /etc/defaultdomain'
doas domainname stns
doas sh -c "echo '+:*::::::::' >> /etc/master.passwd"
doas sh -c "echo '+:*::' >> /etc/group"
doas pwd_mkdb /etc/master.passwd
```

The `+` lines are what make libc ask YP at all, and their position in the file
is their position in the search — local accounts come first and keep working
when the API server does not.

Then the two configuration files. `stns.conf` is the API client and can be
copied verbatim from a Linux host or from a machine running `nss_stns`;
`ypstns.conf` is this daemon's own, in the syntax every other OpenBSD daemon
uses:

```sh
doas mkdir -p /etc/stns/client
doas cp /usr/local/share/examples/ypstns/stns.conf /etc/stns/client/stns.conf
doas cp /usr/local/share/examples/ypstns/ypstns.conf /etc/ypstns.conf
doas chmod 600 /etc/ypstns.conf /etc/stns/client/stns.conf
doas $EDITOR /etc/ypstns.conf
```

Check what the parser made of it — this needs no privileges, which is the
point:

```sh
ypstns -n -f /etc/ypstns.conf
```

Then start everything. `portmap(8)` has to be first; `ypstns` registers with it
and can serve nothing if it is absent:

```sh
doas rcctl enable portmap ypstns ypbind
doas rcctl start portmap ypstns ypbind
```

## Checking it

```sh
ypwhich
ypcat passwd
ypmatch alice passwd
getent passwd alice
id alice
```

`ypcat(1)` and `ypmatch(1)` ask the server directly; `getent(1)` goes through
libc. That distinction is the first thing to reach for when something is wrong:
an answer from the first and not the second means the `+` lines or `ypbind(8)`,
not this daemon.

`yppoll -h localhost passwd.byname` prints the map's order number, which here is
the time the directory was last fetched — the one place to see how stale what is
being served actually is.

## Security

**The directory is not served to the network by default.** Only this machine,
plus whatever `allow` names in `ypstns.conf`. `ypstns` is nearly always run
beside the `ypbind(8)` that consumes it, and a YP server reachable from the
network hands the whole directory to anybody who can guess the domain name —
which is not a secret and never was. `allow any` turns the check off, and has to
be written out in words for that reason.

**The hashes need a reserved port.** `master.passwd.*` is answered only when the
request came from a port below 1024. `ypserv(8)` makes the same distinction, and
it is the only thing between an ordinary user on a client machine and every hash
in the directory.

**The fetcher is confined.** `unveil(2)` reduces the filesystem to the resolver
configuration, the trust store and whatever TLS material `stns.conf` names;
`pledge(2)` reduces it to `stdio rpath inet dns`. The server half is pledged to
`stdio inet proc` — by the time it starts serving it will never open a file
again, and the only thing `proc` buys it is the `kill(2)` that passes a signal
on to the fetcher.

**Two settings in `stns.conf` therefore do not apply to the daemon.**
`query_wrapper` runs a command and the fetcher has no `exec` promise, so it is
ignored with a line in the log rather than aborting the process at the first
refresh; and the on-disk cache is turned off, because a second staler copy of
something already in memory is not worth `wpath cpath`. Both still apply to
`stns-key-wrapper`, which is a separate program with no pledge.

**YP is a protocol from 1985** with no authentication worth the name and no
encryption at all. Everything above is making the best of that, not fixing it.
It is a reasonable arrangement for a machine talking to its own `ypbind(8)` over
the loopback and a poor one across a network you do not control.

## Passwords

`ypstns` answers who somebody is. Whether a password is theirs is a separate
question on OpenBSD, asked through BSD authentication, and `login_stns` answers
it — for `login(1)`, `su(1)`, `sshd` and everything else, because they all call
`authenticate(3)` and it all goes the same way.

```sh
doas ln -s /usr/local/libexec/auth/login_stns /usr/libexec/auth/login_stns
```

```text
# /etc/login.conf
stns:\
	:auth=passwd,stns:\
	:tc=default:
```

`passwd` first, and the order is the whole of the safety: a local account is
answered out of `master.passwd` without the API being asked, so root can still
log in when the directory is unreachable.

The comparison happens on the machine — only the hash is fetched, and the API
is never sent a password. `$6$`, `$5$` and `$2b$` all work; the first two are
implemented in `external/bsd/libstns` because `crypt(3)`
here does bcrypt and nothing else, while STNS directories almost always carry
SHA-512 crypt. See `login_stns(8)`.

## SSH keys

Nothing to do with YP — `sshd` runs a command and reads its output:

```text
AuthorizedKeysCommand     /usr/local/bin/stns-key-wrapper
AuthorizedKeysCommandUser nobody
```

This is the same program `nss_stns` and `ldapstns` install; it lives in
`external/bsd/libstns` because every system can run it.

## Reloading

`rcctl reload ypstns` sends `SIGHUP`, which fetches the directory again at once
rather than waiting out `interval`.

It does **not** re-read the configuration. The server half has pledged not to
open a file again, and the fetcher gave up the privileges it would need to read
`stns.conf` a second time — which is the point of both. `rcctl restart ypstns`
is the answer for anything else.

## Tests

```sh
make test        # the map handling, and the configuration grammar
make external    # the vendored copies still match external/MANIFEST
make ident       # the sample configs' ident lines survive git archive
```

`make test` needs nothing: every lookup the daemon will ever answer goes through
`maps.c` and every configuration it will ever read goes through `parse.y`.

`make integration` needs root, and starts the real thing. It asks three ways,
because they fail differently — `tests/yp_client.c` speaks YPPROG straight to
the server, `ypmatch(1)` and `ypcat(1)` go through `ypbind(8)`, and `getent(1)`
and `id(1)` go through libc, which is the only one that shows the maps are
shaped the way a real lookup needs. It also covers the things that only break
somewhere else: fetching over **HTTPS**, which is the only check that the
`unveil(2)` list leaves the trust store reachable; the refresh timer firing; the
API server going away and the last good maps being served anyway; and the access
list, asked from this machine's own external address, since from the loopback
every configuration answers.

CI runs the lot in an OpenBSD VM, along with `mandoc -T lint`, a staged install
diffed against the port's packing list, and `ksh -n` on the rc script.

## Licence

BSD-2-Clause. The lexer and file handling in `parse.y` are derived from the
shared `parse.y` every OpenBSD daemon has, which is ISC. See `LICENSE`.

## See also

| | |
| --- | --- |
| `external/bsd/libstns` | the STNS API client underneath this, vendored in |
| [nss_stns](https://github.com/zakinko/nss_stns) | the same thing for NetBSD, FreeBSD and DragonFly, as an `nsswitch(5)` module |
| [ldapstns](https://github.com/zakinko/ldapstns) | the same thing for macOS, as an LDAPv3 server behind Open Directory |
