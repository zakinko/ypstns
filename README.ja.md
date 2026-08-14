# ypstns

[English](README.md)

[STNS](https://stns.jp) のディレクトリを、YP として **OpenBSD** に配信します。

```text
getpwnam(3) ─▶ libc ─▶ ypbind(8) ─▶ ypstns ─▶ STNS API
```

## なぜ YP なのか

OpenBSD には `nsswitch.conf` が無く、他に差し込めるディレクトリバックエンドも
ありません。あるのは YP だけです。libc は昔から YP を話しますし、
`/etc/master.passwd` に `+` 行があれば `getpwnam(3)` は YP を見にいきます。

これはこのプロジェクトの都合ではなく、base に `ypldap(8)` がいるのと同じ理由
です。誰も YP を望んではいません。壁に空いている穴が YP だった、というだけの
ことです。

そこで `ypstns` は、STNS API サーバーから応答する YP サーバーであり、
`ypldap(8)` と同じ作りになっています。理由も同じです。

## 仕組み

プロセスは 2 つです。

**特権側**はマップを保持して RPC に応答します。root のままなのは、YP
サーバーがそうせざるを得ないからです。`master.passwd.byname` は予約ポートから
の要求にのみ返すもので、そもそもその区別ができることが `/etc/master.passwd`
が `/etc/passwd` と別に存在する理由です。この側は何もパースしません。RPC
のデコードは libc のもので、マップの本文は別のプロセスが組み立てます。

**fetcher** は `_ypstns` として、`unveil(2)` と `pledge(2)` の内側で動き、HTTP
を行い、完成したマップエントリをパイプで送り返します。ネットワークに触れるのは
このプロセスだけです。

どちらも相手の仕事はできません。それが狙いです。

更新は括られています。エントリは 2 つ目のマップ集合に溜まり、更新が完了したとき
だけ入れ替わります。途中で失敗した取得は、前のディレクトリを配信したまま残す
ということです。中途半端な `passwd` マップは、ほとんどのユーザーがログイン
できないマシンになります。同じ理由で、最初の取得が成功するまで `portmap(8)`
への登録も行いません。起動途中に `YP_NOMAP` を返す YP サーバーは、クライアント
に「`passwd.byname` は存在しない」と教えてしまい、それを信じたクライアントは
誰もログインできないマシンになるからです。

## マップ

| | |
| --- | --- |
| `passwd.byname`, `passwd.byuid` | ディレクトリ。パスワード欄は `*` にマスク |
| `master.passwd.byname`, `master.passwd.byuid` | 同じものにハッシュ付き。**予約ポートからのみ** |
| `group.byname`, `group.bygid` | |
| `netid.byname` | ユーザーが持つ全 gid |
| `ypservers` | このマシン |

`YPPROC_XFR` と `YPPROC_CLEAR` は拒否します。どちらもマップ転送が存在する世界の
ものですが、ここには push したり開き直したりする dbm ファイルがありません
（マップはタイマーで HTTP API から来ます）。応じてしまうと `yppush(8)`
に、実際には起きていない成功を報告させることになります。スレーブサーバーも
ありません。

## インストール

ports から:

```sh
cd /usr/ports/net/ypstns && doas make install
```

または手動で。必要なのは libcurl だけです。

```sh
doas pkg_add curl
git clone --recursive https://github.com/zakinko/ypstns.git
cd ypstns
make
doas make install
```

ビルドは `bsd.prog.mk` なので、`parse.y`、man ページ、`DESTDIR`、インストール
モードはすべて ports ツリーが期待するとおりに処理されます。

## セットアップ

`ypstns` はサーバー側だけです。クライアント側は base の `ypbind(8)` で、
マシンにそれを見るよう教える必要があります。

```sh
doas sh -c 'echo stns > /etc/defaultdomain'
doas domainname stns
doas sh -c "echo '+:*::::::::' >> /etc/master.passwd"
doas sh -c "echo '+:*::' >> /etc/group"
doas pwd_mkdb /etc/master.passwd
```

`+` 行こそが libc に YP を問い合わせさせるものであり、ファイル中の位置が検索順
になります。ローカルアカウントが先に来るので、API サーバーが落ちていても
そちらは動き続けます。

次に設定ファイル 2 つです。`stns.conf` は API クライアントの設定で、Linux
ホストや `nss_stns` の動くマシンからそのままコピーできます。`ypstns.conf`
はこのデーモン固有で、他のすべての OpenBSD デーモンと同じ文法です。

```sh
doas mkdir -p /etc/stns/client
doas cp /usr/local/share/examples/ypstns/stns.conf /etc/stns/client/stns.conf
doas cp /usr/local/share/examples/ypstns/ypstns.conf /etc/ypstns.conf
doas chmod 600 /etc/ypstns.conf /etc/stns/client/stns.conf
doas $EDITOR /etc/ypstns.conf
```

パーサーが何を読み取ったかを確認します。これに特権は要りません。そこが肝心です。

```sh
ypstns -n -f /etc/ypstns.conf
```

そして起動します。`portmap(8)` が先です。`ypstns` はそこに登録するので、
無ければ何も配信できません。

```sh
doas rcctl enable portmap ypstns ypbind
doas rcctl start portmap ypstns ypbind
```

## 確認

```sh
ypwhich
ypcat passwd
ypmatch alice passwd
getent passwd alice
id alice
```

`ypcat(1)` と `ypmatch(1)` はサーバーに直接聞き、`getent(1)` は libc
を通ります。何かおかしいとき最初に見るべきはこの違いです。前者だけ答えて後者が
答えないなら、原因はこのデーモンではなく `+` 行か `ypbind(8)` です。

`yppoll -h localhost passwd.byname` はマップの order number を表示します。ここ
ではディレクトリを最後に取得した時刻であり、配信中のデータがどれだけ古いかを
知れる唯一の場所です。

## セキュリティ

**既定ではネットワークに配信しません。** このマシンと、`ypstns.conf` の
`allow` で挙げたものだけです。`ypstns` はたいてい、それを消費する `ypbind(8)`
の隣で動きます。ネットワークから到達できる YP サーバーは、ドメイン名を当てられる
相手にディレクトリ全体を渡してしまいます。ドメイン名は秘密ではありませんし、
昔からそうでした。`allow any` でチェックを外せますが、そのためにわざわざ言葉で
書かせています。

**ハッシュには予約ポートが要ります。** `master.passwd.*` は 1024
番未満のポートからの要求にのみ応答します。`ypserv(8)` も同じ区別をしており、
これがクライアントマシン上の一般ユーザーとディレクトリ内の全ハッシュの間にある
唯一のものです。

**fetcher は閉じ込められています。** `unveil(2)` でファイルシステムはリゾルバ
設定・トラストストア・`stns.conf` が指定する TLS 資材だけになり、`pledge(2)`
で `stdio rpath inet dns` になります。サーバー側は `stdio inet proc`
です。配信を始める時点で二度とファイルを開くことはなく、`proc` が買っているのは
fetcher にシグナルを渡す `kill(2)` ただ 1 つです。

**そのため `stns.conf` の 2 つの設定はデーモンには効きません。**
`query_wrapper` はコマンドを実行しますが fetcher に `exec` promise
は無いので、最初の更新でプロセスを abort させる代わりに、ログを 1
行残して無視します。オンディスクキャッシュも無効化します。メモリ上にあるものの
2 つ目の、より古いコピーのために `wpath cpath` を渡す価値はありません。どちらも
pledge の無い別プログラムである `stns-key-wrapper` には効いたままです。

**YP は 1985 年のプロトコル**で、まともな認証も暗号化もありません。上に書いた
ことはすべて、その事実の中で最善を尽くしているだけで、直しているわけでは
ありません。自分の `ypbind(8)` とループバックで話すマシンには妥当な構成ですが、
制御できないネットワークを越えるなら不適切です。

## SSH 鍵

YP とは無関係です。`sshd` はコマンドを実行して出力を読むだけです。

```text
AuthorizedKeysCommand     /usr/local/bin/stns-key-wrapper
AuthorizedKeysCommandUser nobody
```

`nss_stns` や `ldapstns` がインストールするのと同じプログラムで、どのシステム
でも動かせるので [libstns](https://github.com/zakinko/libstns) にあります。

## リロード

`rcctl reload ypstns` は `SIGHUP` を送り、`interval` を待たずにディレクトリを
取り直します。

設定は**再読み込みしません**。サーバー側は「二度とファイルを開かない」と
pledge しており、fetcher は `stns.conf` をもう一度読むための権限を既に手放して
います。それこそが両者の目的です。それ以外の変更には `rcctl restart ypstns`
が答えです。

## テスト

```sh
make test        # マップ処理と設定ファイル文法
make external    # 同梱コードが external/MANIFEST と一致するか
make ident       # サンプル設定の ident 行が git archive で展開されるか
```

`make test` は何も要りません。デーモンが答えるあらゆる lookup は `maps.c`
を通り、読むあらゆる設定は `parse.y` を通ります。

`make integration` は root が要り、実物を起動します。壊れ方が違うので 3
通りの聞き方をします — `tests/yp_client.c` はサーバーに直接 YPPROG を話し、
`ypmatch(1)` と `ypcat(1)` は `ypbind(8)` を通り、`getent(1)` と `id(1)` は
libc を通ります。マップが本物の lookup に耐える形かを示せるのは最後のものだけ
です。「他の場所でしか壊れない」ものも見ています。**HTTPS** での取得 —
`unveil(2)` のリストがトラストストアを残せているかを確認できる唯一の手段です —、
更新タイマーの発火、API サーバーが落ちても最後の正常なマップを配信し続けること、
そしてこのマシン自身の外部アドレスから問い合わせるアクセスリスト（ループバック
からはどんな設定でも答えてしまうので）。

CI は OpenBSD の VM で一式を実行し、あわせて `mandoc -T lint`、ステージ
インストールと ports の packing list の突き合わせ、rc スクリプトの `ksh -n`
も行います。

## ライセンス

BSD-2-Clause です。`parse.y` の字句解析とファイル処理は、すべての OpenBSD
デーモンが共有する `parse.y` から派生しており、そちらは ISC
です。`LICENSE` を参照してください。

## 関連

| | |
| --- | --- |
| [libstns](https://github.com/zakinko/libstns) | この下にある STNS API クライアント。`external/` に vendor |
| [nss_stns](https://github.com/zakinko/nss_stns) | NetBSD・FreeBSD・DragonFly 向け。`nsswitch(5)` モジュール |
| [ldapstns](https://github.com/zakinko/ldapstns) | macOS 向け。Open Directory の裏の LDAPv3 サーバー |
