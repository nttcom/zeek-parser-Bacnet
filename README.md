# Zeek-Parser-Bacnet

English is [here](https://github.com/nttcom/zeek-parser-Bacnet/blob/main/README_en.md)

## 概要

Zeek-Parser-BacnetとはBacnetを解析できるZeekプラグインです。

## インストール

### パッケージマネージャーによるインストール

このプラグインは[Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)用のパッケージとして提供されています。

以下のコマンドを実行することで、本プラグインは利用可能になります。

```
zkg refresh
zkg install icsnpp-bacnet
zkg install zeek-parser-Bacnet
```

### マニュアルインストール

本プラグインを利用する前に、Zeekがインストールされていることを確認します。
```
# Zeekのチェック
~$ zeek -version
zeek version 5.0.0

# 本マニュアルではZeekのパスが以下であることを前提としています。
~$ which zeek
/usr/local/zeek/bin/zeek
```

本リポジトリをローカル環境に `git clone` します。
```
~$ git clone https://github.com/nttcom/zeek-parser-Bacnet.git
```

## 使い方

### パッケージマネージャーによるインストールの場合

以下のように本プラグインを使うことで `bacnet.log` が生成されます。

```
zeek -Cr /usr/local/zeek/var/lib/zkg/clones/package/zeek-parser-Bacnet/testing/Traces/test.pcap zeek-parser-Bacnet
```

### マニュアルインストールの場合

Zeekファイルを以下のパスにコピーします。
```
~$ cd ~/zeek-parser-Bacnet/scripts/
~$ cp bacnet_ip.zeek /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek
~$ cp consts_bacnet_ip.zeek /usr/local/zeek/lib/zeek/plugins/packages/icsnpp-bacnet/scripts/consts.zeek
```

Zeekプラグインをインポートします。
```
~$ tail /usr/local/zeek/share/zeek/site/local.zeek
...省略...
@load icsnpp-bacnet
```

本プラグインを使うことで `bacnet.log` が生成されます。
```
~$ cd ~/zeek-parser-Bacnet/testing/Traces
~$ zeek -Cr test.pcap /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek
```

## ログのタイプと説明
本プラグインはbacbetの全ての関数を監視して`bacnet.log`として出力します。

| フィールド | タイプ | 説明 |
| --- | --- | --- |
| ts | time | 最初に通信した時のタイムスタンプ |
| uid | string | ユニークID |
| id.orig_h | addr | 送信元IPアドレス |
| id.orig_p | port | 送信元ポート番号 |
| id.resp_h | addr | 宛先IPアドレス |
| id.resp_p | port | 宛先ポート番号 |
| proto | enum | トランスポート層プロトコル |
| pdu_service | string | PDUサービスの名前 |
| pdu_type | string | PDUタイプ |
| obj_type | string | オブジェクトタイプ  |
| number | int | パケット出現回数 |
| ts_end | time | 最後に通信した時のタイムスタンプ |

`bacnet.log` の例は以下のとおりです。
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	bacnet
#open	2023-08-22-02-33-43
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	pdu_service	pdu_type	obj_type	number	ts_end
#types	time	string	addr	port	addr	port	enum	string	string	string	int	time
83079.679847	Cifz3n4zRoW5N4c3Fg	10.0.20.24	47808	10.0.30.35	47808	udp	atomic_write_file	ConfirmedRequest	file	4	83136.235718
83076.790637	Czf30y4FoJ43aMrB47	10.0.20.22	47808	10.0.30.27	47808	udp	who_is	UnconfirmedRequest	(empty)	8	83138.226848
83076.042712	C6QrIv2oRwgQMqYYc5	10.0.20.23	47808	10.0.30.31	47808	udp	who_has	UnconfirmedRequest	(empty)	12	83147.742865
#close	2023-08-22-02-33-43
```

## 関連ソフトウェア

本プラグインは[OsecT](https://github.com/nttcom/OsecT)で利用されています。
