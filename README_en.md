# Zeek-Parser-Bacnet

## Overview

Zeek-Parser-Bacnet is a Zeek plug-in that can analyze communication using BACnet/IP.

## Usage

### Manual Installation

Before using this plug-in, please make sure Zeek has been installed.

````
# Check Zeek
~$ zeek -version
zeek version 5.0.0

# As a premise, the path of zeek in this manual is as below
~$ which zeek
/usr/local/zeek/bin/zeek
````

Use `git clone` to get a copy of this repository to your local environment.
```
~$ git clone https://github.com/nttcom/zeek-parser-Bacnet.git
```

Then, copy the zeek file to the following paths.
```
~$ cd ~/zeek-parser-Bacnet/scripts/
~$ cp bacnet_ip.zeek /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek
~$ cp consts_bacnet_ip.zeek /usr/local/zeek/lib/zeek/plugins/packages/icsnpp-bacnet/scripts/consts.zeek
```

Finally, import the Zeek plugin.
```
~$ tail /usr/local/zeek/share/zeek/site/local.zeek
... Omit ...
@load icsnpp-bacnet
```

This plug-in generates a `bacnet.log` by the command below:
```
~$ cd ~/zeek-parser-Bacnet/testing/Traces
~$ zeek -Cr test.pcap /usr/local/zeek/share/zeek/site/icsnpp-bacnet/main.zeek
```

## Log type and description
This plug-in monitors all functions of Bacnet/IP and outputs them as `bacnet.log`.

| Field | Type | Description |
| --- | --- | --- |
| ts | time | timestamp of the first communication |
| uid | string | unique ID for this connection |
| id.orig_h | addr | source IP address |
| id.orig_p | port | source port number |
| id.resp_h | addr | destination IP address  |
| id.resp_p | port | destination port number   |
| proto | enum | the transport layer protocol of the connection |
| pdu_service | string | name of Protocol Data Unit service |
| pdu_type | string | PDU type |
| obj_type | string | BACnetObjectIdentifier object |
| number | int | number of packet occurrence |
| ts_end | time | timestamp of the last communication |

An example of `bacnet.log` is as follows:
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

## Related Software

This plug-in is used by [OsecT](https://github.com/nttcom/OsecT).
