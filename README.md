# DNS-OVER-TLS
## TLS OVER DNS written in python
This is a python  app which can establish DNS conn over TLS .
It creates DNS Packet as per  https://tools.ietf.org/html/rfc7858 , creates SSL session and do dns resolution via  cloudfare 1.1.1.1 DNS Server

**This is modified fork to connect to any DoT-capable sites.**

## How to Test ?
cd to current directory, use Python 3

Connect example, using Google DoT DNS resolving Cloudflare DNS IP

```py
import App
d = App.dnsTLS("dns.google")
p = d.buildPacket("1dot1dot1dot1.cloudflare-dns.com")
c = d.connect()
r = d.sendMessage(p, c)
print(r)
print(d.extractIp(r))
```
