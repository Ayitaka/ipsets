# ipsets
Manual and automatic managed interface for ipset

Features:

* Blacklist individual IPs, IP CIDRs, Domains, ASNs, countries, or entire local or remote blocklists
* Override Blacklists with Whitelists
* Implemented as a systemd service with systemd timer update schedule
* Caches blocklists and only downloads updates when new content is found
* rsyslog entry to keep syslog cleaner and redirect messages to separate log file
* logrotate entry to manage log files

Originally based, in part, on [Skynet](https://github.com/Adamm00/IPSet_ASUS) by Adamm00, a very useful ipset firewall for Asus routers running AsusWRT-Merlin firmware.

## ***Requirements***

## ***Installing***

As the root user:

```bash
curl --retry 3 "https://raw.githubusercontent.com/Ayitaka/ipsets/master/ipsets.sh" -o "./ipsets.sh" && chmod 0700 ./ipsets.sh && ./ipsets.sh install
```

## ***How To Use***

After installation, from the command line type:
```bash
ipsets help
```
---

```

```
