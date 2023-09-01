# ipsets
Manual and automatic managed interface for ipset

Features:

* Blacklist individual IPs, IP CIDRs, Domains, ASNs, countries, or entire local or remote blocklists
* Override Blacklists with Whitelists
* Implemented as a systemd service with systemd timer update schedule
* Caches blocklists and only downloads updates when new content is found
* (Optional) rsyslog entry to keep syslog cleaner and redirect messages to separate log file
* (Optional) logrotate entry to manage log files

Originally based, in part, on [Skynet](https://github.com/Adamm00/IPSet_ASUS) by Adamm00, a very useful ipset firewall for Asus routers running AsusWRT-Merlin firmware.

## ***Requirements***

IPSets requires the following programs/packages to be installed, running, and accessable prior to installing IPSets:

* ifconfig
* nslookup
* ipset
* iptables
* curl
* systemd

Optional programs/packages:

* rsyslog
* logrotate

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

```
   ipsets blacklist|whitelist add|del ip       123.456.789                 ["comment"]     
   ipsets blacklist|whitelist add|del cidr     123.456.789/32              ["comment"]     
   ipsets blacklist|whitelist add|del domain   www.example.com             ["comment"]     
   ipsets blacklist|whitelist add|del country  "cn tw ve br"               ["comment"]     
   ipsets blacklist|whitelist add|del asn      "AS714 AS12222 AS16625"     ["comment"]     
   ipsets blacklist|whitelist list|del comment "reg.*ex(patt|ern)?"                        
   ipsets start                                                                            
   ipsets restart                                                                          
   ipsets stop                                                                             
   ipsets save [all|whitelist|whitelistcidr|blacklist|blacklistcidr]   (Default: all)      
   ipsets refresh                                                                          
   ipsets stats                                                                            
   ipsets reset                                                                            
   ipsets install                                                                          
   ipsets uninstall                                                                        
                                                                                           
       NOTE: List of country codes:                                                        
               https://www.iso.org/obp/ui/#search                                          
                                                                                           
       NOTE: Lists of ASNs:                                                                
               https://api.bgpview.io/                                                     
               https://www.cc2asn.com/                                                     
```
---

```

```
