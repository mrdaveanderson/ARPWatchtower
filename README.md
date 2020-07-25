# ARPWatchtower
Simple wrapper for tcpdump to print MAC addr, IP addr, and VLAN number from ARP requests (and replies if visible).

Configurable caching time ensures that if you have particularly chatty hosts on your network, you only see one print/log per N seconds from said chatterbox.

Usage:
```
python3 ARPWatchtower.py <interface name> <seconds to cache>
```

e.g.
```
python3 ARPWatchtower.py en0 600
```

Tested on macOS 10.15.6 and CentOS 8.2.

For now, this script runs tcpdump with `--no-promiscuous-mode`. While there is no cli flag to disable that, feel free to remove it from the list of args to tcpdump if that is not desireable in your environment.


Suggested usecase is on a VM with two interfaces, one for interactive login/log egress/etc, and one with all your vlans trunked to it for monitoring (ensure that it is ifup'd, and recommend it has no IP addresses of its own). Pretty easy to mod to add graylog/ELK ingestion for whatever centralized logging you have using applicable libraries should you so desire (see location of the TODO message).
