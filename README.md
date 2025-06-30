### Description

This system provides a dynamic(prefixes are announced and withdrawn) BGP feed from the [peers of RIPE RIS route collectors](https://www.ris.ripe.net/peerlist/all.shtml).

### Usage example

Let's say, that _Acme Corporation_(`AS 64511`) buys IP transit from three providers:

![ACME IP transit providers](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/ACME_IP_transit_providers.jpg)

With system running, the _Acme Corporation_ Juniper router named `acme-r1` receives 3x IPv4 and 3x IPv6 full feed from its upstream providers:

https://github.com/user-attachments/assets/43e0de7d-7fc8-4810-afa8-b5e72d052f6d

The overall architecture of the system can be seen below:

![ripe-ris-data-to-exabgp architecture](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/ripe-ris-data-to-exabgp_architecture.jpg)

Instances of the [ripe-ris-data-to-exabgp.py](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/scripts-and-conf/usr/local/bin/ripe-ris-data-to-exabgp.py) script, ExaBGP processes and [BIRD](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/scripts-and-conf/etc/bird/bird.conf) all run in the same virtual machine. BIRD takes care of the eBGP sessions with external router `acme-r1`, filters and installs routes received from `acme-r1` into the routing table of the virtual machine and establishes iBGP sessions with ExaBGP processes managed by the [ripe-ris-data-to-exabgp.py](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/scripts-and-conf/usr/local/bin/ripe-ris-data-to-exabgp.py) script. The script works in a way that it subscribes to a BGP feed from a BGP neighbor of the [RIS(Routing Information Service) RRC(Remote Route Collector)](https://www.ris.ripe.net/peerlist/all.shtml). It also reads the entries for that BGP neighbor from the RIS dump and BGP messages from updates files. Entries from the dump file are used to build the ExaBGP configuration file. BGP messages from the updates files are pushed to ExaBGP using its API. Finally, both queued and new real-time messages from the [RIPE RIS Live API](https://ris-live.ripe.net/) are pushed to ExaBGP via its API. Instances of the script are run from the systemd template unit [ripe-ris-data-to-exabgp@.service](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/scripts-and-conf/etc/systemd/system/ripe-ris-data-to-exabgp%40.service), e.g `systemctl enable --now ripe-ris-data-to-exabgp@AS2586-v4` which will start an instance of the script with [configuration file](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/scripts-and-conf/usr/local/etc/conf-AS2586-v4.ini) for v4 stream of `AS 2586`. [Log messages](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/ripe-ris-data-to-exabgp%40AS2586-v4_log_messages.txt) of the `ripe-ris-data-to-exabgp@AS2586-v4.service` will give a good overview of the script operations.


### System requirements and overview

```
martin@upstreams:~$ lsb_release -d
Description:    Debian GNU/Linux 13 (trixie)
martin@upstreams:~$
martin@upstreams:~$ python3 --version
Python 3.13.3
martin@upstreams:~$
martin@upstreams:~$ # third-party Python modules
martin@upstreams:~$ dpkg -l python3-aiofiles python3-aiohttp python3-websockets python3-lxml
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name               Version      Architecture Description
+++-==================-============-============-======================================================
ii  python3-aiofiles   24.1.0-2     all          support for Python asyncio file operations
ii  python3-aiohttp    3.11.16-1    amd64        http client/server for asyncio
ii  python3-lxml:amd64 5.4.0-1      amd64        pythonic binding for the libxml2 and libxslt libraries
ii  python3-websockets 15.0.1-1     amd64        implementation of the WebSocket Protocol (RFC 6455)
martin@upstreams:~$
martin@upstreams:~$ # Scapy module with https://github.com/secdev/scapy/pull/4745 patch
martin@upstreams:~$ python3 -c "import scapy; print(scapy.__version__)"
2.6.1.dev109
martin@upstreams:~$
martin@upstreams:~$ # bgpkit-parser version 0.11.0 or newer in PATH
martin@upstreams:~$ bgpkit-parser --version
bgpkit-parser 0.11.1
martin@upstreams:~$
martin@upstreams:~$ # /usr/sbin/exabgp from python3-exabgp package
martin@upstreams:~$ /usr/sbin/exabgp --version
ExaBGP : 4.2.25
Python : 3.13.3 (main, Apr 10 2025, 21:38:51) [GCC 14.2.0]
Uname  : Linux upstreams 6.12.32-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.32-1 (2025-06-07) x86_64
Root   :
martin@upstreams:~$
martin@upstreams:~$ # bird3; https://pkg.labs.nic.cz/doc/?project=bird
martin@upstreams:~$ /usr/sbin/bird --version
BIRD version 3.1.2
martin@upstreams:~$
```

While not mandatory, the `upstreams` virtual machine is set up in a way that access to Internet is from the `mgnt` VRF only and default VRF contains the direct point to point networks for eBGP sessions:

![upstreams route tables](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/upstreams_route_tables.jpg)

Default VRF does not have default route(s):

![upstreams default vrf static routes](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/upstreams_default_vrf_static_routes.jpg)

This provides a clear separation between the real Internet and lab setup. Prefixes announced by `acme-r1` router and received by BIRD are also installed to default VRF:

![upstreams routes from bird](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/upstreams_routes_from_bird.jpg)

Processes running in `mgnt` VRF:

![upstreams processes in mgnt vrf](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/upstreams_processes_in_mgnt_vrf.jpg)

Output of `birdc show protocols`:

![upstreams_output of birdc](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/upstreams_output_of_birdc.jpg)

Spec of `upstreams` and `acme-r1` virtual machines seen from the host machine:

![lab-svr virsh dominfo](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/lab-svr_virsh_dominfo.jpg)


### Acknowledgements

[![ripe ncc logo](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/ripe_ncc_logo.jpg)](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/)
[![bird logo](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/bird_logo.jpg)](https://bird.network.cz/)
[![bgpkit-parser](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/bgpkit-parser_logo.jpg)](https://github.com/bgpkit/bgpkit-parser)
[![exabgp logo](https://github.com/tonusoo/ripe-ris-data-to-exabgp/blob/main/imgs/exabgp_logo.jpg)](https://github.com/Exa-Networks/exabgp)
