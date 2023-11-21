# BGP over IPsec with-Strongswan To AWS

***Linux-based Router***

This setup uses Centos7 as the Linux distribution for the EC2-based VPN gateway and router. Strongswan provides the IPSec termination for the AWS Site-to-Site VPN connection. And FRRouting provides the dynamic routing capabilities for BGP.

## Installation Steps 

1. [Strongswan Setup](#strongswan-setup)
    - [Install Strongswan](#install-strongswan)
    - [Config Strongswan ipsec.conf](#config-strongswan-ipsecconf)
    - [Config Strongswan ipsec.secrets](#config-ipsecsecrets)
    - [IPsec Virtual Tunnel up/down controll script](#ipsec-virtual-tunnel-updown-controll-script)
    - [Strongswan validation](#strongswan-validation)
2. [FrrRouting Setup](#frrouting-setup)
    - [Option 1: Install with RPM](#option-1)
        - [Install require packages](#install-require-packages)
        - [Install FRR routing](#install-frr)
    - [Option 2: Install packages from git](#option-2)
        - [Add YANG/NETCON Repository](#add-yangnetcon-repository)
        - [Add frr groups and user](#add-frr-groups-and-user)
        - [Download Source, configure and compile it](#download-source-configure-and-compile-it)
        - [Create empty FRR configuration files](#create-empty-frr-configuration-files)
        - [Install daemon config file](#install-daemon-config-file)
        - [Install frr Service](#install-frr-service)
        - [Register the systemd files](#register-the-systemd-files)
        - [Enable frr at startup and start service](#enable-frr-at-startup-and-start-service)
3. [BGP Setup](#bgp-routing)
    - [Config BGP Routing](#config-bgp-routing)
    - [Validate BGP Status](#check-bgp-interface)
4. [Troubleshooting BGP](#troubleshooting)
    - [Main Troubleshoot Flowchart](#main-troubleshoot-flowchart)
    - [Troubleshoot BGP Neighbor Establishment](#troubleshoot-bgp-neighbor-establishment)
    - [Troubleshoot Routes Missing from the Routing Table](#troubleshoot-routes-missing-from-the-routing-table)
    - [Troubleshoot Multihoming Inbound](#troubleshoot-multihoming-inbound)
    - [Troubleshoot BGP Route Advertisement](#troubleshoot-bgp-route-advertisement)
    - [Troubleshoot Multihoming Outbound](#troubleshoot-multihoming-outbound)
5. [Firewall Config](#firewall)
6. [Config Sysctl.conf](#sysctlconf-for-kernel)


## Strongswan Setup

### Install Strongswan
---
Add Epel Repository 

```shell
sudo yum install -y epel-release
```

Install Strongswan
```shell
sudo yum install -y strongswan
```

```shell
cd /etc/strongswan/
```

---

### Config Strongswan ipsec.conf
---

```shell
conn %default 
       leftauth=psk
       rightauth=psk
       ike=aes128-sha1-modp1024
       ikelifetime=28800s
       aggressive=no
       esp=aes128-sha1-modp1024
       lifetime=3600s
       type=tunnel
       dpddelay=10s
       dpdtimeout=30s
       keyexchange=ikev1
       rekey=yes
       reauth=no
       dpdaction=restart
       closeaction=restart
       leftsubnet=0.0.0.0/0,::/0
       rightsubnet=0.0.0.0/0,::/0
       leftupdown=/etc/strongswan/ipsec-vti.sh
       installpolicy=yes
       compress=no
       mobike=no
conn wan219
       left=192.168.0.61
       leftid=39.106.86.31
       right=180.232.176.219
       rightid=180.232.176.219
       auto=start
       mark=100
conn wan66
       left=192.168.0.61
       leftid=39.106.86.31
       right=222.127.131.66
       rightid=222.127.131.66
       auto=start
       mark=200
```

### Config ipsec.secrets
---

```shell
# ipsec.secrets - strongSwan IPsec secrets file

# RSA private key for this host, authenticating it to any other host
# which knows the public part.
Local_IP Remote_IP : PSK "Your IPsec Password"
Local_IP Remote_IP : PSK "Your IPsec Password"
```

### IPsec Virtual Tunnel up/down controll script

```shell
#!/bin/bash

#
# /etc/ipsec-vti.sh
#

IP=$(which ip)
IPTABLES=$(which iptables)

PLUTO_MARK_OUT_ARR=(${PLUTO_MARK_OUT//// })
PLUTO_MARK_IN_ARR=(${PLUTO_MARK_IN//// })
case "$PLUTO_CONNECTION" in
wan219)
VTI_INTERFACE=vti1
VTI_LOCALADDR=169.254.12.38/30
VTI_REMOTEADDR=169.254.12.37/30
;;
wan)
VTI_INTERFACE=vti2
VTI_LOCALADDR=169.254.14.230/30
VTI_REMOTEADDR=169.254.14.229/30
;;
esac

case "${PLUTO_VERB}" in
up-client)
#$IP tunnel add ${VTI_INTERFACE} mode vti local ${PLUTO_ME} remote ${PLUTO_PEER} okey ${PLUTO_MARK_OUT_ARR[0]} ikey ${PLUTO_MARK_IN_ARR[0]}
$IP link add ${VTI_INTERFACE} type vti local ${PLUTO_ME} remote ${PLUTO_PEER} okey ${PLUTO_MARK_OUT_ARR[0]} ikey ${PLUTO_MARK_IN_ARR[0]}
sysctl -w net.ipv4.conf.${VTI_INTERFACE}.disable_policy=1
sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=2 || sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=0
$IP addr add ${VTI_LOCALADDR} remote ${VTI_REMOTEADDR} dev ${VTI_INTERFACE}
$IP link set ${VTI_INTERFACE} up mtu 1436
$IPTABLES -t mangle -I FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
$IPTABLES -t mangle -I INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
$IPTABLES -A INPUT -o ${VTI_INTERFACE} -j ACCEPT
$IPTABLES -t nat -A postrouting -o ${VTI_INTERFACE} -j SNAT --to-source $(ifconfig | grep -E "eth[0-9]" -a1 | grep inet | awk {'print $2'})
$IP route flush table 220
#/etc/init.d/bgpd reload || /etc/init.d/quagga force-reload bgpd
;;
down-client)
#$IP tunnel del ${VTI_INTERFACE}
$IP link del ${VTI_INTERFACE}
$IPTABLES -t mangle -D FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
$IPTABLES -t mangle -D INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
;;
esac

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.eth0.disable_xfrm=1
sysctl -w net.ipv4.conf.eth0.disable_policy=1
```

```shell
chmod +x /etc/ipsec-vti.sh
```
```shell
systemctl restart strongswan
```

### Strongswan validation

---

You can validate that two tunnel interfaces vti1 and vti2 are up and running with the commands

```shell
ip -s tunnel show
```

Looking at the tunnel status you should see bytes being send (TX) and received (RX) for both tunnels.
```shell

vti1: ip/ip remote 35.98.76.54 local 18.123.45.67 ttl inherit nopmtudisc key 100
RX: Packets    Bytes        Errors CsumErrs OutOfSeq Mcasts
    12         792          0      0        0        0
TX: Packets    Bytes        Errors DeadLoop NoRoute  NoBufs
    12         714          7      0        7        0
vti2: ip/ip remote 54.98.76.54 local 18.123.45.67 ttl inherit nopmtudisc key 200
RX: Packets    Bytes        Errors CsumErrs OutOfSeq Mcasts
    4          240          0      0        0        0
TX: Packets    Bytes        Errors DeadLoop NoRoute  NoBufs
    4          160          7      0        7        0
ip_vti0: ip/ip remote any local any ttl inherit nopmtudisc key 0
RX: Packets    Bytes        Errors CsumErrs OutOfSeq Mcasts
    0          0            0      0        0        0
TX: Packets    Bytes        Errors DeadLoop NoRoute  NoBufs
    0          0            0      0        0        0
```


OR

```shell
ifconfig vti1
```

```shell
vti1: flags=209<UP,POINTOPOINT,RUNNING,NOARP>  mtu 1436
        inet 169.254.12.38  netmask 255.255.255.252  destination 169.254.12.37
        inet6 fe80::5efe:ac1f:27e0  prefixlen 64  scopeid 0x20<link>
        tunnel   txqueuelen 1000  (IPIP Tunnel)
        RX packets 12  bytes 792 (792.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12  bytes 714 (714.0 B)
        TX errors 7  dropped 0 overruns 0  carrier 7  collisions 0
```

## FRRouting Setup

###  Option 1

#### Add YANG/NETCON Repository  
FRR depends on the relatively new libyang library to provide YANG/NETCONF support.

---

Download RPM and install from [https://rpm.frrouting.org/](https://rpm.frrouting.org/)

```shell
# possible values for FRRVER: frr-6 frr-7 frr-8 frr-9 frr-stable
# frr-stable will be the latest official stable release
FRRVER="frr-stable"

# add RPM repository on CentOS 6
#    Note: FRR only supported up to Version 7.4.x
curl -O https://rpm.frrouting.org/repo/$FRRVER-repo-1-0.el6.noarch.rpm
sudo yum install ./$FRRVER*

# add RPM repository on CentOS 7
curl -O https://rpm.frrouting.org/repo/$FRRVER-repo-1-0.el7.noarch.rpm
sudo yum install ./$FRRVER*

# add RPM repository on RedHat 8
#    Note: Supported since FRR 7.3
curl -O https://rpm.frrouting.org/repo/$FRRVER-repo-1-0.el8.noarch.rpm
sudo yum install ./$FRRVER*

# add RPM repository on RedHat 9
#    Note: Supported since FRR 8.3
curl -O https://rpm.frrouting.org/repo/$FRRVER-repo-1-0.el9.noarch.rpm
sudo yum install ./$FRRVER*
```

#### Install require packages


Libyang Repo

```shell
sudo yum install git autoconf automake libtool make \
  readline-devel texinfo net-snmp-devel groff pkgconfig \
  json-c-devel pam-devel bison flex pytest c-ares-devel \
  python-devel python-sphinx libcap-devel \
  elfutils-libelf-devel libunwind-devel protobuf-c-devel
```
#### Install FRR

```shell
# 
sudo yum install frr frr-pythontools
```

---

### Option 2 

> `[Note]` Ensure that the libyang build requirements are met before continuing. Usually this entails installing cmake and libpcre2-dev or pcre2-devel.


```
git clone https://github.com/CESNET/libyang.git
cd libyang
git checkout v2.0.0
mkdir build; cd build
cmake -D CMAKE_INSTALL_PREFIX:PATH=/usr \
      -D CMAKE_BUILD_TYPE:String="Release" ..
make
sudo make install
```
#### Add frr groups and user

```shell
sudo groupadd -g 92 frr
sudo groupadd -r -g 85 frrvty
sudo useradd -u 92 -g 92 -M -r -G frrvty -s /sbin/nologin \
  -c "FRR FRRouting suite" -d /var/run/frr frr
```

#### Download Source, configure and compile it

```shell
git clone https://github.com/frrouting/frr.git frr
cd frr
./bootstrap.sh
./configure \
    --bindir=/usr/bin \
    --sbindir=/usr/lib/frr \
    --sysconfdir=/etc/frr \
    --libdir=/usr/lib/frr \
    --libexecdir=/usr/lib/frr \
    --localstatedir=/var/run/frr \
    --with-moduledir=/usr/lib/frr/modules \
    --enable-snmp=agentx \
    --enable-multipath=64 \
    --enable-user=frr \
    --enable-group=frr \
    --enable-vty-group=frrvty \
    --disable-ldpd \
    --enable-fpm \
    --with-pkg-git-version \
    --with-pkg-extra-version=-MyOwnFRRVersion \
    SPHINXBUILD=/usr/bin/sphinx-build
make
make check
sudo make install
```

#### Create empty FRR configuration files

```shell
sudo mkdir /var/log/frr
sudo mkdir /etc/frr
sudo touch /etc/frr/zebra.conf
sudo touch /etc/frr/bgpd.conf
sudo touch /etc/frr/ospfd.conf
sudo touch /etc/frr/ospf6d.conf
sudo touch /etc/frr/isisd.conf
sudo touch /etc/frr/ripd.conf
sudo touch /etc/frr/ripngd.conf
sudo touch /etc/frr/pimd.conf
sudo touch /etc/frr/nhrpd.conf
sudo touch /etc/frr/eigrpd.conf
sudo touch /etc/frr/babeld.conf
sudo chown -R frr:frr /etc/frr/
sudo touch /etc/frr/vtysh.conf
sudo chown frr:frrvty /etc/frr/vtysh.conf
sudo chmod 640 /etc/frr/*.conf
```
#### Install daemon config file

```shell
sudo install -p -m 644 tools/etc/frr/daemons /etc/frr/
sudo chown frr:frr /etc/frr/daemons
```

#### Install frr Service
```shell
sudo install -p -m 644 tools/frr.service /usr/lib/systemd/system/frr.service
```

#### Register the systemd files

```shell
sudo systemctl preset frr.service
```

#### Enable frr at startup and start service

```shell
sudo systemctl start frr.service
sudo systemctl enable frr.service
```

### Config BGP Routing

> `[Note]` You need to install FRR routing first

Enter VTY interface
```shell
sudo vtysh
```

Cisco alike command 
First we configure the BGP process with the provided AS number and the two VPN-based peers. We also chose to announce our local private subnet 10.16.16.0/24.

```
host# conf t
host(config)# router bgp 65016
host(config-router)# no bgp ebgp-requires-policy
host(config-router)# neighbor 169.254.12.229 remote-as 64512
host(config-router)# neighbor 169.254.14.37 remote-as 64512
host(config-router)# address-family ipv4 unicast
host(config-router-af)# neighbor 169.254.12.229 soft-reconfiguration inbound
host(config-router-af)# neighbor 169.254.14.37 soft-reconfiguration inbound
host(config-router-af)# network 10.16.16.0/24
host(config-router-af)# end
host# wr
```

### Check BGP interface
```
host# sh int brief
Interface       Status  VRF             Addresses
---------       ------  ---             ---------
eth0            up      default         10.16.1.254/24
                                        + 2600:1f16:e4d:1a01:fbe6:fa0b:929b:4d72/128
eth1            up      default         10.16.16.254/24
                                        + 2600:1f16:e4d:1a11:2c38:23f7:7a5d:f773/128
ip_vti0         down    default
lo              up      default
vti1            up      default         169.254.12.38/32
vti2            up      default         169.254.14.230/32
```

```
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
       F - PBR,
       > - selected route, * - FIB route

B>* 172.31.0.0/16 [20/100] via 169.254.14.229, vti2, 00:23:10
  *                        via 169.254.12.37, vti1, 00:23:10
```

### Troubleshooting

If you have the output of a show ip bgp , show ip bgp neighbors , show ip bgp summary , or show tech-support command from your Cisco device, you can use [Cisco CLI Analyzer](https://cway.cisco.com/cli/) to display potential issues and fixes. To use Cisco CLI Analyzer, you must be a registered Cisco user.

[Referencing from: Troubleshoot Common BGP Issues](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/22166-bgp-trouble-main.html)

#### Main Troubleshoot Flowchart

![Alt text](/screenshots/22166-bgp-trouble-main-00.png)

#### Troubleshoot BGP Neighbor Establishment

![Alt text](/screenshots/22166-bgp-trouble-main-01.png)


This is a sample log message that must be checked when the neighbor does not come up:
```
BGP_SESSION-5-ADJCHANGE: neighbor[ip address] IPv4 Unicast topology base removed
  from session Peer closed the session
BGP_SESSION-5-ADJCHANGE: neighbor[ip address] IPv4 Unicast topology base removed
  from session Unknown path error
```

This is an example of ping with packet size and enable does not contain fragment bit in the IP header:
```
Router#ping 10.10.10.2 size 1400 df-bit

Type escape sequence to abort.
Sending 5, 1400-byte ICMP Echos to 10.10.10.2, timeout is 2 seconds:
Packet sent with the DF bit set
!!!!!
Success rate is 100 percent (5/5), round-trip min/avg/max = 1/37/84 ms
```
#### Troubleshoot Routes Missing from the Routing Table
![Alt text](/screenshots/22166-bgp-trouble-main-02.png)

> `[Note]` If the BGP routes are not in the routing table, verify if the network statement under the BGP configuration is correct.

> `[Note]` In the debug ip bgp x.x.x.x updates command, x.x.x.x is the neighbor to which the route must be advertised.

#### Troubleshoot Multihoming Inbound
![Alt text](/screenshots/22166-bgp-trouble-main-03.png)

#### Troubleshoot BGP Route Advertisement
![Alt text](/screenshots/22166-bgp-trouble-main-04.png)

#### Troubleshoot Multihoming Outbound
![Alt text](/screenshots/22166-bgp-trouble-main-05.png)

### Firewall
---
Allow Ports
```shell
$ sudo firewall-cmd --permanent --add-port=80/tcp
$ sudo firewall-cmd --permanent --add-port=500/udp
$ sudo firewall-cmd --permanent --add-port=4500/udp
```

Allow NAT packet forwarding, also known as IP masquerade.

```shell
$ sudo firewall-cmd --permanent --add-masquerade
```
Reload Firewall

```shell
sudo firewall-cmd --reload
```

### Sysctl.conf for kernel

```shell
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.conf
echo "net.ipv4.conf.all.forwarding=1" | sudo tee /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee /etc/sysctl.conf

# apply config to sysctl
sudo sysctl -p /etc/sysctl.conf
```