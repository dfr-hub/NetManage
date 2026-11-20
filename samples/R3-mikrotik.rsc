# 2026-11-01 10:00:00 by RouterOS 7.16
# model = CCR2004-16G-2S+
/interface bridge
add name=loopback0
/interface ethernet
set [ find default-name=ether1 ] comment="TO-R2-JUNIPER"
set [ find default-name=ether2 ] comment="TO-R4-HUAWEI"
set [ find default-name=ether3 ] comment="LAN-TRUNK"
set [ find default-name=ether4 ] comment="UNUSED" disabled=yes
/interface vlan
add comment="LAN-OFFICE" interface=ether3 name=vlan30 vlan-id=30
/routing ospf instance
add name=ospf-1 router-id=10.255.0.3 version=2 redistribute=static out-filter-chain=OSPF-OUT
/routing ospf area
add area-id=0.0.0.0 instance=ospf-1 name=backbone
/ip address
add address=10.255.0.3/32 interface=loopback0 network=10.255.0.3
add address=10.0.23.2/30 interface=ether1 network=10.0.23.0
add address=10.0.34.1/30 interface=ether2 network=10.0.34.0
add address=192.168.3.1/24 interface=vlan30 network=192.168.3.0
/ip dns
set servers=8.8.8.8,1.1.1.1
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input in-interface=ether1 protocol=tcp dst-port=23
/ip route
add comment="DEFAULT" dst-address=0.0.0.0/0 gateway=10.0.23.1
add distance=150 dst-address=10.99.0.0/24 gateway=10.0.34.2
/routing filter rule
add chain=NM-POLICY-SAMPLE rule="if (dst in 192.168.3.0/24 && dst-len == 24) { accept }"
add chain=OSPF-OUT rule="if (dst in 192.168.30.0/23 && dst-len in 24-24) { set ospf-ext-metric 25; accept }"
add chain=OSPF-OUT rule="reject"
/routing ospf interface-template
add area=backbone interfaces=loopback0 passive
add area=backbone interfaces=ether1
add area=backbone cost=20 interfaces=ether2
add area=backbone interfaces=vlan30 passive
/snmp
set contact=noc@lab.local enabled=yes location=Jakarta-DC1
/snmp community
add name=public
/system identity
set name=R3-MIKROTIK
/system ntp client
set enabled=yes
/system ntp client servers
add address=192.168.1.10
