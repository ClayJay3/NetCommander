import re
import string


interface_output = """Port         Name               Status       Vlan       Duplex  Speed Type
Twe1/0/1     ESXI NODE 1 PORT 2 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/2     ESXI NODE 1 PORT 4 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/3     ESXI NODE 2 PORT 2 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/4     ESXI NODE 2 PORT 4 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/5     ESXI NODE 3 PORT 2 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/6     ESXI NODE 3 PORT 4 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/7     ESXI NODE 4 PORT 2 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/8     ESXI NODE 4 PORT 4 connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/9     UNITY DPE SPA MGMT connected    115          full    10G SFP-10GBase-SR
Twe1/0/10    UNIT DPE SPB MGMT  connected    115          full    10G SFP-10GBase-SR
Twe1/0/11    IDPA PORT 3        connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/12    IDPA PORT          connected    115          full    10G SFP-10GBase-SR
Twe1/0/13                       notconnect   1            auto   auto unknown
Twe1/0/14                       connected    1            full    10G SFP-10GBase-SR
Twe1/0/15    SAN SPA PORT 0     connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/16    SPB PORT 0         connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/17                       notconnect   115          auto   auto unknown
Twe1/0/18                       notconnect   115          auto   auto unknown
Twe1/0/19    SAN SPA MOD1 PORT  connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/20    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/21    SAN SPB MOD1 PORT  connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/22    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe1/0/23                       disabled     1            auto   auto unknown
Twe1/0/24                       connected    4094         full    10G SFP-10GBase-SR
Hu1/0/25     To CoreA Fo1/1/1   notconnect   1            auto   auto unknown
Hu1/0/26     To CoreB Fo1/1/1   notconnect   1            auto   auto unknown
Hu1/0/27                        connected    4094         full    40G QSFP 40G CU1M
Hu1/0/28                        connected    4094         full    40G QSFP 40G CU1M
Twe2/0/1     ESXI NODE 1 PORT 1 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/2     ESXI NODE 1 PORT 3 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/3     ESXI NODE 2 PORT 1 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/4     ESXI NODE 2 PORT 3 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/5     ESXI NODE 3 PORT 1 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/6     ESXI NODE 3 PORT 3 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/7     ESXI NODE 4 PORT 1 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/8     ESXI NODE 4 PORT 3 connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/9     IDPA INT 0         connected    115          full    10G SFP-10GBase-SR
Twe2/0/10    IDPA INT 1         connected    115          full    10G SFP-10GBase-SR
Twe2/0/11    IDPA PORT 1        connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/12    IDPA PORT 7        connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/13                       connected    113          full    10G SFP-10GBase-SR
Twe2/0/14    SAN SPB            connected    115          full    10G SFP-10GBase-SR
Twe2/0/15    SAN SPA PORT 1     err-disabled 1            full    10G SFP-10GBase-SR
Twe2/0/16    SPB PORT 1         connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/17                       notconnect   115          full    10G SFP-10GBase-SR
Twe2/0/18                       connected    1            full    10G SFP-10GBase-SR
Twe2/0/19    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/20    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/21    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/22    VLANS FOR SAN A AN connected    trunk        full    10G SFP-10GBase-SR
Twe2/0/23                       disabled     1            full    10G unknown
Twe2/0/24                       connected    4094         full    10G SFP-10GBase-SR
Hu2/0/25     To CoreA Fo1/1/2   connected    trunk        full    40G QSFP 40G CSR4 SFP
Hu2/0/26     To CoreB Fo1/1/2   notconnect   1            auto   auto unknown
Hu2/0/27                        connected    4094         full    40G QSFP 40G CU1M
Hu2/0/28                        connected    4094         full    40G QSFP 40G CU1M
Po1                             connected    113        a-full  a-10G N/A

"""

config = """
Building configuration...

Current configuration : 20832 bytes
!
! Last configuration change at 21:20:06 UTC Tue Nov 1 2022 by clayton.cowen
! NVRAM config last updated at 17:06:47 UTC Mon Oct 31 2022 by clayton.cowen
!
version 16.12
no service pad
service timestamps debug datetime msec
service timestamps log datetime msec
service call-home
platform punt-keepalive disable-kernel-core
!
hostname KNK-TOR-ACCESS
!
!
vrf definition Mgmt-vrf
 !
 address-family ipv4
 exit-address-family
 !
 address-family ipv6
 exit-address-family
!
logging buffered 100000
enable secret 9 $9$j15bebwgJEiy5E$KdD9Vf19MnowIXtbEsZcu3J/NsRQQUgNrbxz78mtN5s
!
aaa new-model
!
!
aaa authentication login deviceadmin group radius local
aaa authorization exec deviceadmin group radius if-authenticated
!
!
!
!
!
!
aaa session-id common
switch 1 provision c9500-24y4c
switch 2 provision c9500-24y4c
boot system bootflash:packages.conf
stackwise-virtual
 domain 10
call-home
 ! If contact email address in call-home is configured as sch-smart-licensing@cisco.com
 ! the email address configured in Cisco Smart License Portal will be used as contact email address to send SCH notifications.
 contact-email-addr sch-smart-licensing@cisco.com
 profile "CiscoTAC-1"
  active
  destination transport-method http
  no destination transport-method email
!
no ip domain lookup
ip domain name bar.nucorsteel.local
no ip cef optimize neighbor resolution
!
!
!
login on-success log
!
!
!
!
!
!
!
no device-tracking logging theft
!
crypto pki trustpoint SLA-TrustPoint
 enrollment pkcs12
 revocation-check crl
!
crypto pki trustpoint TP-self-signed-1275384546
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-1275384546
 revocation-check none
 rsakeypair TP-self-signed-1275384546
!
!
crypto pki certificate chain SLA-TrustPoint
 certificate ca 01
  30820321 30820209 A0030201 02020101 300D0609 2A864886 F70D0101 0B050030
  32310E30 0C060355 040A1305 43697363 6F312030 1E060355 04031317 43697363
  6F204C69 63656E73 696E6720 526F6F74 20434130 1E170D31 33303533 30313934
  3834375A 170D3338 30353330 31393438 34375A30 32310E30 0C060355 040A1305
  43697363 6F312030 1E060355 04031317 43697363 6F204C69 63656E73 696E6720
  526F6F74 20434130 82012230 0D06092A 864886F7 0D010101 05000382 010F0030
  82010A02 82010100 A6BCBD96 131E05F7 145EA72C 2CD686E6 17222EA1 F1EFF64D
  CBB4C798 212AA147 C655D8D7 9471380D 8711441E 1AAF071A 9CAE6388 8A38E520
  1C394D78 462EF239 C659F715 B98C0A59 5BBB5CBD 0CFEBEA3 700A8BF7 D8F256EE
  4AA4E80D DB6FD1C9 60B1FD18 FFC69C96 6FA68957 A2617DE7 104FDC5F EA2956AC
  7390A3EB 2B5436AD C847A2C5 DAB553EB 69A9A535 58E9F3E3 C0BD23CF 58BD7188
  68E69491 20F320E7 948E71D7 AE3BCC84 F10684C7 4BC8E00F 539BA42B 42C68BB7
  C7479096 B4CB2D62 EA2F505D C7B062A4 6811D95B E8250FC4 5D5D5FB8 8F27D191
  C55F0D76 61F9A4CD 3D992327 A8BB03BD 4E6D7069 7CBADF8B DF5F4368 95135E44
  DFC7C6CF 04DD7FD1 02030100 01A34230 40300E06 03551D0F 0101FF04 04030201
  06300F06 03551D13 0101FF04 05300301 01FF301D 0603551D 0E041604 1449DC85
  4B3D31E5 1B3E6A17 606AF333 3D3B4C73 E8300D06 092A8648 86F70D01 010B0500
  03820101 00507F24 D3932A66 86025D9F E838AE5C 6D4DF6B0 49631C78 240DA905
  604EDCDE FF4FED2B 77FC460E CD636FDB DD44681E 3A5673AB 9093D3B1 6C9E3D8B
  D98987BF E40CBD9E 1AECA0C2 2189BB5C 8FA85686 CD98B646 5575B146 8DFC66A8
  467A3DF4 4D565700 6ADF0F0D CF835015 3C04FF7C 21E878AC 11BA9CD2 55A9232C
  7CA7B7E6 C1AF74F6 152E99B7 B1FCF9BB E973DE7F 5BDDEB86 C71E3B49 1765308B
  5FB0DA06 B92AFE7F 494E8A9E 07B85737 F3A58BE1 1A48A229 C37C1E69 39F08678
  80DDCD16 D6BACECA EEBC7CF9 8428787B 35202CDC 60E4616A B623CDBD 230E3AFB
  418616A9 4093E049 4D10AB75 27E86F73 932E35B5 8862FDAE 0275156F 719BB2F0
  D697DF7F 28
        quit
crypto pki certificate chain TP-self-signed-1275384546
 certificate self-signed 01
  30820330 30820218 A0030201 02020101 300D0609 2A864886 F70D0101 05050030
  31312F30 2D060355 04031326 494F532D 53656C66 2D536967 6E65642D 43657274
  69666963 6174652D 31323735 33383435 3436301E 170D3230 30393031 31383538
  34335A17 0D333030 31303130 30303030 305A3031 312F302D 06035504 03132649
  4F532D53 656C662D 5369676E 65642D43 65727469 66696361 74652D31 32373533
  38343534 36308201 22300D06 092A8648 86F70D01 01010500 0382010F 00308201
  0A028201 0100C3F3 32960F59 2151DC15 FDC0C8B1 75938DD1 3BAC349E BF431A89
  6949674D 09F478A2 09C4FEB3 7633F673 DE66EF0A FA0FB6E2 840C646D C663BB93
  7DAECAF6 06E87484 38F689F0 0B27E62B 0FF78AA3 1446C44C DCD9CCF6 EEB41489
  D9E44AA4 68AAA69A B160FFC2 226885B7 27AE71DA FFDAB4FE D7B36B65 52F141DE
  DF4FDB03 EDD477AE 9F4D6D5F EBB25FA2 2C73FD01 F8E8D0C6 1F27D00F A7088004
  365A6582 0FDE93B9 FA5E8173 37E1E807 82E79D2D E368F2BC 653C008D D7DB5A72
  13E9D924 996E1A9C 1A6423A3 EE2EA9FE DA33FB4F CE3EF0A9 1EE10E03 975AE553
  7AE605A0 E266C7BD 8026EEFB F8E626A1 DA7943AF 0C6199B0 041D7955 A3C32265
  8A62A777 A6A90203 010001A3 53305130 0F060355 1D130101 FF040530 030101FF
  301F0603 551D2304 18301680 149057D6 3EF7E7AC 381430BD 54213855 2C1C5777
  90301D06 03551D0E 04160414 9057D63E F7E7AC38 1430BD54 2138552C 1C577790
  300D0609 2A864886 F70D0101 05050003 82010100 224124AD 96392582 2E10670C
  9626D134 323C54AB E9B13306 EDCCCB04 8223D438 38801CA1 529373AE 3419FE77
  E188F9CA 44CABC7C D85189B3 47B27C0F 4B8C4EEB 14843C0E A7C3FAE7 BF627A69
  36AD41E7 7624DBA6 DEC7858A C8D29562 DF9D7079 88B32D44 517C5CDE 8F1295A1
  19987268 92AF9529 FB67A793 FF50850F 03A459BC DF0AF5D6 FE288B7E 01BFA48F
  3A454215 9FB05748 C5B3C6D3 67EE2598 196D883B 70F7395B 289F12B8 FE324455
  BC4A6743 FFC1FDD5 DC696045 41EC0E57 C5E308A8 B9113DDF 68FCEECB 6B09E0A3
  CF91A66D D669736D B0AC2335 2E1AA206 077A1AA5 6DBE6DDA 50EBC5CC FFCE0EA5
  FB1FBD7C F8F627AD 2E905061 BEEF91EF B4A1186A
        quit
!
!
license boot level network-advantage addon dna-advantage
!
!
diagnostic bootup level minimal
!
spanning-tree mode rapid-pvst
spanning-tree extend system-id
spanning-tree vlan 2-4093 priority 36864
archive
 path tftp://10.20.115.9//$h
 time-period 20160
memory free low-watermark processor 186813
!
username admin privilege 15 secret 9 $9$5Oz85CHlcKz.s.$fBLaOX9NYNeIONx42Po9jsW4GQFWRtBm72yUNoOUncc
!
redundancy
 mode sso
!
!
!
!
lldp run
!
!
class-map match-any system-cpp-police-ewlc-control
  description EWLC Control
class-map match-any system-cpp-police-topology-control
  description Topology control
class-map match-any system-cpp-police-sw-forward
  description Sw forwarding, L2 LVX data packets, LOGGING, Transit Traffic
class-map match-any system-cpp-default
  description EWLC Data, Inter FED Traffic
class-map match-any system-cpp-police-sys-data
  description Openflow, Exception, EGR Exception, NFL Sampled Data, RPF Failed
class-map match-any system-cpp-police-punt-webauth
  description Punt Webauth
class-map match-any system-cpp-police-l2lvx-control
  description L2 LVX control packets
class-map match-any system-cpp-police-forus
  description Forus Address resolution and Forus traffic
class-map match-any system-cpp-police-multicast-end-station
  description MCAST END STATION
class-map match-any system-cpp-police-high-rate-app
  description High Rate Applications
class-map match-any system-cpp-police-multicast
  description MCAST Data
class-map match-any system-cpp-police-l2-control
  description L2 control
class-map match-any system-cpp-police-dot1x-auth
  description DOT1X Auth
class-map match-any system-cpp-police-data
  description ICMP redirect, ICMP_GEN and BROADCAST
class-map match-any system-cpp-police-stackwise-virt-control
  description Stackwise Virtual OOB
class-map match-any non-client-nrt-class
class-map match-any system-cpp-police-routing-control
  description Routing control and Low Latency
class-map match-any system-cpp-police-protocol-snooping
  description Protocol snooping
class-map match-any system-cpp-police-dhcp-snooping
  description DHCP snooping
class-map match-any system-cpp-police-ios-routing
  description L2 control, Topology control, Routing control, Low Latency
class-map match-any system-cpp-police-system-critical
  description System Critical and Gold Pkt
class-map match-any system-cpp-police-ios-feature
  description ICMPGEN,BROADCAST,ICMP,L2LVXCntrl,ProtoSnoop,PuntWebauth,MCASTData,Transit,DOT1XAuth,Swfwd,LOGGING,L2LVXData,ForusTraffic,ForusARP,McastEndStn,Openflow,Exception,EGRExcption,NflSampled,RpfFailed
!
policy-map system-cpp-policy
!
!
!
!
!
!
!
!
!
!
!
interface Port-channel1
 switchport access vlan 113
 switchport mode access
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 shutdown
 negotiation auto
!
interface TwentyFiveGigE1/0/1
 description ESXI NODE 1 PORT 2
 switchport trunk native vlan 115
 switchport mode trunk
 no macro auto processing
!
interface TwentyFiveGigE1/0/2
 description ESXI NODE 1 PORT 4
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/3
 description ESXI NODE 2 PORT 2
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/4
 description ESXI NODE 2 PORT 4
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/5
 description ESXI NODE 3 PORT 2
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/6
 description ESXI NODE 3 PORT 4
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/7
 description ESXI NODE 4 PORT 2
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/8
 description ESXI NODE 4 PORT 4
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/9
 description UNITY DPE SPA MGMT
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE1/0/10
 description UNIT DPE SPB MGMT
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE1/0/11
 description IDPA PORT 3
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE1/0/12
 description IDPA PORT
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE1/0/13
!
interface TwentyFiveGigE1/0/14
!
interface TwentyFiveGigE1/0/15
 description SAN SPA PORT 0
 switchport trunk native vlan 115
 switchport trunk allowed vlan 1,45,112-116,118,119,124-127,192
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/16
 description SPB PORT 0
 switchport trunk native vlan 115
 switchport trunk allowed vlan 1,45,112-116,118,119,124-127,192
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/17
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE1/0/18
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE1/0/19
 description SAN SPA MOD1 PORT 0
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/20
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/21
 description SAN SPB MOD1 PORT 0
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/22
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE1/0/23
 shutdown
!
interface TwentyFiveGigE1/0/24
 stackwise-virtual dual-active-detection
 !
 interface HundredGigE1/0/25
 description To CoreA Fo1/1/1
 switchport mode trunk
!
interface HundredGigE1/0/26
 description To CoreB Fo1/1/1
 switchport mode trunk
!
interface HundredGigE1/0/27
 stackwise-virtual link 1
 !
 interface HundredGigE1/0/28
 stackwise-virtual link 1
 !
 interface TwentyFiveGigE2/0/1
 description ESXI NODE 1 PORT 1
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/2
 description ESXI NODE 1 PORT 3
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/3
 description ESXI NODE 2 PORT 1
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/4
 description ESXI NODE 2 PORT 3
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/5
 description ESXI NODE 3 PORT 1
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/6
 description ESXI NODE 3 PORT 3
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/7
 description ESXI NODE 4 PORT 1
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/8
 description ESXI NODE 4 PORT 3
 switchport trunk native vlan 115
 switchport trunk allowed vlan 10-13,115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/9
 description IDPA INT 0
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE2/0/10
 description IDPA INT 1
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE2/0/11
 description IDPA PORT 1
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/12
 description IDPA PORT 7
 switchport trunk native vlan 115
 switchport mode trunk
!
interface TwentyFiveGigE2/0/13
 switchport access vlan 113
 switchport mode access
 channel-group 1 mode active
!
interface TwentyFiveGigE2/0/14
 description SAN SPB
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE2/0/15
 description SAN SPA PORT 1
 switchport trunk native vlan 115
 switchport trunk allowed vlan 1,45,112-116,118,119,124-127,192
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/16
 description SPB PORT 1
 switchport trunk native vlan 115
 switchport trunk allowed vlan 1,45,112-116,118,119,124-127,192
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/17
 switchport access vlan 115
 switchport mode access
!
interface TwentyFiveGigE2/0/18
!
interface TwentyFiveGigE2/0/19
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/20
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/21
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/22
 description VLANS FOR SAN A AND B FIBER NON ROUTED
 switchport trunk allowed vlan 12,13
 switchport mode trunk
 spanning-tree link-type point-to-point
!
interface TwentyFiveGigE2/0/23
 shutdown
!
interface TwentyFiveGigE2/0/24
 stackwise-virtual dual-active-detection
 !
 interface HundredGigE2/0/25
 description To CoreA Fo1/1/2
 switchport mode trunk
!
interface HundredGigE2/0/26
 description To CoreB Fo1/1/2
 switchport mode trunk
!
interface HundredGigE2/0/27
 stackwise-virtual link 1
 !
 interface HundredGigE2/0/28
 stackwise-virtual link 1
 !
 interface Vlan1
 no ip address
!
interface Vlan60
 description OldBusiness
 no ip address
!
interface Vlan126
 ip address 10.20.126.197 255.255.255.0
!
ip forward-protocol nd
no ip http server
no ip http secure-server
ip route 0.0.0.0 0.0.0.0 10.20.126.254
ip ssh version 2
!
!
!
ip radius source-interface Vlan126
kron occurrence BACKUP_OCCURRENCE at 9:00 1 recurring
 policy-list CONFIGURATION_BACKUP
!
kron policy-list CONFIGURATION_BACKUP
 cli archive config
!
!
!
snmp-server group RO_ACCESS v3 priv read ALL_ACCESS
snmp-server group RO_ACCESS v3 priv context vlan- match prefix read ALL_ACCESS
snmp-server group LanSweeper v3 priv read cutdown
snmp-server view cutdown iso included
snmp-server view ALL_ACCESS iso included
snmp-server community private RW
snmp-server community public RO
snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart
snmp-server enable traps flowmon
snmp-server enable traps entity-perf throughput-notif
snmp-server enable traps call-home message-send-fail server-fail
snmp-server enable traps tty
snmp-server enable traps ospf state-change
snmp-server enable traps ospf errors
snmp-server enable traps ospf retransmit
snmp-server enable traps ospf lsa
snmp-server enable traps ospf cisco-specific state-change nssa-trans-change
snmp-server enable traps ospf cisco-specific state-change shamlink interface
snmp-server enable traps ospf cisco-specific state-change shamlink neighbor
snmp-server enable traps ospf cisco-specific errors
snmp-server enable traps ospf cisco-specific retransmit
snmp-server enable traps ospf cisco-specific lsa
snmp-server enable traps eigrp
snmp-server enable traps auth-framework sec-violation
snmp-server enable traps rep
snmp-server enable traps vtp
snmp-server enable traps vlancreate
snmp-server enable traps vlandelete
snmp-server enable traps port-security
snmp-server enable traps license
snmp-server enable traps smart-license
snmp-server enable traps cpu threshold
snmp-server enable traps memory bufferpeak
snmp-server enable traps stackwise
snmp-server enable traps udld link-fail-rpt
snmp-server enable traps udld status-change
snmp-server enable traps fru-ctrl
snmp-server enable traps flash insertion removal lowspace
snmp-server enable traps power-ethernet police
snmp-server enable traps entity
snmp-server enable traps pw vc
snmp-server enable traps mvpn
snmp-server enable traps envmon
snmp-server enable traps cef resource-failure peer-state-change peer-fib-state-change inconsistency
snmp-server enable traps lisp
snmp-server enable traps isis
snmp-server enable traps ipsla
snmp-server enable traps entity-diag boot-up-fail hm-test-recover hm-thresh-reached scheduled-test-fail
snmp-server enable traps bfd
snmp-server enable traps ike policy add
snmp-server enable traps ike policy delete
snmp-server enable traps ike tunnel start
snmp-server enable traps ike tunnel stop
snmp-server enable traps ipsec cryptomap add
snmp-server enable traps ipsec cryptomap delete
snmp-server enable traps ipsec cryptomap attach
snmp-server enable traps ipsec cryptomap detach
snmp-server enable traps ipsec tunnel start
snmp-server enable traps ipsec tunnel stop
snmp-server enable traps ipsec too-many-sas
snmp-server enable traps config-copy
snmp-server enable traps config
snmp-server enable traps config-ctid
snmp-server enable traps dhcp
snmp-server enable traps event-manager
snmp-server enable traps hsrp
snmp-server enable traps ipmulticast
snmp-server enable traps msdp
snmp-server enable traps ospfv3 state-change
snmp-server enable traps ospfv3 errors
snmp-server enable traps pim neighbor-change rp-mapping-change invalid-pim-message
snmp-server enable traps bridge newroot topologychange
snmp-server enable traps stpx inconsistency root-inconsistency loop-inconsistency
snmp-server enable traps syslog
snmp-server enable traps bgp cbgp2
snmp-server enable traps nhrp nhs
snmp-server enable traps nhrp nhc
snmp-server enable traps nhrp nhp
snmp-server enable traps nhrp quota-exceeded
snmp-server enable traps mpls rfc ldp
snmp-server enable traps mpls ldp
snmp-server enable traps mpls rfc traffic-eng
snmp-server enable traps mpls traffic-eng
snmp-server enable traps mpls fast-reroute protected
snmp-server enable traps local-auth
snmp-server enable traps vlan-membership
snmp-server enable traps errdisable
snmp-server enable traps rf
snmp-server enable traps transceiver all
snmp-server enable traps bulkstat collection transfer
snmp-server enable traps mac-notification change move threshold
snmp-server enable traps vrfmib vrf-up vrf-down vnet-trunk-up vnet-trunk-down
snmp-server enable traps mpls vpn
snmp-server enable traps mpls rfc vpn
snmp ifmib ifindex persist
!
radius-server key 7 023605484F2D210A1D
!
radius server NSKNK
 address ipv4 10.52.79.130 auth-port 1645 acct-port 1646
!
!
control-plane
 service-policy input system-cpp-policy
!
banner login ^CC********************  Warning  ********************
This device is property of Nucor Steel Kankakee.
Access to this device is restricted to authorized
persons only! Unauthorized access is prohibited.
Violators will be prosecuted.
*****************************************************C^C
!
line con 0
 logging synchronous
 stopbits 1
line aux 0
 stopbits 1
line vty 0 4
 privilege level 15
 logging synchronous
 login authentication deviceadmin
 length 0
 transport input ssh
line vty 5 15
!
ntp server 10.20.60.97
ntp server 10.20.60.30 prefer
!
!
!
!
!
!
end

"""


# Parse interface output.
interfaces = []
data_keys = re.split(" +", interface_output.splitlines()[0])
int_output = re.split("\n\n", interface_output)[0].splitlines()[1:]
interface_details = []
for line in int_output:
    # Split line by spaces.
    line = re.split(" +", line)
    # Check if the second to last element contains just CSR4. If so, then join the last two elements together.
    if "SR4" in line[-2]:
      # Get the last two elements and add them together.
        new_type = f"{line.pop(-4)} {line.pop(-3)} {line.pop(-2)} {line.pop(-1)}"
        # Reappend to line.
        line.append(new_type)
    # Check if the last element contains just SFP. If so, then join the last two elements together.
    elif line[-1] == "SFP" or line[-1] == "Present":
        # Get the last two elements and add them together.
        new_type = f"{line.pop(-2)} {line.pop(-1)}"
        # Reappend to line.
        line.append(new_type)
    # Check if the last element contains CU1M. If so, then join the last three elements together.
    elif line[-1] == "CU1M":
        # Get the last three elements and add them together.
        new_type = f"{line.pop(-3)} {line.pop(-2)} {line.pop(-1)}"
        # Reappend to line.
        line.append(new_type)

    # If the array is greater than a certain length, then the desc must have spaces.
    if len(line) > 7:
        # Break data back apart to isolate desc.
        last_data = line[-5:]
        first_data = [line[0]]
        # Join desc back into a single string.
        inbetween = [" ".join(line[1:-5])]
        # Rebuild line.
        line = first_data + inbetween + last_data
    # If the array is less than a certain length, then the desc must be empty.
    elif len(line) < 7:
        # Break data back apart to isolate desc.
        last_data = line[-5:]
        first_data = [line[0]]
        # Join desc back into a single string.
        inbetween = [""]
        # Rebuild line.
        line = first_data + inbetween + last_data
        
    # Match/zip values into a dictionary with the keys being the labels from the first line.
    interface_details.append(dict(zip(data_keys, line)))

for interface_dict in interface_details:
    # Even though we parsed all the data in the code above, we are just going to use two of the values for now.
    interfaces.append({"name" : interface_dict["Port"], "vlan_status": interface_dict["Vlan"]})

## Get individual interface data.
# Split up config by !.
config_blocks = re.split("!+", config)

interface_blocks = []
# Loop through the split up config blocks and only keep the interface ones.          
for block in config_blocks:
    # Check if the block contains the word interface.
    if "interface" in block:
        # Remove first two chars from block.
        block = block[1:]
        # split block up by new lines.
        block = block.splitlines()
        # Loop through the block and remove trailing and leading spaces for each line.
        new_block = []
        for line in block:
            new_block.append(line.strip())
        # Append to list.
        interface_blocks.append(new_block)

# Loop through the interfaces and blocks and match them by name.
for interface in interfaces:
    for interface_data in interface_blocks:
        # Get interface name.
        name_data = re.split(" +", interface_data[0])[1]
        block_name_two_letter = name_data[:2] + name_data.translate(str.maketrans('', '', string.ascii_letters + "-")).strip()
        block_name_three_letter = name_data[:3] + name_data.translate(str.maketrans('', '', string.ascii_letters + "-")).strip()
        # Check if names are equal.
        if interface["name"] == block_name_two_letter or interface["name"] == block_name_three_letter:
            # Add relevant info to the interface using the interface_data list.
            description = ""
            shutdown = False
            switch_mode_access = False
            switch_mode_trunk = False
            spanning_tree_portfast = False
            spanning_tree_bpduguard = False
            switch_access_vlan = 1
            switch_voice_vlan = 0
            switch_trunk_vlan = 0


            # Loop through each config line for the interface and get data.
            for data in interface_data:
                # Get Description info.
                if "description" in data and description == "" and "macro" not in data:
                    # Remove unneeded keyword from data.
                    data = data.replace("description", "")
                    # Remove trailing and leading spaces and set description equal to new data.
                    description = data.strip()

                # Get port shutdown info.
                if "shutdown" in data and not "no shutdown" in data:
                    # Set toggle.
                    shutdown = True

                # Check for sw mo acc interface flag.
                if "switchport mode access" in data:
                    # Set toggle.
                    switch_mode_access = True

                # Check for spanning tree.
                if "spanning-tree portfast" in data:
                    # Set toggle.
                    spanning_tree_portfast = True
                if "spanning-tree bpduguard enable" in data:
                    # Set toggle.
                    spanning_tree_bpduguard = True

                # Check for trunk mode data.
                if "switchport mode trunk" in data:
                    # Set toggle.
                    switch_mode_trunk = True

                # Check for access, voicem, and trunk vlan number.
                if "switchport access vlan" in data:
                    # Remove all letters from data.
                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                    # Remove trailing and leading whitespace and store.
                    switch_access_vlan = data.strip()
                if "switchport voice vlan" in data:
                    # Remove all letters from data.
                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                    # Remove trailing and leading whitespace and store.
                    switch_voice_vlan = data.strip()
                if "switchport trunk native vlan" in data:
                    # Remove all letters from data.
                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                    # Remove trailing and leading whitespace and store.
                    switch_trunk_vlan = data.strip()

                
            # Add description to interface dictionary.
            interface["description"] = description
            interface["shutdown"] = shutdown
            interface["switchport mode access"] = switch_mode_access
            interface["switchport mode trunk"] = switch_mode_trunk
            interface["spanning-tree portfast"] = spanning_tree_portfast
            interface["spanning-tree bpduguard enable"] = spanning_tree_bpduguard
            interface["switchport access vlan"] = switch_access_vlan
            interface["switchport voice vlan"] = switch_voice_vlan
            interface["switchport trunk native vlan"] = switch_trunk_vlan
            interface["config_has_changed"] = False
            print(interface)
