#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/windows/_net.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  'AS IS' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import ctypes
import ipaddress
import socket

from ._scalars import *
from .. import common

__all__ = (
	'ADDRESS_FAMILY',
	'IF_INDEX',
	'IP_ADDRESS_PREFIX',
	'MIB_IPFORWARDROW',
	'MIB_IPFORWARDTABLE',
	'MIB_IPFORWARD_PROTO',
	'MIB_IPFORWARD_ROW2',
	'MIB_IPFORWARD_TABLE2',
	'MIB_IPFORWARD_TYPE',
	'MIB_IPINTERFACE_ROW',
	'NETIO_STATUS',
	'NET_IFINDEX',
	'NET_LUID',
	'NL_INTERFACE_OFFLOAD_ROD',
	'NL_LINK_LOCAL_ADDRESS_BEHAVIOR',
	'NL_ROUTE_ORIGIN',
	'NL_ROUTE_PROTOCOL',
	'NL_ROUTER_DISCOVERY_BEHAVIOR',
	'PIF_INDEX',
	'PMIB_IPFORWARDROW',
	'PMIB_IPFORWARDTABLE',
	'PMIB_IPFORWARD_ROW2',
	'PMIB_IPFORWARD_TABLE2',
	'PMIB_IPINTERFACE_ROW',
	'PNET_IFINDEX',
	'PNET_LUID',
	'PSOCKADDR_IN',
	'PSOCKADDR_IN6',
	'SCOPE_LEVEL',
	'SOCKADDR_IN',
	'SOCKADDR_IN6',
	'SOCKADDR_INET',
	'in6_addr',
	'in_addr',
	'ipaddress',
	'sockaddr_in',
	'sockaddr_in6',
	'socket'
)

NETIO_STATUS = DWORD
NET_IFINDEX = ctypes.c_uint32
PNET_IFINDEX = ctypes.POINTER(NET_IFINDEX)
IF_INDEX = NET_IFINDEX
PIF_INDEX = PNET_IFINDEX

class _NET_LUID_INFO(common.MayhemStructure):
	# see: https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/ifdef.h#L116
	_fields_ = [
		('Reserved', ctypes.c_uint64, 24),
		('NetLuidIndex', ctypes.c_uint64, 24),
		('IfType', ctypes.c_uint64, 16)
	]

class NET_LUID(common.MayhemUnion):
	# see: https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/ifdef.h#L116
	_fields_ = [
		('Value', ctypes.c_uint64),
		('Info', _NET_LUID_INFO)
	]
PNET_LUID = ctypes.POINTER(NET_LUID)

class ADDRESS_FAMILY(common.MayhemEnum):
	AF_UNSPEC = 0
	AF_INET = 2
	AF_INET6 = 23
	@classmethod
	def get_ctype(cls):
		return USHORT

class _in_addr_u0_s0(common.MayhemStructure):
	_fields_ = [
		('s_b1', ctypes.c_uint8),
		('s_b2', ctypes.c_uint8),
		('s_b3', ctypes.c_uint8),
		('s_b4', ctypes.c_uint8)
	]

class _in_addr_u0_s1(common.MayhemStructure):
	_fields_ = [
		('s_w1', ctypes.c_ushort),
		('s_w2', ctypes.c_ushort)
	]

class _in_addr_u0(common.MayhemUnion):
	_fields_ = [
		('S_un_b', _in_addr_u0_s0),
		('S_un_w', _in_addr_u0_s1),
		('S_addr', ctypes.c_ulong),
	]

class in_addr(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
	"""
	_fields_ = [
		('S_un', _in_addr_u0),
	]
	def __repr__(self):
		return "<{} ({}) >".format(self.__class__.__name__, str(self.to_ip_address()))

	@classmethod
	def from_ip_address(cls, ip_address):
		if isinstance(ip_address, str):
			ip_address = ipaddress.IPv4Address(ip_address)
		if not isinstance(ip_address, ipaddress.IPv4Address):
			raise TypeError('ip_address must be an IPv4 address')
		self = cls()
		self.S_un.S_addr = socket.ntohl(int(ip_address))
		return self

	def to_ip_address(self):
		return ipaddress.IPv4Address(socket.htonl(self.S_un.S_addr))

class sockaddr_in(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
	"""
	_fields_ = [
		('sin_family', ctypes.c_short),
		('sin_port', ctypes.c_ushort),
		('sin_addr', in_addr),
		('sin_zero', ctypes.c_char * 8)
	]
	def __init__(self, sin_family=ADDRESS_FAMILY.AF_INET, **kwargs):
		return super().__init__(sin_family=sin_family, **kwargs)

	def __repr__(self):
		return "<{} ({}:{}) >".format(self.__class__.__name__, str(self.sin_addr.to_ip_address()), self.sin_port)

	def to_ip_address(self):
		return self.sin_addr.to_ip_address()
SOCKADDR_IN = sockaddr_in
PSOCKADDR_IN = ctypes.POINTER(SOCKADDR_IN)

class _in6_addr_u0(common.MayhemUnion):
	"""see:
	https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms738560(v=vs.85)
	"""
	_fields_ = [
		('Byte', ctypes.c_uint8 * 16),
		('Word', ctypes.c_ushort * 8),
	]

class in6_addr(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms738560(v=vs.85)
	"""
	_fields_ = [
		('u', _in6_addr_u0)
	]
	def __repr__(self):
		return "<{} ({}) >".format(self.__class__.__name__, str(self.to_ip_address()))

	@classmethod
	def from_ip_address(cls, ip_address):
		if isinstance(ip_address, str):
			ip_address = ipaddress.IPv6Address(ip_address)
		if not isinstance(ip_address, ipaddress.IPv6Address):
			raise TypeError('ip_address must be an IPv6 address')
		self = cls()
		for index, value in enumerate(ip_address.packed):
			self.u.Byte[index] = value
		return self

	def to_ip_address(self):
		return ipaddress.IPv6Address(bytes(self.u.Byte))

class sockaddr_in6(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_in6_lh
	"""
	_fields_ = [
		('sin6_family', ctypes.c_short),
		('sin6_port', ctypes.c_ushort),
		('sin6_flowinfo', ctypes.c_ulong),
		('sin6_addr', in6_addr),
		('sin6_scope_id', ctypes.c_ulong)
	]
	def __init__(self, sin6_family=ADDRESS_FAMILY.AF_INET6, **kwargs):
		return super().__init__(sin6_family=sin6_family, **kwargs)

	def __repr__(self):
		return "<{} ([{}]:{}) >".format(self.__class__.__name__, str(self.sin6_addr.to_ip_address()), self.sin6_port)

	def to_ip_address(self):
		return self.sin6_addr.to_ip_address()
SOCKADDR_IN6 = sockaddr_in6
PSOCKADDR_IN6 = ctypes.POINTER(SOCKADDR_IN6)

class SOCKADDR_INET(common.MayhemUnion):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
	"""
	_fields_ = [
		('Ipv4', SOCKADDR_IN),
		('Ipv6', SOCKADDR_IN6),
		('si_family', ADDRESS_FAMILY)
	]
	def __repr__(self):
		if self.si_family == ADDRESS_FAMILY.AF_INET:
			return "<{} ({}:{}) >".format(self.__class__.__name__, str(self.Ipv4.to_ip_address()), self.Ipv4.sin_port)
		elif self.si_family == ADDRESS_FAMILY.AF_INET6:
			return "<{} ([{}]:{}) >".format(self.__class__.__name__, str(self.Ipv6.to_ip_address()), self.Ipv6.sin6_port)
		return "<{} >".format(self.__class__.__name__)

	def to_ip_address(self):
		if self.si_family == ADDRESS_FAMILY.AF_INET:
			return self.Ipv4.to_ip_address()
		elif self.si_family == ADDRESS_FAMILY.AF_INET6:
			return self.Ipv6.to_ip_address()
		return None

class NL_LINK_LOCAL_ADDRESS_BEHAVIOR(common.MayhemEnum):
	LinkLocalAlwaysOff = 0
	LinkLocalDelayed = 1
	LinkLocalAlwaysOn = 2
	LinkLocalUnchanged = -1

class NL_ROUTE_ORIGIN(common.MayhemEnum):
	NlroManual = 0
	NlroWellKnown = 1
	NlroDHCP = 2
	NlroRouterAdvertisement = 3
	Nlro6to4 = 4

class NL_ROUTE_PROTOCOL(common.MayhemEnum):
	RouteProtocolOther = 0
	RouteProtocolLocal = 1
	RouteProtocolNetMgmt = 2
	RouteProtocolIcmp = 3
	RouteProtocolEgp = 4
	RouteProtocolGgp = 5
	RouteProtocolHello = 6
	RouteProtocolRip = 7
	RouteProtocolIsIs = 8
	RouteProtocolEsIs = 9
	RouteProtocolCisco = 10
	RouteProtocolBbn = 11
	RouteProtocolOspf = 12
	RouteProtocolBgp = 13
	RouteProtocolIdpr = 14
	RouteProtocolEigrp = 15
	RouteProtocolDvmrp = 16
	RouteProtocolRpl = 17
	RouteProtocolDhcp = 18

class NL_ROUTER_DISCOVERY_BEHAVIOR(common.MayhemEnum):
	RouterDiscoveryDisabled = 0
	RouterDiscoveryEnabled = 1
	RouterDiscoveryDhcp = 2
	RouterDiscoveryUnchanged = -1

class MIB_IPFORWARD_PROTO(common.MayhemEnum):
	# see: https://docs.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow
	MIB_IPPROTO_OTHER = 1
	MIB_IPPROTO_LOCAL = 2
	MIB_IPPROTO_NETMGMT = 3
	MIB_IPPROTO_ICMP = 4
	MIB_IPPROTO_EGP = 5
	MIB_IPPROTO_GGP = 6
	MIB_IPPROTO_HELLO = 7
	MIB_IPPROTO_RIP = 8
	MIB_IPPROTO_IS_IS = 9
	MIB_IPPROTO_ES_IS = 10
	MIB_IPPROTO_CISCO = 11
	MIB_IPPROTO_BBN = 12
	MIB_IPPROTO_OSPF = 13
	MIB_IPPROTO_BGP = 14
	MIB_IPPROTO_NT_AUTOSTATIC = 10002
	MIB_IPPROTO_NT_STATIC = 10006
	MIB_IPPROTO_NT_STATIC_NON_DOD = 10007

class MIB_IPFORWARD_TYPE(common.MayhemEnum):
	# see: https://docs.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow
	MIB_IPROUTE_TYPE_OTHER = 1
	MIB_IPROUTE_TYPE_INVALID = 2
	MIB_IPROUTE_TYPE_DIRECT = 3
	MIB_IPROUTE_TYPE_INDIRECT = 4

class SCOPE_LEVEL(common.MayhemEnum):
	ScopeLevelInterface = 1
	ScopeLevelLink = 2
	ScopeLevelSubnet = 3
	ScopeLevelAdmin = 4
	ScopeLevelSite = 5
	ScopeLevelOrganization = 8
	ScopeLevelGlobal = 14
	ScopeLevelCount = 16

class IP_ADDRESS_PREFIX(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
	"""
	_fields_ = [
		('Prefix', SOCKADDR_INET),
		('PrefixLength', ctypes.c_uint8)
	]

class NL_INTERFACE_OFFLOAD_ROD(common.MayhemStructure):
	_fields_ = [
		('NlChecksumSupported', BOOLEAN, 1),
		('NlOptionsSupported', BOOLEAN, 1),
		('TlDatagramChecksumSupported', BOOLEAN, 1),
		('TlStreamChecksumSupported', BOOLEAN, 1),
		('TlStreamOptionsSupported', BOOLEAN, 1),
		('FastPathCompatible', BOOLEAN, 1),
		('TlLargeSendOffloadSupported', BOOLEAN, 1),
		('TlGiantSendOffloadSupported', BOOLEAN, 1),
	]

class _MIB_IPFORWARDROW_U0(common.MayhemUnion):
	_fields_ = [
		('dwForwardType', DWORD),
		('ForwardType', MIB_IPFORWARD_TYPE)
	]

class _MIB_IPFORWARDROW_U1(common.MayhemUnion):
	_fields_ = [
		('dwForwardProto', DWORD),
		('ForwardProto', MIB_IPFORWARD_PROTO)
	]

class MIB_IPFORWARDROW(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow
	"""
	_anonymous_ = ('u0', 'u1')
	_fields_ = [
		('dwForwardDest', DWORD),
		('dwForwardMask', DWORD),
		('dwForwardPolicy', DWORD),
		('dwForwardNextHop', DWORD),
		('dwForwardIfIndex', IF_INDEX),
		('u0', _MIB_IPFORWARDROW_U0),
		('u1', _MIB_IPFORWARDROW_U1),
		('dwForwardAge', DWORD),
		('dwForwardNextHopAS', DWORD),
		('dwForwardMetric1', DWORD),
		('dwForwardMetric2', DWORD),
		('dwForwardMetric3', DWORD),
		('dwForwardMetric4', DWORD),
		('dwForwardMetric5', DWORD),
	]
PMIB_IPFORWARDROW = ctypes.POINTER(MIB_IPFORWARDROW)

class MIB_IPFORWARD_ROW2(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
	"""
	_fields_ = [
		('InterfaceLuid', NET_LUID),
		('InterfaceIndex', NET_IFINDEX),
		('DestinationPrefix', IP_ADDRESS_PREFIX),
		('NextHop', SOCKADDR_INET),
		('SitePrefixLength', UCHAR),
		('ValidLifetime', ULONG),
		('PreferredLifetime', ULONG),
		('Metric', ULONG),
		('Protocol', NL_ROUTE_PROTOCOL),
		('Loopback', BOOLEAN),
		('AutoconfigureAddress', BOOLEAN),
		('Publish', BOOLEAN),
		('Immortal', BOOLEAN),
		('Age', ULONG),
		('Origin', NL_ROUTE_PROTOCOL),
	]
PMIB_IPFORWARD_ROW2 = ctypes.POINTER(MIB_IPFORWARD_ROW2)

class MIB_IPFORWARDTABLE(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardtable
	"""
	_fields_ = [
		('dwNumEntries', DWORD),
		('table', MIB_IPFORWARDROW * 0)
	]
PMIB_IPFORWARDTABLE = ctypes.POINTER(MIB_IPFORWARDTABLE)

class MIB_IPFORWARD_TABLE2(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2
	"""
	_fields_ = [
		('NumEntries', ULONG),
		('Table', MIB_IPFORWARD_ROW2 * 0)
	]
PMIB_IPFORWARD_TABLE2 = ctypes.POINTER(MIB_IPFORWARD_TABLE2)

class MIB_IPINTERFACE_ROW(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
	"""
	_fields_ = [
		('Family', ADDRESS_FAMILY),
		('InterfaceLuid', NET_LUID),
		('InterfaceIndex', NET_IFINDEX),
		('MaxReassemblySize', ULONG),
		('InterfaceIdentifier', ULONG64),
		('MinRouterAdvertisementInterval', ULONG),
		('MaxRouterAdvertisementInterval', ULONG),
		('AdvertisingEnabled', BOOLEAN),
		('ForwardingEnabled', BOOLEAN),
		('WeakHostSend', BOOLEAN),
		('WeakHostReceive', BOOLEAN),
		('UseAutomaticMetric', BOOLEAN),
		('UseNeighborUnreachabilityDetection', BOOLEAN),
		('ManagedAddressConfigurationSupported', BOOLEAN),
		('OtherStatefulConfigurationSupported', BOOLEAN),
		('AdvertiseDefaultRoute', BOOLEAN),
		('RouterDiscoveryBehavior', NL_ROUTER_DISCOVERY_BEHAVIOR),
		('DadTransmits', ULONG),
		('BaseReachableTime', ULONG),
		('RetransmitTime', ULONG),
		('PathMtuDiscoveryTimeout', ULONG),
		('LinkLocalAddressBehavior', NL_LINK_LOCAL_ADDRESS_BEHAVIOR),
		('LinkLocalAddressTimeout', ULONG),
		('ZoneIndices', ULONG * SCOPE_LEVEL.ScopeLevelCount),
		('SitePrefixLength', ULONG),
		('Metric', ULONG),
		('NlMtu', ULONG),
		('Connected', BOOLEAN),
		('SupportsWakeUpPatterns', BOOLEAN),
		('SupportsNeighborDiscovery', BOOLEAN),
		('SupportsRouterDiscovery', BOOLEAN),
		('ReachableTime', ULONG),
		('TransmitOffload', NL_INTERFACE_OFFLOAD_ROD),
		('ReceiveOffload', NL_INTERFACE_OFFLOAD_ROD),
		('DisableDefaultRoutes', BOOLEAN),
	]
PMIB_IPINTERFACE_ROW = ctypes.POINTER(MIB_IPINTERFACE_ROW)