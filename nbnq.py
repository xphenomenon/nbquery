#
# Copyright (c) 2011, Michael Smith
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that
# the following conditions are met:
#
#     o  Redistributions of source code must retain the above copyright notice, this list of conditions and
#        the following disclaimer.
#     o  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and 
#        the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import socket
from struct import pack, unpack
from random import randint

# Refer to PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT:
#     RFC 1001 - CONCEPTS AND METHODS
#     RFC 1002 - DETAILED SPECIFICATIONS

class NetBIOS(object):
	# Socket settings
	BCAST_ADDR = "<broadcast>"
	BCAST_PORT = 137
	BCAST_REQ_TIMEOUT = 5
	BCAST_REQ_MAX_ATTEMPTS = 3
	
	# Resource Record attributes
	RR_TYPE_A = 0x0001
	RR_TYPE_NS = 0x0002
	RR_TYPE_NULL = 0x000A
	RR_TYPE_NB = 0x0020
	RR_TYPE_NBSTAT = 0x0021
	CLASS_IN = 0x0001 
	
	TYPE_UNKNOWN = 0x01
	TYPE_WORKSTATION = 0x00
	TYPE_CLIENT = 0x03
	TYPE_SERVER = 0x20
	TYPE_DOMAIN_MASTER = 0x1B
	TYPE_MASTER_BROWSER = 0x1D
	TYPE_BROWSER = 0x1E
	
	def __init__(self):
		try:
			self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self._socket.settimeout(NetBIOS.BCAST_REQ_TIMEOUT)
		except socket.error:
			self.__del__()
			raise

	def __del__(self):
		try:
			self._socket.close()
		except AttributeError:
			pass

	def _query(self, netbios_name, domain_name, type, rr_type):
		transaction_id = randint(1, 65535)
		attempt = 1
		while (attempt <= NetBIOS.BCAST_REQ_MAX_ATTEMPTS):
			try:
				self._socket.sendto(NetBIOS.NameServiceQuery.request().new(transaction_id, netbios_name, domain_name, type, rr_type), 0, (NetBIOS.BCAST_ADDR, NetBIOS.BCAST_PORT))
				while (True):
					response = NetBIOS.NameServiceQuery.response().read(self._socket.recv(65535))
					if not(response.header.transaction_id == transaction_id): continue # Ignore responses with the wrong transaction id
					resource_record = NetBIOS.NameServiceResourceRecord(response)
					if (resource_record.rr_type == rr_type): break # Ignore Negative/Redirect responses. BNODE should never get these, but just in case.
				break
			except socket.timeout:
				if (attempt == NetBIOS.BCAST_REQ_MAX_ATTEMPTS): raise NetBIOS.Timeout("Timed out. No response to request for %s." % netbios_name)
				attempt += 1
				
		return resource_record

	def get_ip(self, netbios_name, domain_name="", type=TYPE_WORKSTATION):
		return self._query(netbios_name, domain_name, type, NetBIOS.RR_TYPE_NB).get_ip()
		

	# Custom Exceptions		
	class Timeout(Exception): pass
	class UnsupportedFeature(Exception): pass
	
	
	class NameServiceHeader(object):
		class request(object):
			def new(self, transaction_id, qdcount=0, ancount=0, nscount=0, arcount=0, broadcast=True):
				if (broadcast): flags = 0x0110
				else: flags = 0x0100
				header = pack(">HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)
				return header
		
		class response(object):
			def read(self, data):
				self.transaction_id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount = unpack(">HHHHHH", data)
				if (self.flags & (1 << 9)): raise NetBIOS.UnsupportedFeature("Cannot handle truncated messages")
				return self
			
			
	class NameServiceQuery(object):
		class request(object):
			def encode(self, netbios_name, domain_name, type):
				if (len(netbios_name) > 15): netbios_name = "".join([netbios_name[:15], chr(type)])
				elif (len(netbios_name) < 15): netbios_name = "".join([netbios_name, " "*(15 - len(netbios_name)), chr(type)])
				encoded_name = "".join([(chr((ord(ch) >> 4) + 0x41) + chr((ord(ch) & 0x0F) + 0x41)) for ch in netbios_name])
				encoded_domain_name = ""
				if (domain_name): encoded_domain_name = "".join([ "%s%s" % (chr(len(label)), label) for label in domain_name.split(".")])
				return "%s%s%s%s" % ("\x20", encoded_name, encoded_domain_name, "\x00")
	
			def new(self, transaction_id, netbios_name, domain_name, type, rr_type):
				header = NetBIOS.NameServiceHeader.request().new(transaction_id, qdcount=1, broadcast=False)
				name = self.encode(netbios_name, domain_name, type)
				klass = NetBIOS.CLASS_IN
				message = "".join([name, pack(">HH", rr_type, klass)])
				return "".join([header, message])
	
		class response(object):
			def read(self, data):
				self.header = NetBIOS.NameServiceHeader.response().read(data[0:12])
				self.resource_record = data[12:]
				return self
			
			
	class NameServiceResourceRecord(object):
		def __init__(self, data):
			end_of_name = data.resource_record.find("\x00")
			self.name = data.resource_record[0:end_of_name]
			self.rr_type, self.rr_class, self.ttl, self.rdata_length = unpack(">HHIH", data.resource_record[end_of_name+1:end_of_name+11])
			self.rdata = data.resource_record[end_of_name+11:]
	
		def get_ip(self):
			if not(self.rr_type == NetBIOS.RR_TYPE_NB): return None
			ip = []
			addr_array = self.rdata
			while (len(addr_array) >= 6):
				ip.append("%d.%d.%d.%d" % unpack(">BBBB", addr_array[2:6]))
				addr_array = addr_array[6:]
			return ip
