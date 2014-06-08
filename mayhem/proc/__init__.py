#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/proc/__init__.py
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
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
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

import os
import uuid

class ProcessError(Exception):
	"""
	This base exception describes process related errors and are raised
	by :py:class:`mayhem.proc.Process` classes.
	"""
	def __init__(self, msg):
		self.msg = msg

	def __str__(self):
		return repr(self.msg)

class Hook:
	"""
	This object describes a hook which has been installed to modify the
	behavior of native code. This is generally used for hijacking functions
	to force them to execute different instructions when they are called.
	The *Hook* specifically referes to the data which has been modified
	to alter the flow of execution. This is generally a modified funciton
	pointer or an assembly stub which redirects code to the *new_handler*.
	"""
	def __init__(self, hook_type, hook_location, old_address, new_address):
		"""
		:param str hook_type: The type of hook (iat or eat).
		:param int hook_location: The address of where the hook has been installed.
		:param int old_address: The original address of the hooked function.
		:param int new_address: The new modified address of the hooked function.
		"""
		self.hook_type = hook_type
		self.hook_location = hook_location
		self.old_handler_address = old_address
		self.new_handler_address = new_address
		self.uid = uuid.uuid4()

	def __eq__(self, other):
		if not isinstance(other, Hook):
			return False
		if hasattr(other, 'uid'):
			if self.uid == other.uid:
				return True
		return False

class MemoryRegion(object):
	"""
	This describes a memory region in a platform independant way. Permissions
	are described with a string using 'rwx' for full read, write and execute
	permissions and substituting '-' for missing permissions. For example
	a page with only read and execute permissions would have permissions
	of 'r-x'.
	"""
	def __init__(self, addr_low, addr_high, perms):
		"""
		:param int addr_low: The address of where this memory region starts.
		:param int addr_high: The address of where this memory region ends.
		:param str perms: The permissions that this memory region has.
		"""
		self.addr_low = addr_low
		self.addr_high = addr_high
		self.perms = perms

	def __repr__(self):
		return "{0:08x}-{1:08x} {2}".format(self.addr_low, self.addr_high, self.perms)

	@property
	def size(self):
		"""The size of the memory region."""
		return (self.addr_high - self.addr_low)

	@property
	def is_readable(self):
		"""Whether or not the memory region contains the read permission."""
		return bool(self.perms[0] == 'r')

	@property
	def is_writeable(self):
		"""Whether or not the memory region contains the write permission."""
		return bool(self.perms[1] == 'w')

	@property
	def is_executable(self):
		"""Whether or not the memory region contains the execute permission."""
		return bool(self.perms[2] == 'x')

	@property
	def is_private(self):
		"""Whether or not the memory region is marked as private."""
		return bool(self.perms[3] == 'p')

	@property
	def is_shared(self):
		"""Whether or not the memory region is marked as shared."""
		return bool(self.perms[3] == 's')

class Process(object):
	__arch__ = None

	def __repr__(self):
		return "{0}(pid={1}, exe='{2}')".format(self.__class__.__name__, self.pid, os.path.basename(self.exe_file))

	def read_memory_string(self, address):
		string = ''
		while string.find('\x00') == -1:
			string += self.read_memory(address, 16)
			address += 16
		return string.split('\x00', 1)[0]

	def read_region(self, region):
		if isinstance(region, (int, long)):
			region = self.maps.get(region)
		return self.read_memory(region.addr_low, region.size)

	@property
	def arch(self):
		return self.__arch__
