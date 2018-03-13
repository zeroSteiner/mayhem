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

	def __hash__(self):
		return hash(self.addr_low, self.addr_high, self.perms)

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

class ProcessBase(object):
	__arch__ = None
	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.close()

	def __repr__(self):
		return "{0}(pid={1}, exe='{2}')".format(self.__class__.__name__, self.pid, os.path.basename(self.exe_file))

	def read_memory_string(self, address):
		"""
		Read bytes from *address* until a NULL termination character is
		encountered.

		:param int address: The address to start reading from.
		:return: The string residing at *address*.
		:rtype: str
		"""
		string = b''
		while string.find(b'\x00') == -1:
			string += self.read_memory(address, 16)
			address += 16
		return string.split(b'\x00', 1)[0]

	def read_region(self, region):
		"""
		Read an entire region from memory. If *region* is a
		:py:class:`.MemoryRegion` instance, it is returned. If *region*
		is an int, it must be the starting address of a memory region in
		the :py:attr:`.maps` attribute.

		:param region: The region to read from.
		:type region: int, :py:class:`.MemoryRegion`
		:return: The contents of the memory region.
		:rtype: str
		"""
		if isinstance(region, int):
			region = self.maps.get(region)
		return self.read_memory(region.addr_low, region.size)

	def allocate(self, size=0x400, address=None, permissions=None):
		"""
		Allocate memory in the attached process. If *permissions* is not
		specified it will be the platform specific version of read, write
		and execute.

		:param int size: The size of the space to allocate.
		:param int address: The preferred address to allocate space at.
		:param str permissions: The permissions to set in the newly allocated space.
		"""
		raise NotImplementedError()

	def close(self):
		"""
		Close the handle to the process and perform any necessary clean
		up operations. No further calls should be made to the object after
		this function is called.
		"""
		raise NotImplementedError()

	def free(self, address):
		"""
		Unallocate the memory at *address*.

		:param int address: The address to unallocate.
		"""
		raise NotImplementedError()

	def get_proc_attribute(self, attribute):
		"""
		Look up a platform specific attribute of the process. Valid values
		for *attribute* will be different depending on the class.

		:param str attribute: The attribute to look up.
		"""
		raise NotImplementedError()

	def install_hook(self, mod_name, new_address, name=None, ordinal=None):
		"""
		Install a hook to redirect execution from the specified function
		to *new_address*. Different platform implemenations of this function
		may not support both the *name* and *ordinal* parameters.

		:param str mod_name: The module where the target function to hook resides.
		:param int new_address: The address of the new code to be executed.
		:param str name: The name of the function to hook.
		:param int ordinal: The ordinal of the function to hook.
		"""
		raise NotImplementedError()

	def join_thread(self, thread_id):
		"""
		Wait for the thread described in *thread_id* to finish execution.

		:param int thread_id: The ID of the thread to wait for.
		"""
		raise NotImplementedError()

	def kill(self):
		"""Kill the process which is currently being manipulated."""
		raise NotImplementedError()

	def load_library(self, libpath):
		"""
		Load the library specified by *libpath* into the address space
		of the attached process.

		:param str libpath: The path to the library to load.
		"""
		raise NotImplementedError()

	def protect(self, address, permissions=None, size=0x400):
		"""
		Change the access permissions to the memory residing at *address*.
		If *permissions* is not specified it will be the platform specific
		version of read, write and execute.

		:param int address: The address to change the permissions of.
		:param str permissions: The permissions to set for *address*.
		:param int size: The size of the space starting at *address* to change the permissions of.
		"""
		raise NotImplementedError()

	def read_memory(self, address, size=0x400):
		"""
		Return the contents of memory at *address*.

		:param int address: The location from which to read memory.
		:param int size: The number of bytes to read.
		:return: The contents of memory at *address*.
		:rtype: str
		"""
		raise NotImplementedError()

	def start_thread(self, address, targ=None):
		"""
		Execute *address* in the context of a new thread.

		:param int address: The entry point of the thread.
		:param targ: The arguments to supply for the thread.
		:return: A platform specific thread identifier.
		"""
		raise NotImplementedError()

	def write_memory(self, address, data):
		"""
		Write arbitrary data to the processes memory.

		:param int address: The location to start writing to.
		:param str data: The data to write into memory.
		"""
		raise NotImplementedError()

	@property
	def arch(self):
		"""The architecture of the process."""
		return self.__arch__
