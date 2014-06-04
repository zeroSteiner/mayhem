#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/proc/windows.py
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

import ctypes
import os
import platform

from mayhem.proc import Process, ProcessError, Hook, MemoryRegion
from mayhem.datatypes import windows as wintypes
from mayhem.utilities import eval_number

CONSTANTS = {
	'GENERIC_READ': 0x80000000,
	'GENERIC_WRITE': 0x40000000,

	'OPEN_EXISTING': 0x03,
	'CREATE_ALWAYS': 0x02,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx
	'MEM_COMMIT': 0x00001000,
	'MEM_RESERVE': 0x00002000,
	'MEM_RESET': 0x00080000,
	'MEM_RESET_UNDO': 0x01000000,
	'MEM_LARGE_PAGES': 0x20000000,
	'MEM_PHYSICAL': 0x00400000,
	'MEM_TOP_DOWN': 0x00100000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775%28v=vs.85%29.aspx
	'MEM_IMAGE': 0x01000000,
	'MEM_MAPPED': 0x00040000,
	'MEM_PRIVATE': 0x00020000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366894%28v=vs.85%29.aspx
	'MEM_DECOMMIT': 0x4000,
	'MEM_RELEASE': 0x8000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366786%28v=vs.85%29.aspx
	'PAGE_EXECUTE': 0x10,
	'PAGE_EXECUTE_READ': 0x20,
	'PAGE_EXECUTE_READWRITE': 0x40,
	'PAGE_EXECUTE_WRITECOPY': 0x80,
	'PAGE_NOACCESS': 0x01,
	'PAGE_READONLY': 0x02,
	'PAGE_READWRITE': 0x04,
	'PAGE_WRITECOPY': 0x08,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx
	'PROCESS_CREATE_PROCESS': 0x0080,
	'PROCESS_CREATE_THREAD': 0x0002,
	'PROCESS_DUP_HANDLE': 0x0040,
	'PROCESS_QUERY_INFORMATION': 0x0400,
	'PROCESS_QUERY_LIMITED_INFORMATION': 0x1000,
	'PROCESS_SET_INFORMATION': 0x0200,
	'PROCESS_SET_QUOTA': 0x0100,
	'PROCESS_SUSPEND_RESUME': 0x0800,
	'PROCESS_TERMINATE': 0x0001,
	'PROCESS_VM_OPERATION': 0x0008,
	'PROCESS_VM_READ': 0x0010,
	'PROCESS_VM_WRITE': 0x0020,
	'SYNCHRONIZE': 0x00100000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858%28v:vs.85%29.aspx
	'FILE_SHARE_READ': 0x00000001,
	'FILE_SHARE_WRITE': 0x00000002,
	'FILE_SHARE_DELETE': 0x00000004,

	'FILE_FLAG_OVERLAPPED': 0x40000000
}

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_TLS = 9

class WindowsProcessError(ProcessError):
	def __init__(self, *args, **kwargs):
		self.get_last_error = None
		if 'get_last_error' in kwargs:
			self.get_last_error = kwargs['get_last_error']
			del kwargs['get_last_error']
		ProcessError.__init__(self, *args, **kwargs)

def flags(flags):
	supported_operators = ['|', '+', '-', '^']
	if isinstance(flags, (int, long)):
		return flags
	if flags[0] == '(' and flags[-1] == ')':
		flags = flags[1:-1]
	for sop in supported_operators:
		flags = flags.replace(sop, ' ' + sop + ' ')
	flags
	flags = flags.split()
	parsed_flags = 0
	last_operator = None
	for part in flags:
		if part in CONSTANTS:
			part = CONSTANTS[part]
		elif part in supported_operators:
			last_operator = part
			continue
		else:
			part = eval_number(part)
		if last_operator == None:
			parsed_flags = part
		else:
			parsed_flags = eval(str(parsed_flags) + last_operator + str(part))
	return parsed_flags

class WindowsProcess(Process):
	def __init__(self, pid=None, exe=None, handle=None, arch='x86', access=None):
		if platform.system() != 'Windows':
			raise RuntimeError('incompatible platform')
		self.__arch__ = arch
		self.k32 = ctypes.windll.kernel32
		self.ntdll = ctypes.windll.ntdll
		self.psapi = ctypes.windll.psapi

		self.handle = None
		if pid == -1:
			handle = -1
			pid = None
		if access == None:
			access = "(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_TERMINATE)"
		if pid:
			self.handle = self.k32.OpenProcess(flags(access), False, pid)
			if not self.handle:
				raise ProcessError('could not open PID')
		elif exe:
			startupinfo = wintypes.STARTUPINFO()
			process_info = wintypes.PROCESS_INFORMATION()
			startupinfo.dwFlags = 0x01
			startupinfo.wShowWindow = 0x00
			startupinfo.cb = ctypes.sizeof(startupinfo)
			self.k32.CreateProcessA(exe, None, None, None, True, 0, None, None, ctypes.byref(startupinfo), ctypes.byref(process_info))
			self.handle = process_info.hProcess
			if not self.handle:
				raise ProcessError('could not the create process')
		elif handle:
			self.handle = handle
		else:
			raise ProcessError('either a pid, exe or a handle must be specified')
		self.pid = self.k32.GetProcessId(self.handle)
		_name = (ctypes.c_char * 0x400)
		name = _name()
		if hasattr(self.psapi, 'GetModuleFileNameExA'):
			self.psapi.GetModuleFileNameExA(self.handle, 0, name, ctypes.sizeof(name))
		else:
			self.k32.GetModuleFileNameExA(self.handle, 0, name, ctypes.sizeof(name))
		self.exe_file = ''.join(name).rstrip('\x00')
		self._installed_hooks = []
		self._update_maps()

	def __del__(self):
		if self.handle:
			self.close()

	def get_proc_attribute(self, attribute):
		requested_attribute = attribute
		if attribute.startswith('&'):
			attribute = attribute[1:] + '_addr'
		if hasattr(self, '_get_attr_' + attribute):
			return getattr(self, '_get_attr_' + attribute)()
		raise ProcessError('Unknown Attribute: ' + requested_attribute)

	def _get_attr_peb_addr(self):
		process_basic_information = wintypes.PROCESS_BASIC_INFORMATION()
		return_length = wintypes.DWORD()
		self.ntdll.NtQueryInformationProcess(self.handle, 0, ctypes.byref(process_basic_information), ctypes.sizeof(process_basic_information), ctypes.byref(return_length))
		return process_basic_information.PebBaseAddress

	def _get_attr_peb(self):
		peb_addr = self.get_proc_attribute('peb_addr')
		peb = wintypes.PEB()
		self.k32.ReadProcessMemory(self.handle, peb_addr, ctypes.byref(peb), ctypes.sizeof(peb), 0)
		return peb

	def _get_attr_peb_ldr_data_addr(self):
		peb = self.get_proc_attribute('peb')
		return peb.Ldr

	def _get_attr_peb_ldr_data(self):
		peb_ldr_data_addr = self.get_proc_attribute('peb_ldr_data_addr')
		peb_ldr_data = wintypes.PEB_LDR_DATA()
		self.k32.ReadProcessMemory(self.handle, peb_ldr_data_addr, ctypes.byref(peb_ldr_data), ctypes.sizeof(peb_ldr_data), 0)
		return peb_ldr_data

	def _get_attr_image_dos_header_addr(self):
		return self.get_proc_attribute('peb').ImageBaseAddress

	def _get_attr_image_dos_header(self):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		image_dos_header = wintypes.IMAGE_DOS_HEADER()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr, ctypes.byref(image_dos_header), ctypes.sizeof(image_dos_header), 0)
		return image_dos_header

	def _get_attr_image_nt_headers_addr(self):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		image_dos_header = self.get_proc_attribute('image_dos_header')
		return image_dos_header_addr + image_dos_header.e_lfanew

	def _get_attr_image_nt_headers(self):
		if self.__arch__ == 'x86':
			image_nt_headers = wintypes.IMAGE_NT_HEADERS32()
		else:
			raise Exception('the selected architecture is not supported')
		self.k32.ReadProcessMemory(self.handle, self.get_proc_attribute('image_nt_headers_addr'), ctypes.byref(image_nt_headers), ctypes.sizeof(image_nt_headers), 0)
		return image_nt_headers

	def _get_attr_image_import_descriptor_addr(self):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		optional_header = self.get_proc_attribute('image_nt_headers').OptionalHeader
		return image_dos_header_addr + optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress

	def _get_attr_image_import_descriptor(self):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		optional_header = self.get_proc_attribute('image_nt_headers').OptionalHeader

		import_directory = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
		_import_descriptors = wintypes.IMAGE_IMPORT_DESCRIPTOR * ((import_directory.Size / ctypes.sizeof(wintypes.IMAGE_IMPORT_DESCRIPTOR)) - 1)
		import_descriptors = _import_descriptors()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr + import_directory.VirtualAddress, ctypes.byref(import_descriptors), ctypes.sizeof(import_descriptors), 0)
		return import_descriptors

	def _get_attr_system_info(self):
		system_info = wintypes.SYSTEM_INFO()
		self.k32.GetSystemInfo(ctypes.byref(system_info))
		return system_info

	def _get_name_for_ilt_entry(self, ilt_ent):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		_name = (ctypes.c_char * 0x200)
		name = _name()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr + ilt_ent + ctypes.sizeof(wintypes.WORD), ctypes.byref(name), ctypes.sizeof(name), 0)
		name = ''.join(name)
		name = name.split('\x00')[0]
		return name

	def _get_ordinal_for_ilt_entry(self, ilt_ent):
		return (ilt_ent & 0x7FFFFFFF)

	def _get_name_for_image_import_descriptor(self, iid):
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		_name = (ctypes.c_char * 0x400)
		name = _name()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr + iid.Name, ctypes.byref(name), ctypes.sizeof(name), 0)
		name = ''.join(name)
		name = name.split('\x00')[0]
		return name

	def _get_ilt_for_image_import_descriptor(self, iid): # import lookup table
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		_ilt = (ctypes.c_void_p * 0x200)
		ilt = _ilt()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr + iid.OriginalFirstThunk, ctypes.byref(ilt), ctypes.sizeof(ilt), 0)
		return ilt

	def _get_iat_for_image_import_descriptor(self, iid): # import address table
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		_iat = (ctypes.c_void_p * 0x200)
		iat = _iat()
		self.k32.ReadProcessMemory(self.handle, image_dos_header_addr + iid.FirstThunk, ctypes.byref(iat), ctypes.sizeof(iat), 0)
		return iat

	def _get_image_base_by_name(self, name):
		peb_ldr_data = self.get_proc_attribute('peb_ldr_data')

		firstFLink = 0
		fLink = peb_ldr_data.InLoadOrderModuleList.Flink
		while fLink != firstFLink:
			firstFLink = peb_ldr_data.InLoadOrderModuleList.Flink
			module = wintypes.LDR_MODULE()

			self.k32.ReadProcessMemory(self.handle, fLink, ctypes.byref(module), ctypes.sizeof(module), 0)

			_base_dll_name = (ctypes.c_wchar * module.BaseDllName.MaximumLength)
			base_dll_name = _base_dll_name()

			self.k32.ReadProcessMemory(self.handle, module.BaseDllName.Buffer, base_dll_name, module.BaseDllName.Length + 2, 0)
			base_dll_name = base_dll_name[:(module.BaseDllName.Length / 2)]
			if name == base_dll_name:
				return module
			fLink = module.InLoadOrderModuleList.Flink
		return None

	def _update_maps(self):
		sys_info = self.get_proc_attribute('system_info')
		self.maps = {}
		address_cursor = 0
		if platform.architecture()[0] == '64bit':
			meminfo = wintypes.MEMORY_BASIC_INFORMATION64()
		else:
			meminfo = wintypes.MEMORY_BASIC_INFORMATION()
		MEM_COMMIT = flags('MEM_COMMIT')
		MEM_PRIVATE = flags('MEM_PRIVATE')
		PROTECT_FLAGS = {0x10: '--x', 0x20: 'r-x', 0x40: 'rwx', 0x80: 'r-x', 0x01: '---', 0x02: 'r--', 0x04: 'rw-', 0x08: 'r--'}
		while address_cursor < sys_info.lpMaximumApplicationAddress:
			if self.k32.VirtualQueryEx(self.handle, address_cursor, ctypes.byref(meminfo), ctypes.sizeof(meminfo)) == 0:
				break
			address_cursor = meminfo.BaseAddress + meminfo.RegionSize
			if (meminfo.State & MEM_COMMIT) == 0:
				continue
			addr_low = meminfo.BaseAddress
			addr_high = address_cursor
			perms = PROTECT_FLAGS[(meminfo.Protect & 0xff)]
			if (meminfo.Type & MEM_PRIVATE) == 0:
				perms += 's'
			else:
				perms += 'p'
			self.maps[addr_low] = MemoryRegion(addr_low, addr_high, perms)
		return

	def install_hook(self, mod_name, new_address, name=None, ordinal=None):
		if not (bool(name) ^ bool(ordinal)):
			raise ValueError('must select either name or ordinal, not both')
		image_import_descriptors = self.get_proc_attribute('image_import_descriptor')
		image_dos_header_addr = self.get_proc_attribute('image_dos_header_addr')
		is_ordinal = lambda x: bool(x & 0x80000000)

		for iid in image_import_descriptors:
			cur_mod_name = self._get_name_for_image_import_descriptor(iid)
			if cur_mod_name.lower() != mod_name.lower():
				continue
			ilt = self._get_ilt_for_image_import_descriptor(iid)
			iat = self._get_iat_for_image_import_descriptor(iid)

			for idx in xrange(len(ilt)):
				if ilt[idx] == None:
					continue
				hook_it = False
				if not is_ordinal(ilt[idx]) and name:
					cur_func_name = self._get_name_for_ilt_entry(ilt[idx])
					if cur_func_name == name:
						hook_it = True
				elif is_ordinal(ilt[idx]) and ordinal:
					cur_func_ordinal = self._get_ordinal_for_ilt_entry(ilt[idx])
					if cur_func_ordinal == ordinal:
						hook_it = True
				if hook_it:
					old_address = iat[idx]

					iat_ent_addr = image_dos_header_addr
					iat_ent_addr += iid.FirstThunk
					iat_ent_addr += (ctypes.sizeof(ctypes.c_void_p) * idx)

					new_addr = ctypes.c_void_p()
					new_addr.value = new_address
					written = wintypes.DWORD()
					if self.k32.WriteProcessMemory(self.handle, iat_ent_addr, ctypes.byref(new_addr), ctypes.sizeof(new_addr), ctypes.byref(written)) == 0:
						errno = self.k32.GetLastError()
						if errno == 998:
							errno = 0
							old_permissions = wintypes.DWORD()
							if (self.k32.VirtualProtectEx(self.handle, iat_ent_addr, 0x400, flags('PAGE_READWRITE'), ctypes.byref(old_permissions)) == 0):
								raise WindowsProcessError('Error: VirtualProtectEx', get_last_error=self.k32.GetLastError())
							if self.k32.WriteProcessMemory(self.handle, iat_ent_addr, ctypes.byref(new_addr), ctypes.sizeof(new_addr), ctypes.byref(written)) == 0:
								errno = self.k32.GetLastError()
							self.protect(iat_ent_addr, permissions=old_permissions)
						if errno:
							raise WindowsProcessError('Error: WriteProcessMemory', get_last_error=errno)
					hook = Hook('iat', iat_ent_addr, old_address, new_address)
					self._installed_hooks.append(hook)
					return hook
		raise ProcessError('failed to find location to install hook')

	def close(self):
		self.k32.CloseHandle(self.handle)
		self.handle = None

	def kill(self):
		self.k32.TerminateProcess(self.handle, 0)
		self.close()

	def load_library(self, dllpath):
		dllpath = os.path.abspath(dllpath)
		LoadLibraryA = self.k32.GetProcAddress(self.k32.GetModuleHandleA("kernel32.dll"), "LoadLibraryA")
		RemotePage = self.k32.VirtualAllocEx(self.handle, None, len(dllpath) + 1, flags("MEM_COMMIT"), flags("PAGE_EXECUTE_READWRITE"))
		self.k32.WriteProcessMemory(self.handle, RemotePage, dllpath, len(dllpath), None)
		RemoteThread = self.k32.CreateRemoteThread(self.handle, None, 0, LoadLibraryA, RemotePage, 0, None)
		self.k32.WaitForSingleObject(RemoteThread, -1)

		exitcode = wintypes.DWORD(0)
		self.k32.GetExitCodeThread(RemoteThread, ctypes.byref(exitcode))
		self.k32.VirtualFreeEx(self.handle, RemotePage, len(dllpath), flags("MEM_RELEASE"))
		if exitcode.value == 0:
			raise WindowsProcessError('Error: failed to load: ' + repr(dllpath))
		self._update_maps()
		return exitcode.value

	def read_memory(self, address, size=0x400):
		_data = (ctypes.c_char * size)
		data = _data()
		if (self.k32.ReadProcessMemory(self.handle, address, ctypes.byref(data), ctypes.sizeof(data), 0) == 0):
			raise WindowsProcessError('Error: ReadProcessMemory', get_last_error=self.k32.GetLastError())
		return ''.join(data)

	def write_memory(self, address, data):
		_wr_data = (ctypes.c_char * len(data))
		wr_data = _wr_data()
		wr_data.value = data
		written = wintypes.DWORD()
		if (self.k32.WriteProcessMemory(self.handle, address, ctypes.byref(wr_data), ctypes.sizeof(wr_data), ctypes.byref(written)) == 0):
			raise WindowsProcessError('Error: WriteProcessMemory', get_last_error=self.k32.GetLastError())
		return

	def allocate(self, size=0x400, address=None, permissions='PAGE_EXECUTE_READWRITE'):
		alloc_type = flags('MEM_COMMIT')
		permissions = flags(permissions)
		result = self.k32.VirtualAllocEx(self.handle, address, size, alloc_type, permissions)
		self._update_maps()
		return result

	def free(self, address):
		free_type = flags('MEM_RELEASE')
		if (self.k32.VirtualFreeEx(self.handle, address, 0, free_type) == 0):
			raise WindowsProcessError('Error: VirtualFreeEx', get_last_error=self.k32.GetLastError())
		self._update_maps()
		return

	def protect(self, address, permissions='PAGE_EXECUTE_READWRITE', size=0x400):
		permissions = flags(permissions)
		old_permissions = wintypes.DWORD()
		if (self.k32.VirtualProtectEx(self.handle, address, size, permissions, ctypes.byref(old_permissions)) == 0):
			raise WindowsProcessError('Error: VirtualProtectEx', get_last_error=self.k32.GetLastError())
		return

	def start_thread(self, address, targ=None):
		handle = self.k32.CreateRemoteThread(self.handle, None, 0, address, targ, 0, None)
		if handle == 0:
			raise WindowsProcessError('Error: CreateRemoteThread', get_last_error=self.k32.GetLastError())
		return handle

	def join_thread(self, thread_id):
		self.k32.WaitForSingleObject(thread_id, -1)
		return
