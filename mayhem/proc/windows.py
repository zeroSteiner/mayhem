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
import ctypes.wintypes as wintypes
import os
import platform

from mayhem.proc import Process, ProcessError, Hook, MemoryRegion

CONSTANTS = {
	'GENERIC_READ'  : 0x80000000,
	'GENERIC_WRITE' : 0x40000000,

	'OPEN_EXISTING' : 0x03,
	'CREATE_ALWAYS' : 0x02,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366890%28v=vs.85%29.aspx
	'MEM_COMMIT'     : 0x00001000,
	'MEM_RESERVE'    : 0x00002000,
	'MEM_RESET'      : 0x00080000,
	'MEM_RESET_UNDO' : 0x01000000,
	'MEM_LARGE_PAGES': 0x20000000,
	'MEM_PHYSICAL'   : 0x00400000,
	'MEM_TOP_DOWN'   : 0x00100000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775%28v=vs.85%29.aspx
	'MEM_IMAGE'      : 0x01000000,
	'MEM_MAPPED'     : 0x00040000,
	'MEM_PRIVATE'    : 0x00020000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366894%28v=vs.85%29.aspx
	'MEM_DECOMMIT'   : 0x4000,
	'MEM_RELEASE'    : 0x8000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa366786%28v=vs.85%29.aspx
	'PAGE_EXECUTE'                      : 0x10,
	'PAGE_EXECUTE_READ'                 : 0x20,
	'PAGE_EXECUTE_READWRITE'            : 0x40,
	'PAGE_EXECUTE_WRITECOPY'            : 0x80,
	'PAGE_NOACCESS'                     : 0x01,
	'PAGE_READONLY'                     : 0x02,
	'PAGE_READWRITE'                    : 0x04,
	'PAGE_WRITECOPY'                    : 0x08,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx
	'PROCESS_CREATE_PROCESS'            : 0x0080,
	'PROCESS_CREATE_THREAD'             : 0x0002,
	'PROCESS_DUP_HANDLE'                : 0x0040,
	'PROCESS_QUERY_INFORMATION'         : 0x0400,
	'PROCESS_QUERY_LIMITED_INFORMATION' : 0x1000,
	'PROCESS_SET_INFORMATION'           : 0x0200,
	'PROCESS_SET_QUOTA'                 : 0x0100,
	'PROCESS_SUSPEND_RESUME'            : 0x0800,
	'PROCESS_TERMINATE'                 : 0x0001,
	'PROCESS_VM_OPERATION'              : 0x0008,
	'PROCESS_VM_READ'                   : 0x0010,
	'PROCESS_VM_WRITE'                  : 0x0020,
	'SYNCHRONIZE'                       : 0x00100000,

	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858%28v:vs.85%29.aspx
	'FILE_SHARE_READ'   : 0x00000001,
	'FILE_SHARE_WRITE'  : 0x00000002,
	'FILE_SHARE_DELETE' : 0x00000004,

	'FILE_FLAG_OVERLAPPED' : 0x40000000
}

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_TLS = 9

wintypes.LPTSTR = ctypes.POINTER(ctypes.c_char)
wintypes.PSTR = ctypes.POINTER(ctypes.c_char)
wintypes.PWSTR = ctypes.POINTER(ctypes.c_wchar)
wintypes.LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
wintypes.PUCHAR = ctypes.POINTER(ctypes.c_ubyte)
wintypes.UCHAR = ctypes.c_ubyte
wintypes.HANDLE = ctypes.c_void_p
wintypes.PVOID = ctypes.c_void_p
wintypes.PULONG = ctypes.POINTER(wintypes.ULONG)
wintypes.ULONGLONG = ctypes.c_uint64
wintypes.PULONGLONG = ctypes.POINTER(wintypes.ULONGLONG)

class __LIST_ENTRY(ctypes.Structure):
	_fields_ = [("Flink", ctypes.c_void_p),
				("Blink", ctypes.c_void_p),]
wintypes.LIST_ENTRY = __LIST_ENTRY

class __UNICODE_STRING(ctypes.Structure):
	_fields_ = [("Length", wintypes.USHORT),
				("MaximumLength", wintypes.USHORT),
				("Buffer", ctypes.c_void_p),]
wintypes.UNICODE_STRING = __UNICODE_STRING

class __STARTUPINFO(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
	"""
	_fields_ = [("cb", wintypes.DWORD),
				("lpReserved", wintypes.LPTSTR),
				("lpDesktop", wintypes.LPTSTR),
				("lpTitle", wintypes.LPTSTR),
				("dwX", wintypes.DWORD),
				("dwY", wintypes.DWORD),
				("dwXSize", wintypes.DWORD),
				("dwYSize", wintypes.DWORD),
				("dwXCountChars", wintypes.DWORD),
				("dwYCountChars", wintypes.DWORD),
				("dwFillAttribute",wintypes.DWORD),
				("dwFlags", wintypes.DWORD),
				("wShowWindow", wintypes.WORD),
				("cbReserved2", wintypes.WORD),
				("lpReserved2", wintypes.LPBYTE),
				("hStdInput", wintypes.HANDLE),
				("hStdOutput", wintypes.HANDLE),
				("hStdError", wintypes.HANDLE),]
wintypes.STARTUPINFO = __STARTUPINFO

class __LOADED_IMAGE(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms680349%28v=vs.85%29.aspx
	"""
	_fields_ = [("ModuleName", wintypes.PSTR),
				("hFile", wintypes.HANDLE),
				("MappedAddress", wintypes.PUCHAR),
				("FileHeader", ctypes.c_void_p),
				("LastRvaSection", ctypes.c_void_p),
				("NumberOfSections", wintypes.ULONG),
				("Sections", ctypes.c_void_p),
				("Characteristics", wintypes.ULONG),
				("fSystemImage", wintypes.BOOLEAN),
				("fDOSImage", wintypes.BOOLEAN),
				("fReadOnly", wintypes.BOOLEAN),
				("Version", wintypes.UCHAR),
				("Links", ctypes.c_void_p),
				("SizeOfImage", wintypes.ULONG),]
wintypes.LOADED_IMAGE = __LOADED_IMAGE

class __LDR_MODULE(ctypes.Structure):
	_fields_ = [("InLoadOrderModuleList", wintypes.LIST_ENTRY),
				("InMemoryOrderModuleList", wintypes.LIST_ENTRY),
				("InInitializationOrderModuleList", wintypes.LIST_ENTRY),
				("BaseAddress", ctypes.c_void_p),
				("EntryPoint", ctypes.c_void_p),
				("SizeOfImage", wintypes.ULONG),
				("FullDllName", wintypes.UNICODE_STRING),
				("BaseDllName", wintypes.UNICODE_STRING),
				("Flags", wintypes.ULONG),
				("LoadCount", wintypes.SHORT),
				("TlsIndex", wintypes.SHORT),
				("HashTableEntry", wintypes.LIST_ENTRY),
				("TimeDateStamp", wintypes.ULONG),]
wintypes.LDR_MODULE = __LDR_MODULE

class __IMAGE_DATA_DIRECTORY(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms680305%28v=vs.85%29.aspx
	"""
	_fields_ = [("VirtualAddress", wintypes.DWORD),
				("Size", wintypes.DWORD),]
wintypes.IMAGE_DATA_DIRECTORY = __IMAGE_DATA_DIRECTORY

class __IMAGE_DOS_HEADER(ctypes.Structure):
	_fields_ = [("e_magic", wintypes.WORD),
				("e_cblp", wintypes.WORD),
				("e_cp", wintypes.WORD),
				("e_crlc", wintypes.WORD),
				("e_cparhdr", wintypes.WORD),
				("e_minalloc", wintypes.WORD),
				("e_maxalloc", wintypes.WORD),
				("e_ss", wintypes.WORD),
				("e_sp", wintypes.WORD),
				("e_csum", wintypes.WORD),
				("e_ip", wintypes.WORD),
				("e_cs", wintypes.WORD),
				("e_lfarlc", wintypes.WORD),
				("e_ovno", wintypes.WORD),
				("e_res", wintypes.WORD * 4),
				("e_oemid", wintypes.WORD),
				("e_oeminfo", wintypes.WORD),
				("e_res2", wintypes.WORD * 10),
				("e_lfanew", wintypes.LONG),]
wintypes.IMAGE_DOS_HEADER = __IMAGE_DOS_HEADER

class __IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
	_fields_ = [("Characteristics", wintypes.DWORD),
				("TimeDateStamp", wintypes.DWORD),
				("MajorVersion", wintypes.WORD),
				("MinorVersion", wintypes.WORD),
				("Name", wintypes.DWORD),
				("Base", wintypes.DWORD),
				("NumberOfFunctions", wintypes.DWORD),
				("NumberOfNames", wintypes.DWORD),
				("AddressOfFunctions", wintypes.DWORD),
				("AddressOfNames", wintypes.DWORD),
				("AddressOfNameOrdinals", wintypes.DWORD),]
wintypes.IMAGE_EXPORT_DIRECTORY = __IMAGE_EXPORT_DIRECTORY

class __IMAGE_FILE_HEADER(ctypes.Structure):
	_fields_ = [("Machine", wintypes.WORD),
				("NumberOfSections", wintypes.WORD),
				("TimeDateStamp", wintypes.DWORD),
				("PointerToSymbolTable", wintypes.DWORD),
				("NumberOfSymbols", wintypes.DWORD),
				("SizeOfOptionalHeader", wintypes.WORD),
				("Characteristics", wintypes.WORD),]
wintypes.IMAGE_FILE_HEADER = __IMAGE_FILE_HEADER

class __IMAGE_OPTIONAL_HEADER(ctypes.Structure):
	_fields_ = [("Magic", wintypes.WORD),
				("MajorLinkerVersion", wintypes.BYTE),
				("MinorLinkerVersion", wintypes.BYTE),
				("SizeOfCode", wintypes.DWORD),
				("SizeOfInitializedData", wintypes.DWORD),
				("SizeOfUninitializedData", wintypes.DWORD),
				("AddressOfEntryPoint", wintypes.DWORD),
				("BaseOfCode", wintypes.DWORD),
				("BaseOfData", wintypes.DWORD),
				("ImageBase", wintypes.DWORD),
				("SectionAlignment", wintypes.DWORD),
				("FileAlignment", wintypes.DWORD),
				("MajorOperatingSystemVersion", wintypes.WORD),
				("MinorOperatingSystemVersion", wintypes.WORD),
				("MajorImageVersion", wintypes.WORD),
				("MinorImageVersion", wintypes.WORD),
				("MajorSubsystemVersion", wintypes.WORD),
				("MinorSubsystemVersion", wintypes.WORD),
				("Win32VersionValue", wintypes.DWORD),
				("SizeOfImage", wintypes.DWORD),
				("SizeOfHeaders", wintypes.DWORD),
				("CheckSum", wintypes.DWORD),
				("Subsystem", wintypes.WORD),
				("DllCharacteristics", wintypes.WORD),
				("SizeOfStackReserve", wintypes.DWORD),
				("SizeOfStackCommit", wintypes.DWORD),
				("SizeOfHeapReserve", wintypes.DWORD),
				("SizeOfHeapCommit", wintypes.DWORD),
				("LoaderFlags", wintypes.DWORD),
				("NumberOfRvaAndSizes", wintypes.DWORD),
				("DataDirectory", wintypes.IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),]
wintypes.IMAGE_OPTIONAL_HEADER = __IMAGE_OPTIONAL_HEADER

class __IMAGE_IMPORT_BY_NAME(ctypes.Structure):
	_fields_ = [("Hint", wintypes.WORD),
				("Name", wintypes.BYTE),]
wintypes.IMAGE_IMPORT_BY_NAME = __IMAGE_IMPORT_BY_NAME

class __IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
	_fields_ = [("OriginalFirstThunk", wintypes.DWORD), # import lookup table
				("TimeDateStamp", wintypes.DWORD),
				("ForwarderChain", wintypes.DWORD),
				("Name", wintypes.DWORD),
				("FirstThunk", wintypes.DWORD),] # import address table
wintypes.IMAGE_IMPORT_DESCRIPTOR = __IMAGE_IMPORT_DESCRIPTOR

class __IMAGE_THUNK_DATA32(ctypes.Structure):
	_fields_ = [("ForwarderString", wintypes.DWORD),
				("Function", wintypes.DWORD),
				("Ordinal", wintypes.DWORD),
				("AddressOfData", wintypes.DWORD),]
wintypes.IMAGE_THUNK_DATA32 = __IMAGE_THUNK_DATA32

class __IMAGE_NT_HEADERS32(ctypes.Structure):
	_fields_ = [("Signature", wintypes.DWORD),
				("FileHeader", wintypes.IMAGE_FILE_HEADER),
				("OptionalHeader", wintypes.IMAGE_OPTIONAL_HEADER),]
wintypes.IMAGE_NT_HEADERS32 = __IMAGE_NT_HEADERS32

class __PEB(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa813706%28v=vs.85%29.aspx
	"""
	_fields_ = [("Reserved1", wintypes.BYTE * 2),
				("BeingDebugged", wintypes.BYTE),
				("SpareBool", wintypes.BYTE),
				("Mutant", ctypes.c_void_p),
				("ImageBaseAddress", ctypes.c_void_p),
				("Ldr", ctypes.c_void_p),
				("ProcessParameters", ctypes.c_void_p),
				("SubSystemData", ctypes.c_void_p),
				("ProcessHeap", ctypes.c_void_p),
				("Reserved4", wintypes.BYTE * 96),
				("Reserved5", ctypes.c_void_p * 52),
				("PostProcessInitRoutine", ctypes.c_void_p),
				("Reserved6", wintypes.BYTE * 128),
				("Reserved7", ctypes.c_void_p),
				("SessionId", wintypes.ULONG),]
wintypes.PEB = __PEB

class __PEB_LDR_DATA(ctypes.Structure):
	_fields_ = [("Length", wintypes.ULONG),
				("Reserved", wintypes.UCHAR * 4),
				("SsHandle", wintypes.HANDLE),
				("InLoadOrderModuleList", wintypes.LIST_ENTRY),
				("InMemoryOrderModuleList", wintypes.LIST_ENTRY),
				("InInitializationOrderModuleList", wintypes.LIST_ENTRY),]
wintypes.PEB_LDR_DATA = __PEB_LDR_DATA

class __PROCESS_BASIC_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms684280%28v=vs.85%29.aspx
	"""
	_fields_ = [("Reserved1", ctypes.c_void_p),
				("PebBaseAddress", wintypes.c_void_p),
				("Reserved2", ctypes.c_void_p * 2),
				("UniqueProcessId", wintypes.PULONG),
				("Reserved3", ctypes.c_void_p),]
wintypes.PROCESS_BASIC_INFORMATION = __PROCESS_BASIC_INFORMATION

class __SYSTEM_INFO(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx
	"""
	_fields_ = [("wProcessorArchitecture", wintypes.WORD),
				("wReserved", wintypes.WORD),
				("dwPageSize", wintypes.DWORD),
				("lpMinimumApplicationAddress", wintypes.c_void_p),
				("lpMaximumApplicationAddress", wintypes.c_void_p),
				("dwActiveProcessorMask", wintypes.DWORD),
				("dwNumberOfProcessors", wintypes.DWORD),
				("dwProcessorType", wintypes.DWORD),
				("dwAllocationGranularity", wintypes.DWORD),
				("wProcessorLevel", wintypes.WORD),
				("wProcessorRevision", wintypes.WORD),]
wintypes.SYSTEM_INFO = __SYSTEM_INFO

class __PROCESS_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
	"""
	_fields_ = [("hProcess", wintypes.HANDLE),
				("hThread", wintypes.HANDLE),
				("dwProcessId", wintypes.DWORD),
				("dwThreadId", wintypes.DWORD),]
wintypes.PROCESS_INFORMATION = __PROCESS_INFORMATION

class __MEMORY_BASIC_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
	"""
	_fields_ = [("BaseAddress", wintypes.ULONG),
				("AllocationBase", wintypes.PVOID),
				("AllocationProtect", wintypes.DWORD),
				("RegionSize", wintypes.ULONG),
				("State", wintypes.DWORD),
				("Protect", wintypes.DWORD),
				("Type", wintypes.DWORD),]
wintypes.MEMORY_BASIC_INFORMATION = __MEMORY_BASIC_INFORMATION

class __MEMORY_BASIC_INFORMATION64(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
	"""
	_fields_ = [("BaseAddress", wintypes.ULONG),
				("AllocationBase", wintypes.PVOID),
				("AllocationProtect", wintypes.DWORD),
				("__alignment1", wintypes.DWORD),
				("RegionSize", wintypes.ULONG),
				("State", wintypes.DWORD),
				("Protect", wintypes.DWORD),
				("Type", wintypes.DWORD),
				("__alignment2", wintypes.DWORD),]
wintypes.MEMORY_BASIC_INFORMATION64 = __MEMORY_BASIC_INFORMATION64

class WindowsProcessError(ProcessError):
	def __init__(self, *args, **kwargs):
		self.get_last_error = None
		if 'get_last_error' in kwargs:
			self.get_last_error = kwargs['get_last_error']
			del kwargs['get_last_error']
		ProcessError.__init__(self, *args, **kwargs)

def flags(flags):
	supported_operators = ['|', '+', '-', '^']
	if isinstance(flags, int) or isinstance(flags, long):
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
			if part.isdigit():
				part = int(part)
			elif part.startswith('0x'):
				part = int(part[2:], 16)
			else:
				raise ValueError('unknown token: ' + part)
		if last_operator == None:
			parsed_flags = part
		else:
			parsed_flags = eval(str(parsed_flags) + last_operator + str(part))
	return parsed_flags

class WindowsProcess(Process):
	def __init__(self, pid = None, exe = None, handle = None, arch = 'x86', access = None):
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
				raise Exception('could not open PID')
		elif exe:
			startupinfo = wintypes.STARTUPINFO()
			process_info = wintypes.PROCESS_INFORMATION()
			startupinfo.dwFlags = 0x01
			startupinfo.wShowWindow = 0x00
			startupinfo.cb = ctypes.sizeof(startupinfo)
			self.k32.CreateProcessA(exe, None, None, None, True, 0, None, None, ctypes.byref(startupinfo), ctypes.byref(process_info))
			self.handle = process_info.hProcess
			if not self.handle:
				raise Exception('could not the create process')
		elif handle:
			self.handle = handle
		else:
			raise Exception('either a pid, exe or a handle must be specified')
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
			try:
				print base_dll_name
			except:
				pass
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
		PROTECT_FLAGS = { 0x10: '--x', 0x20: 'r-x', 0x40: 'rwx', 0x80: 'r-x', 0x01: '---', 0x02: 'r--', 0x04: 'rw-', 0x08: 'r--' }
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

	def install_hook(self, mod_name, new_address, name = None, ordinal = None):
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

					iat_ent_addr =  image_dos_header_addr
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
								raise WindowsProcessError('Error: VirtualProtectEx', get_last_error = self.k32.GetLastError())
							if self.k32.WriteProcessMemory(self.handle, iat_ent_addr, ctypes.byref(new_addr), ctypes.sizeof(new_addr), ctypes.byref(written)) == 0:
								errno = self.k32.GetLastError()
							self.protect(iat_ent_addr, permissions = old_permissions)
						if errno:
							raise WindowsProcessError('Error: WriteProcessMemory', get_last_error = errno)
					hook = Hook('iat', iat_ent_addr, old_address, new_address)
					self._installed_hooks.append(hook)
					return hook
		raise Exception('failed to find location to install hook')

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

	def read_memory(self, address, size = 0x400):
		_data = (ctypes.c_char * size)
		data = _data()
		if (self.k32.ReadProcessMemory(self.handle, address, ctypes.byref(data), ctypes.sizeof(data), 0) == 0):
			raise WindowsProcessError('Error: ReadProcessMemory', get_last_error = self.k32.GetLastError())
		return ''.join(data)

	def write_memory(self, address, data):
		_wr_data = (ctypes.c_char * len(data))
		wr_data = _wr_data()
		wr_data.value = data
		written = wintypes.DWORD()
		if (self.k32.WriteProcessMemory(self.handle, address, ctypes.byref(wr_data), ctypes.sizeof(wr_data), ctypes.byref(written)) == 0):
			raise WindowsProcessError('Error: WriteProcessMemory', get_last_error = self.k32.GetLastError())
		return

	def allocate(self, size = 0x400, address = None, permissions = 'PAGE_EXECUTE_READWRITE'):
		alloc_type = flags('MEM_COMMIT')
		permissions = flags(permissions)
		result = self.k32.VirtualAllocEx(self.handle, address, size, alloc_type, permissions)
		self._update_maps()
		return result

	def free(self, address):
		free_type = flags('MEM_RELEASE')
		if (self.k32.VirtualFreeEx(self.handle, address, 0, free_type) == 0):
			raise WindowsProcessError('Error: VirtualFreeEx', get_last_error = self.k32.GetLastError())
		self._update_maps()
		return

	def protect(self, address, permissions = 'PAGE_EXECUTE_READWRITE', size = 0x400):
		permissions = flags(permissions)
		old_permissions = wintypes.DWORD()
		if (self.k32.VirtualProtectEx(self.handle, address, size, permissions, ctypes.byref(old_permissions)) == 0):
			raise WindowsProcessError('Error: VirtualProtectEx', get_last_error = self.k32.GetLastError())
		return

	def start_thread(self, address, targ = None):
		handle = self.k32.CreateRemoteThread(self.handle, None, 0, address, targ, 0, None)
		if handle == 0:
			raise WindowsProcessError('Error: CreateRemoteThread', get_last_error = self.k32.GetLastError())
		return handle

	def join_thread(self, thread_id):
		self.k32.WaitForSingleObject(thread_id, -1)
		return
