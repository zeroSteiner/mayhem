#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/windows.py
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

_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

# http://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
BOOLEAN = ctypes.c_byte
BYTE = ctypes.c_uint8

DWORD = ctypes.c_uint32
DWORDLONG = ctypes.c_uint64
DWORD32 = ctypes.c_uint32
DWORD64 = ctypes.c_uint64

LONG = ctypes.c_int32
LONGLONG = ctypes.c_int64
LONG32 = ctypes.c_int32
LONG64 = ctypes.c_int64

QWORD = ctypes.c_uint64

SHORT = ctypes.c_int16

UCHAR = ctypes.c_uint8
ULONG = ctypes.c_uint32
ULONGLONG = ctypes.c_uint64
USHORT = ctypes.c_uint16

WORD = ctypes.c_uint16

LPTSTR = ctypes.POINTER(ctypes.c_char)
PSTR = ctypes.POINTER(ctypes.c_char)
PWSTR = ctypes.POINTER(ctypes.c_wchar)
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
PUCHAR = ctypes.POINTER(ctypes.c_ubyte)
UCHAR = ctypes.c_ubyte
HANDLE = ctypes.c_void_p
PVOID = ctypes.c_void_p
PULONG = ctypes.POINTER(ULONG)
ULONGLONG = ctypes.c_uint64
PULONGLONG = ctypes.POINTER(ULONGLONG)

class LIST_ENTRY(ctypes.Structure):
	_fields_ = [("Flink", ctypes.c_void_p),
				("Blink", ctypes.c_void_p),]

class UNICODE_STRING(ctypes.Structure):
	_fields_ = [("Length", USHORT),
				("MaximumLength", USHORT),
				("Buffer", ctypes.c_void_p),]

class STARTUPINFO(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
	"""
	_fields_ = [("cb", DWORD),
				("lpReserved", LPTSTR),
				("lpDesktop", LPTSTR),
				("lpTitle", LPTSTR),
				("dwX", DWORD),
				("dwY", DWORD),
				("dwXSize", DWORD),
				("dwYSize", DWORD),
				("dwXCountChars", DWORD),
				("dwYCountChars", DWORD),
				("dwFillAttribute",DWORD),
				("dwFlags", DWORD),
				("wShowWindow", WORD),
				("cbReserved2", WORD),
				("lpReserved2", LPBYTE),
				("hStdInput", HANDLE),
				("hStdOutput", HANDLE),
				("hStdError", HANDLE),]

class LOADED_IMAGE(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms680349%28v=vs.85%29.aspx
	"""
	_fields_ = [("ModuleName", PSTR),
				("hFile", HANDLE),
				("MappedAddress", PUCHAR),
				("FileHeader", ctypes.c_void_p),
				("LastRvaSection", ctypes.c_void_p),
				("NumberOfSections", ULONG),
				("Sections", ctypes.c_void_p),
				("Characteristics", ULONG),
				("fSystemImage", BOOLEAN),
				("fDOSImage", BOOLEAN),
				("fReadOnly", BOOLEAN),
				("Version", UCHAR),
				("Links", ctypes.c_void_p),
				("SizeOfImage", ULONG),]

class LDR_MODULE(ctypes.Structure):
	_fields_ = [("InLoadOrderModuleList", LIST_ENTRY),
				("InMemoryOrderModuleList", LIST_ENTRY),
				("InInitializationOrderModuleList", LIST_ENTRY),
				("BaseAddress", ctypes.c_void_p),
				("EntryPoint", ctypes.c_void_p),
				("SizeOfImage", ULONG),
				("FullDllName", UNICODE_STRING),
				("BaseDllName", UNICODE_STRING),
				("Flags", ULONG),
				("LoadCount", SHORT),
				("TlsIndex", SHORT),
				("HashTableEntry", LIST_ENTRY),
				("TimeDateStamp", ULONG),]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms680305%28v=vs.85%29.aspx
	"""
	_fields_ = [("VirtualAddress", DWORD),
				("Size", DWORD),]

class IMAGE_DOS_HEADER(ctypes.Structure):
	_fields_ = [("e_magic", WORD),
				("e_cblp", WORD),
				("e_cp", WORD),
				("e_crlc", WORD),
				("e_cparhdr", WORD),
				("e_minalloc", WORD),
				("e_maxalloc", WORD),
				("e_ss", WORD),
				("e_sp", WORD),
				("e_csum", WORD),
				("e_ip", WORD),
				("e_cs", WORD),
				("e_lfarlc", WORD),
				("e_ovno", WORD),
				("e_res", WORD * 4),
				("e_oemid", WORD),
				("e_oeminfo", WORD),
				("e_res2", WORD * 10),
				("e_lfanew", LONG),]

class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
	_fields_ = [("Characteristics", DWORD),
				("TimeDateStamp", DWORD),
				("MajorVersion", WORD),
				("MinorVersion", WORD),
				("Name", DWORD),
				("Base", DWORD),
				("NumberOfFunctions", DWORD),
				("NumberOfNames", DWORD),
				("AddressOfFunctions", DWORD),
				("AddressOfNames", DWORD),
				("AddressOfNameOrdinals", DWORD),]

class IMAGE_FILE_HEADER(ctypes.Structure):
	_fields_ = [("Machine", WORD),
				("NumberOfSections", WORD),
				("TimeDateStamp", DWORD),
				("PointerToSymbolTable", DWORD),
				("NumberOfSymbols", DWORD),
				("SizeOfOptionalHeader", WORD),
				("Characteristics", WORD),]

class IMAGE_OPTIONAL_HEADER(ctypes.Structure):
	_fields_ = [("Magic", WORD),
				("MajorLinkerVersion", BYTE),
				("MinorLinkerVersion", BYTE),
				("SizeOfCode", DWORD),
				("SizeOfInitializedData", DWORD),
				("SizeOfUninitializedData", DWORD),
				("AddressOfEntryPoint", DWORD),
				("BaseOfCode", DWORD),
				("BaseOfData", DWORD),
				("ImageBase", DWORD),
				("SectionAlignment", DWORD),
				("FileAlignment", DWORD),
				("MajorOperatingSystemVersion", WORD),
				("MinorOperatingSystemVersion", WORD),
				("MajorImageVersion", WORD),
				("MinorImageVersion", WORD),
				("MajorSubsystemVersion", WORD),
				("MinorSubsystemVersion", WORD),
				("Win32VersionValue", DWORD),
				("SizeOfImage", DWORD),
				("SizeOfHeaders", DWORD),
				("CheckSum", DWORD),
				("Subsystem", WORD),
				("DllCharacteristics", WORD),
				("SizeOfStackReserve", DWORD),
				("SizeOfStackCommit", DWORD),
				("SizeOfHeapReserve", DWORD),
				("SizeOfHeapCommit", DWORD),
				("LoaderFlags", DWORD),
				("NumberOfRvaAndSizes", DWORD),
				("DataDirectory", IMAGE_DATA_DIRECTORY * _IMAGE_NUMBEROF_DIRECTORY_ENTRIES),]

class IMAGE_IMPORT_BY_NAME(ctypes.Structure):
	_fields_ = [("Hint", WORD),
				("Name", BYTE),]

class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
	_fields_ = [("OriginalFirstThunk", DWORD), # import lookup table
				("TimeDateStamp", DWORD),
				("ForwarderChain", DWORD),
				("Name", DWORD),
				("FirstThunk", DWORD),] # import address table

class IMAGE_THUNK_DATA32(ctypes.Structure):
	_fields_ = [("ForwarderString", DWORD),
				("Function", DWORD),
				("Ordinal", DWORD),
				("AddressOfData", DWORD),]

class IMAGE_NT_HEADERS32(ctypes.Structure):
	_fields_ = [("Signature", DWORD),
				("FileHeader", IMAGE_FILE_HEADER),
				("OptionalHeader", IMAGE_OPTIONAL_HEADER),]

class PEB(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa813706%28v=vs.85%29.aspx
	"""
	_fields_ = [("Reserved1", BYTE * 2),
				("BeingDebugged", BYTE),
				("SpareBool", BYTE),
				("Mutant", ctypes.c_void_p),
				("ImageBaseAddress", ctypes.c_void_p),
				("Ldr", ctypes.c_void_p),
				("ProcessParameters", ctypes.c_void_p),
				("SubSystemData", ctypes.c_void_p),
				("ProcessHeap", ctypes.c_void_p),
				("Reserved4", BYTE * 96),
				("Reserved5", ctypes.c_void_p * 52),
				("PostProcessInitRoutine", ctypes.c_void_p),
				("Reserved6", BYTE * 128),
				("Reserved7", ctypes.c_void_p),
				("SessionId", ULONG),]

class PEB_LDR_DATA(ctypes.Structure):
	_fields_ = [("Length", ULONG),
				("Reserved", UCHAR * 4),
				("SsHandle", HANDLE),
				("InLoadOrderModuleList", LIST_ENTRY),
				("InMemoryOrderModuleList", LIST_ENTRY),
				("InInitializationOrderModuleList", LIST_ENTRY),]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms684280%28v=vs.85%29.aspx
	"""
	_fields_ = [("Reserved1", ctypes.c_void_p),
				("PebBaseAddress", ctypes.c_void_p),
				("Reserved2", ctypes.c_void_p * 2),
				("UniqueProcessId", PULONG),
				("Reserved3", ctypes.c_void_p),]

class SYSTEM_INFO(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx
	"""
	_fields_ = [("wProcessorArchitecture", WORD),
				("wReserved", WORD),
				("dwPageSize", DWORD),
				("lpMinimumApplicationAddress", ctypes.c_void_p),
				("lpMaximumApplicationAddress", ctypes.c_void_p),
				("dwActiveProcessorMask", DWORD),
				("dwNumberOfProcessors", DWORD),
				("dwProcessorType", DWORD),
				("dwAllocationGranularity", DWORD),
				("wProcessorLevel", WORD),
				("wProcessorRevision", WORD),]

class PROCESS_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
	"""
	_fields_ = [("hProcess", HANDLE),
				("hThread", HANDLE),
				("dwProcessId", DWORD),
				("dwThreadId", DWORD),]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
	"""
	_fields_ = [("BaseAddress", ULONG),
				("AllocationBase", PVOID),
				("AllocationProtect", DWORD),
				("RegionSize", ULONG),
				("State", DWORD),
				("Protect", DWORD),
				("Type", DWORD),]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
	"""see:
	http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
	"""
	_fields_ = [("BaseAddress", ULONG),
				("AllocationBase", PVOID),
				("AllocationProtect", DWORD),
				("__alignment1", DWORD),
				("RegionSize", ULONG),
				("State", DWORD),
				("Protect", DWORD),
				("Type", DWORD),
				("__alignment2", DWORD),]
