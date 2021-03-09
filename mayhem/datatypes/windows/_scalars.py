#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/windows/_scalars.py
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
import platform

_is_64bit = platform.architecture()[0] == '64bit'

VOID    = None

# http://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
BOOLEAN = ctypes.c_byte
BOOL    = ctypes.c_bool
PBOOL   = ctypes.POINTER(BOOL)
BYTE    = ctypes.c_uint8
PBYTE   = ctypes.POINTER(BYTE)
LPBYTE  = PBYTE

WORD    = ctypes.c_uint16
PWORD   = ctypes.POINTER(WORD)
LPWORD  = PWORD

DWORD     = ctypes.c_uint32
DWORDLONG = ctypes.c_uint64
DWORD32   = ctypes.c_uint32
DWORD64   = ctypes.c_uint64
PDWORD    = ctypes.POINTER(DWORD)
LPDWORD   = PDWORD

QWORD    = ctypes.c_uint64
PQWORD   = ctypes.POINTER(QWORD)
LPQWORD  = PQWORD

SHORT    = ctypes.c_int16
INT      = ctypes.c_int32

LONG     = ctypes.c_int32
LONGLONG = ctypes.c_int64
LONG32   = ctypes.c_int32
LONG64   = ctypes.c_int64
PLONG    = ctypes.POINTER(LONG)
LPLONG   = PLONG

UCHAR       = ctypes.c_uint8
USHORT      = ctypes.c_uint16
UINT        = ctypes.c_uint32
ULONG       = ctypes.c_uint32
PULONG      = ctypes.POINTER(ULONG)
LPULONG     = PULONG
ULONGLONG   = ctypes.c_uint64
PULONGLONG  = ctypes.POINTER(ULONGLONG)
LPULONGLONG = PULONGLONG
ULONG_PTR   = ctypes.c_uint64 if _is_64bit else ctypes.c_ulong

class PSTR(ctypes.c_char_p):
	def __str__(self):
		return self.value.decode('ascii')

	@classmethod
	def from_param(cls, param):
		if isinstance(param, str):
			param = param.encode('ascii')
		return super(PSTR, cls).from_param(param)
LPSTR  = PSTR

class PWSTR(ctypes.c_wchar_p):
	def __str__(self):
		return self.value
LPWSTR = PWSTR

UCHAR  = ctypes.c_ubyte
PUCHAR = ctypes.POINTER(ctypes.c_ubyte)

HANDLE    = ctypes.c_void_p
LPHANDLE  = PHANDLE  = ctypes.POINTER(HANDLE)
HMODULE   = HANDLE
LPHMODULE = PHMODULE = ctypes.POINTER(HMODULE)
HWND      = HANDLE
LPHWND    = PHWND    = ctypes.POINTER(HWND)
HINSTANCE = HANDLE

PVOID     = ctypes.c_void_p
LPVOID    = PVOID

SE_SIGNING_LEVEL  = ULONG
PSE_SIGNING_LEVEL = ctypes.POINTER(ULONG)

NTSTATUS  = ctypes.c_uint32

# platform specific data primitives
if _is_64bit:
	SIZE_T = ctypes.c_uint64
else:
	SIZE_T = ctypes.c_uint32
PSIZE_T = ctypes.POINTER(SIZE_T)