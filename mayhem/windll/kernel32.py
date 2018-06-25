#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/windll/kernel32.py
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

import mayhem.datatypes.windows as wintypes

_kernel32 = ctypes.windll.kernel32

def _patch_winfunctype(function, restype, argtypes=(), **kwargs):
	address = ctypes.cast(function, ctypes.c_void_p).value
	prototype = wintypes.WINFUNCTYPE(restype, *argtypes, **kwargs)
	return prototype(address)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx
CloseHandle = _patch_winfunctype(
	_kernel32.CloseHandle,
	wintypes.BOOL,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365146(v=vs.85).aspx
ConnectNamedPipe = _patch_winfunctype(
	_kernel32.ConnectNamedPipe,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.POVERLAPPED)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396(v=vs.85).aspx
CreateEventA = _patch_winfunctype(
	_kernel32.CreateEventA,
	wintypes.HANDLE,
	(wintypes.PSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.BOOL, wintypes.LPSTR)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682396(v=vs.85).aspx
CreateEventW = _patch_winfunctype(
	_kernel32.CreateEventW,
	wintypes.HANDLE,
	(wintypes.PSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.BOOL, wintypes.LPWSTR)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
CreateFileA = _patch_winfunctype(
	_kernel32.CreateFileA,
	wintypes.HANDLE,
	(
		wintypes.LPSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.HANDLE
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
CreateFileW = _patch_winfunctype(
	_kernel32.CreateFileW,
	wintypes.HANDLE,
	(
		wintypes.LPWSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.HANDLE
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx
CreateNamedPipeA = _patch_winfunctype(
	_kernel32.CreateNamedPipeA,
	wintypes.HANDLE,
	(
		wintypes.LPSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx
CreateNamedPipeW = _patch_winfunctype(
	_kernel32.CreateNamedPipeW,
	wintypes.HANDLE,
	(
		wintypes.LPWSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcessA = _patch_winfunctype(
	_kernel32.CreateProcessA,
	wintypes.BOOL,
	(
		wintypes.LPSTR,
		wintypes.LPSTR,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.BOOL,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.LPSTR,
		wintypes.PSTARTUPINFO,
		wintypes.PPROCESS_INFORMATION
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcessW = _patch_winfunctype(
	_kernel32.CreateProcessW,
	wintypes.BOOL,
	(
		wintypes.LPWSTR,
		wintypes.LPWSTR,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.BOOL,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.LPWSTR,
		wintypes.PSTARTUPINFO,
		wintypes.PPROCESS_INFORMATION
	)
)

CreateRemoteThread = _patch_winfunctype(
	_kernel32.CreateRemoteThread,
	wintypes.HANDLE,
	(
		wintypes.HANDLE,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.SIZE_T,
		wintypes.PVOID,
		wintypes.LPVOID,
		wintypes.DWORD,
		wintypes.LPDWORD
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453(v=vs.85).aspx
CreateThread = _patch_winfunctype(
	_kernel32.CreateThread,
	wintypes.HANDLE,
	(
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.SIZE_T,
		wintypes.PVOID,
		wintypes.LPVOID,
		wintypes.DWORD,
		wintypes.LPDWORD
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724251(v=vs.85).aspx
DuplicateHandle = _patch_winfunctype(
	_kernel32.DuplicateHandle,
	wintypes.BOOL,
	(
		wintypes.HANDLE,
		wintypes.HANDLE,
		wintypes.HANDLE,
		wintypes.LPHANDLE,
		wintypes.DWORD,
		wintypes.BOOL,
		wintypes.DWORD
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658(v=vs.85).aspx
ExitProcess = _patch_winfunctype(
	_kernel32.ExitProcess,
	wintypes.VOID,
	(wintypes.UINT,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682659(v=vs.85).aspx
ExitThread = _patch_winfunctype(
	_kernel32.ExitThread,
	wintypes.VOID,
	(wintypes.DWORD,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683152(v=vs.85).aspx
FreeLibrary = _patch_winfunctype(
	_kernel32.FreeLibrary,
	wintypes.BOOL,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
GetCurrentProcess = _patch_winfunctype(
	_kernel32.GetCurrentProcess,
	wintypes.HANDLE
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683180(v=vs.85).aspx
GetCurrentProcessId = _patch_winfunctype(
	_kernel32.GetCurrentProcessId,
	wintypes.DWORD
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683182(v=vs.85).aspx
GetCurrentThread = _patch_winfunctype(
	_kernel32.GetCurrentThread,
	wintypes.HANDLE
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683183(v=vs.85).aspx
GetCurrentThreadId = _patch_winfunctype(
	_kernel32.GetCurrentThreadId,
	wintypes.DWORD
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683189(v=vs.85).aspx
GetExitCodeProcess = _patch_winfunctype(
	_kernel32.GetExitCodeProcess,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683190(v=vs.85).aspx
GetExitCodeThread = _patch_winfunctype(
	_kernel32.GetExitCodeThread,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError = _patch_winfunctype(
	_kernel32.GetLastError,
	wintypes.DWORD
)

if hasattr(_kernel32, 'GetModuleFileNameExA'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
	GetModuleFileNameExA = _patch_winfunctype(
		_kernel32.GetModuleFileNameExA,
		wintypes.DWORD,
		(wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD)
	)

if hasattr(_kernel32, 'GetModuleFileNameExW'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
	GetModuleFileNameExW = _patch_winfunctype(
		_kernel32.GetModuleFileNameExW,
		wintypes.DWORD,
		(wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD)
	)


GetModuleHandleA = _patch_winfunctype(
	_kernel32.GetModuleHandleA,
	wintypes.HANDLE,
	(wintypes.LPSTR,)
)

GetModuleHandleW = _patch_winfunctype(
	_kernel32.GetModuleHandleW,
	wintypes.HANDLE,
	(wintypes.LPWSTR,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
GetModuelHandleExA = _patch_winfunctype(
	_kernel32.GetModuleHandleExA,
	wintypes.BOOL,
	(wintypes.DWORD, wintypes.LPSTR, wintypes.PHMODULE)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
GetModuelHandleExW = _patch_winfunctype(
	_kernel32.GetModuleHandleExW,
	wintypes.BOOL,
	(wintypes.DWORD, wintypes.LPWSTR, wintypes.PHMODULE)
)

GetProcAddress = _patch_winfunctype(
	_kernel32.GetProcAddress,
	wintypes.PVOID,
	(wintypes.HMODULE, wintypes.LPSTR)
)

GetProcessId = _patch_winfunctype(
	_kernel32.GetProcessId,
	wintypes.DWORD,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724381(v=vs.85).aspx
GetSystemInfo = _patch_winfunctype(
	_kernel32.GetSystemInfo,
	wintypes.VOID,
	(wintypes.PSYSTEM_INFO,)
)

if hasattr(ctypes.windll.kernel32, 'IsWow64Process'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684139(v=vs.85).aspx
	IsWow64Process = _patch_winfunctype(
		_kernel32.IsWow64Process,
		wintypes.BOOL,
		(wintypes.HANDLE, wintypes.PBOOL)
	)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx
LoadLibraryA = _patch_winfunctype(
	_kernel32.LoadLibraryA,
	wintypes.HMODULE,
	(wintypes.LPSTR,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx
LoadLibraryW = _patch_winfunctype(
	_kernel32.LoadLibraryW,
	wintypes.HMODULE,
	(wintypes.LPWSTR,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
LoadLibraryExA = _patch_winfunctype(
	_kernel32.LoadLibraryExA,
	wintypes.HMODULE,
	(wintypes.LPSTR, wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
LoadLibraryExW = _patch_winfunctype(
	_kernel32.LoadLibraryExW,
	wintypes.HMODULE,
	(wintypes.LPWSTR, wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess = _patch_winfunctype(
	_kernel32.OpenProcess,
	wintypes.HANDLE,
	(wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
OpenThread = _patch_winfunctype(
	_kernel32.OpenThread,
	wintypes.HANDLE,
	(wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
ReadFile = _patch_winfunctype(
	_kernel32.ReadFile,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.POVERLAPPED)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
ReadProcessMemory = _patch_winfunctype(
	_kernel32.ReadProcessMemory,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.SIZE_T, wintypes.SIZE_T)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms686714(v=vs.85).aspx
TerminateProcess = _patch_winfunctype(
	_kernel32.TerminateProcess,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.UINT)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx
VirtualAlloc = _patch_winfunctype(
	_kernel32.VirtualAlloc,
	wintypes.LPVOID,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD)
)

VirtualAllocEx = _patch_winfunctype(
	_kernel32.VirtualAllocEx,
	wintypes.SIZE_T,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366892(v=vs.85).aspx
VirtualFree = _patch_winfunctype(
	_kernel32.VirtualFree,
	wintypes.BOOL,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD)
)

VirtualFreeEx = _patch_winfunctype(
	_kernel32.VirtualFreeEx,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898(v=vs.85).aspx
VirtualProtect = _patch_winfunctype(
	_kernel32.VirtualProtect,
	wintypes.BOOL,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx
VirtualProtectEx = _patch_winfunctype(
	_kernel32.VirtualProtectEx,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366902(v=vs.85).aspx
VirtualQuery = _patch_winfunctype(
	_kernel32.VirtualQuery,
	wintypes.SIZE_T,
	(wintypes.LPVOID, wintypes.PMEMORY_BASIC_INFORMATION, wintypes.SIZE_T)
)

VirtualQueryEx = _patch_winfunctype(
	_kernel32.VirtualQueryEx,
	wintypes.SIZE_T,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.PMEMORY_BASIC_INFORMATION, wintypes.SIZE_T)
)

WaitForSingleObject = _patch_winfunctype(
	_kernel32.WaitForSingleObject,
	wintypes.DWORD,
	(wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms687036(v=vs.85).aspx
WaitForSingleObjectEx = _patch_winfunctype(
	_kernel32.WaitForSingleObjectEx,
	wintypes.DWORD,
	(wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
WriteProcessMemory = _patch_winfunctype(
	_kernel32.WriteProcessMemory,
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.SIZE_T, wintypes.PSIZE_T)
)

address = GetModuleHandleW('kernel32.dll')
