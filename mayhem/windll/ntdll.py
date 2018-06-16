#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/windll/ntdll.py
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

from . import kernel32 as m_k32
import mayhem.datatypes.windows as wintypes

_ntdll = ctypes.windll.ntdll

NtAllocateVirtualMemory = m_k32._patch_winfunctype(
	_ntdll.NtAllocateVirtualMemory,
	wintypes.NTSTATUS,
	(
		wintypes.HANDLE,
		ctypes.POINTER(wintypes.PVOID),
		wintypes.ULONG_PTR,
		wintypes.PSIZE_T,
		wintypes.ULONG,
		wintypes.ULONG
	)
)

NtDeviceIoControlFile = m_k32._patch_winfunctype(
	_ntdll.NtDeviceIoControlFile,
	wintypes.NTSTATUS,
	(
		wintypes.HANDLE,
		wintypes.HANDLE,
		ctypes.c_void_p,
		wintypes.PVOID,
		wintypes.PIO_STATUS_BLOCK,
		wintypes.ULONG,
		wintypes.PVOID,
		wintypes.ULONG,
		wintypes.PVOID,
		wintypes.ULONG
	)
)

NtQueryInformationProcess = m_k32._patch_winfunctype(
	_ntdll.NtQueryInformationProcess,
	wintypes.NTSTATUS,
	(
		wintypes.HANDLE,
		wintypes.DWORD,
		wintypes.PVOID,
		wintypes.ULONG,
		wintypes.PULONG
	)
)

NtSetCachedSigningLevel = m_k32._patch_winfunctype(
	_ntdll.NtSetCachedSigningLevel,
	wintypes.NTSTATUS,
	(
		wintypes.ULONG,
		wintypes.SE_SIGNING_LEVEL,
		wintypes.PHANDLE,
		wintypes.ULONG,
		wintypes.HANDLE
	)
)

address = m_k32.GetModuleHandleW('ntdll.dll')
