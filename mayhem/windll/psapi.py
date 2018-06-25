#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/windll/psapi.py
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

_psapi = ctypes.windll.psapi

if hasattr(_psapi, 'GetModuleFileNameExA'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
	GetModuleFileNameExA = m_k32._patch_winfunctype(
		_psapi.GetModuleFileNameExA,
		wintypes.DWORD,
		(wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD)
	)

if hasattr(_psapi, 'GetModuleFileNameExW'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx
	GetModuleFileNameExW = m_k32._patch_winfunctype(
		_psapi.GetModuleFileNameExW,
		wintypes.DWORD,
		(wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD)
	)

address = m_k32.GetModuleHandleW('psapi.dll')
