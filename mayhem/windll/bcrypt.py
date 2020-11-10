#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/windll/bcrypt.py
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
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,rr
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import ctypes
import enum

from . import kernel32 as m_k32
import mayhem.datatypes.common as common
import mayhem.datatypes.windows as wintypes

_bcrypt = ctypes.windll.bcrypt

# configuration tables
CRYPT_LOCAL  = 1
CRYPT_DOMAIN = 2

class BCryptInterface(enum.IntEnum):
	Cipher                 = 0x00000001
	Hash                   = 0x00000002
	AsymmetricEncryption   = 0x00000003
	SecretAgreement        = 0x00000004
	Signature              = 0x00000005
	RNG                    = 0x00000006

class CRYPT_CONTEXT_FUNCTIONS(common.MayhemStructure):
	_fields_ = [
		('cFunctions', wintypes.ULONG),
		('rgpszFunctions', ctypes.POINTER(wintypes.PWSTR))       
	]
PCRYPT_CONTEXT_FUNCTIONS = ctypes.POINTER(CRYPT_CONTEXT_FUNCTIONS)

class CRYPT_CONTEXTS(common.MayhemStructure):
	_fields_ = [
		('cContexts', wintypes.ULONG),
		('rgpszContexts', ctypes.POINTER(wintypes.PWSTR))       
	]
PCRYPT_CONTEXTS = ctypes.POINTER(CRYPT_CONTEXTS)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumcontextfunctions
BCryptEnumContextFunctions = m_k32._patch_winfunctype(
	_bcrypt.BCryptEnumContextFunctions,
	wintypes.NTSTATUS,
	(wintypes.ULONG, wintypes.LPWSTR, wintypes.ULONG, wintypes.PULONG, ctypes.POINTER(PCRYPT_CONTEXT_FUNCTIONS))
)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumcontexts
BCryptEnumContexts = m_k32._patch_winfunctype(
	_bcrypt.BCryptEnumContexts,
	wintypes.NTSTATUS,
	(wintypes.ULONG, wintypes.PULONG, ctypes.POINTER(PCRYPT_CONTEXTS))
)

# https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetcontextfunctionproperty
BCryptSetContextFunctionProperty = m_k32._patch_winfunctype(
	_bcrypt.BCryptSetContextFunctionProperty,
	wintypes.NTSTATUS,
	(wintypes.ULONG, wintypes.LPWSTR, wintypes.ULONG, wintypes.LPWSTR, wintypes.LPWSTR, wintypes.ULONG, wintypes.PUCHAR)
)

address = m_k32.GetModuleHandleW('bcrypt.dll')
