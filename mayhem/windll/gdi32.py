#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/windll/gdi32.py
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

_gdi32 = ctypes.windll.gdi32

HBITMAP   = wintypes.HANDLE
PHBITMAP  = ctypes.POINTER(HBITMAP)
HDC       = wintypes.HANDLE
PHDC      = ctypes.POINTER(HDC)
HGDIOBJ   = wintypes.HANDLE
PHGDIOBJ  = ctypes.POINTER(HGDIOBJ)

CreateCompatibleBitmap = m_k32._patch_winfunctype(
	_gdi32.CreateCompatibleBitmap,
	HBITMAP,
	(
		HDC,
		ctypes.c_int,
		ctypes.c_int
	)
)

CreateCompatibleDC = m_k32._patch_winfunctype(
	_gdi32.CreateCompatibleDC,
	HDC,
	(
		HDC,
	)
)

SelectObject = m_k32._patch_winfunctype(
	_gdi32.SelectObject,
	HGDIOBJ,
	(
		HDC,
		HGDIOBJ
	)
)

SetLayout = m_k32._patch_winfunctype(
	_gdi32.SetLayout,
	wintypes.DWORD,
	(
		HDC,
		wintypes.DWORD
	)
)

StretchBlt = m_k32._patch_winfunctype(
	_gdi32.StretchBlt,
	wintypes.BOOL,
	(
		HDC,
		ctypes.c_int,
		ctypes.c_int,
		ctypes.c_int,
		ctypes.c_int,
		HDC,
		ctypes.c_int,
		ctypes.c_int,
		ctypes.c_int,
		ctypes.c_int,
		wintypes.DWORD
	)
)
