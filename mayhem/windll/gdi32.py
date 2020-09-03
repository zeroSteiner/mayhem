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
import enum

from . import kernel32 as m_k32
import mayhem.datatypes.common as common
import mayhem.datatypes.windows as wintypes

_gdi32 = ctypes.windll.gdi32

HBITMAP           = wintypes.HANDLE
PHBITMAP          = ctypes.POINTER(HBITMAP)
HDC               = wintypes.HANDLE
PHDC              = ctypes.POINTER(HDC)
HGDIOBJ           = wintypes.HANDLE
PHGDIOBJ          = ctypes.POINTER(HGDIOBJ)

class BITMAPINFOHEADER(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/previous-versions/dd183376(v=vs.85)
	"""
	_fields_ = [
		('biSize', wintypes.DWORD),
		('biWidth', wintypes.LONG),
		('biHeight', wintypes.LONG),
		('biPlanes', wintypes.WORD),
		('biBitCount', wintypes.WORD),
		('biCompression', wintypes.DWORD),
		('biSizeImage', wintypes.DWORD),
		('biXPelsPerMeter', wintypes.LONG),
		('biYPelsPerMeter', wintypes.LONG),
		('biClrUsed', wintypes.DWORD),
		('biClrImportant', wintypes.DWORD),
	]
PBITMAPINFOHEADER = ctypes.POINTER(BITMAPINFOHEADER)

class BITMAPINFO(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapinfo
	"""
	_fields_ = [
		('bmiHeader', BITMAPINFOHEADER),
		('bmiColors', wintypes.RGBQUAD * 0),
	]
PBITMAPINFO = ctypes.POINTER(BITMAPINFO)

# see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/97b31821-a0db-4113-a210-fffbcedcec4a
class MapMode(enum.IntEnum):
	TEXT = 0x0001
	LOMETRIC = 0x0002
	HIMETRIC = 0x0003
	LOENGLISH = 0x0004
	HIENGLISH = 0x0005
	TWIPS = 0x0006
	ISOTROPIC = 0x0007
	ANISOTROPIC = 0x0008

CreateCompatibleBitmap = m_k32._patch_winfunctype(
	_gdi32.CreateCompatibleBitmap,
	HBITMAP,
	(HDC, ctypes.c_int, ctypes.c_int)
)

CreateCompatibleDC = m_k32._patch_winfunctype(
	_gdi32.CreateCompatibleDC,
	HDC,
	(HDC,)
)

CreateDIBitmap = m_k32._patch_winfunctype(
	_gdi32.CreateDIBitmap,
	HBITMAP,
	(HDC, PBITMAPINFOHEADER, wintypes.DWORD, wintypes.PVOID, PBITMAPINFO, wintypes.UINT)
)

SelectObject = m_k32._patch_winfunctype(
	_gdi32.SelectObject,
	HGDIOBJ,
	(HDC, HGDIOBJ)
)

SetLayout = m_k32._patch_winfunctype(
	_gdi32.SetLayout,
	wintypes.DWORD,
	(HDC, wintypes.DWORD)
)

SetMapMode = m_k32._patch_winfunctype(
	_gdi32.SetMapMode,
	ctypes.c_int,
	(HDC, ctypes.c_int)
)

SetStretchBltMode = m_k32._patch_winfunctype(
	_gdi32.SetStretchBltMode,
	ctypes.c_int,
	(HDC,ctypes.c_int)
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

address = m_k32.GetModuleHandleW('gdi32.dll')
