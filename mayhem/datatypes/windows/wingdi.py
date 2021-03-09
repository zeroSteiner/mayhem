#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/windows/_wingdi.py
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

from ._scalars import *
from .. import common

__all__ = (
	'BITMAPINFO',
	'BITMAPINFOHEADER',
	'HBITMAP',
	'HDC',
	'HGDIOBJ',
	'MapMode',
	'PBITMAPINFO',
	'PBITMAPINFOHEADER',
	'PHBITMAP',
	'PHDC',
	'PHGDIOBJ',
	'PRGBQUAD',
	'RGBQUAD'
)

HBITMAP           = HANDLE
PHBITMAP          = ctypes.POINTER(HBITMAP)
HDC               = HANDLE
PHDC              = ctypes.POINTER(HDC)
HGDIOBJ           = HANDLE
PHGDIOBJ          = ctypes.POINTER(HGDIOBJ)

class MapMode(common.MayhemEnum):
	"""see:
	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/97b31821-a0db-4113-a210-fffbcedcec4a
	"""
	MM_TEXT = 0x0001
	MM_LOMETRIC = 0x0002
	MM_HIMETRIC = 0x0003
	MM_LOENGLISH = 0x0004
	MM_HIENGLISH = 0x0005
	MM_TWIPS = 0x0006
	MM_ISOTROPIC = 0x0007
	MM_ANISOTROPIC = 0x0008

class RGBQUAD(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-rgbquad
	"""
	_fields_ = [
		('rgbBlue', BYTE),
		('rgbGreen', BYTE),
		('rgbRed', BYTE),
		('rgbReserved', BYTE),
	]
PRGBQUAD = ctypes.POINTER(RGBQUAD)

class BITMAPINFOHEADER(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/previous-versions/dd183376(v=vs.85)
	"""
	_fields_ = [
		('biSize', DWORD),
		('biWidth', LONG),
		('biHeight', LONG),
		('biPlanes', WORD),
		('biBitCount', WORD),
		('biCompression', DWORD),
		('biSizeImage', DWORD),
		('biXPelsPerMeter', LONG),
		('biYPelsPerMeter', LONG),
		('biClrUsed', DWORD),
		('biClrImportant', DWORD),
	]
PBITMAPINFOHEADER = ctypes.POINTER(BITMAPINFOHEADER)

class BITMAPINFO(common.MayhemStructure):
	"""see:
	https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapinfo
	"""
	_fields_ = [
		('bmiHeader', BITMAPINFOHEADER),
		('bmiColors', RGBQUAD * 0),
	]
PBITMAPINFO = ctypes.POINTER(BITMAPINFO)
