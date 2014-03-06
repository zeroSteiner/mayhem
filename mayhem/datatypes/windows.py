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

# http://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
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
