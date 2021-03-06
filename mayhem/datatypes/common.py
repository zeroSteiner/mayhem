#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/datatypes/common.py
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

import _ctypes
import collections
import ctypes
import enum
import math

_function_cache = {}
_function_cache_entry = collections.namedtuple('FunctionCacheEntry', ('restype', 'argtypes', 'flags'))

def _int_width(value):
	"""Calculate the number of bits required to represent *value*."""
	if value < 0:
		raise ValueError('value must be a positive integer')
	if value == 0:
		return 1
	return math.floor(math.log(value, 2)) + 1

class MayhemEnum(enum.IntEnum):
	@classmethod
	def from_param(cls, value):
		return int(value)

	@classmethod
	def get_ctype(cls):
		# https://docs.microsoft.com/en-us/cpp/c-language/cpp-integer-limits?view=msvc-160
		types = [
			(True,  ctypes.c_int16),
			(True,  ctypes.c_int32),
			(True,  ctypes.c_int64),
			(False, ctypes.c_uint16),
			(False, ctypes.c_uint32),
			(False, ctypes.c_uint64)
		]
		val_min = min(cls)
		val_max = max(cls)
		required_bits = max(_int_width(abs(val_min)), _int_width(val_max))
		val_signed = val_min < 0
		for ctype_signed, ctype in types:
			if ctype_signed != val_signed:
				continue
			available_bits = ctypes.sizeof(ctype) * 8
			if ctype_signed:
				available_bits -= 1
			if required_bits <= available_bits:
				return ctype
		raise ValueError('could not calculate a compatible ctype')

class MayhemCFuncPtr(_ctypes.CFuncPtr):
	_argtypes_ = ()
	_restype_ = None
	_flags_ = 0
	@property
	def address(self):
		return ctypes.cast(self, ctypes.c_void_p).value

	def duplicate(self, other):
		if callable(other):
			if isinstance(other, ctypes._CFuncPtr):
				other = ctypes.cast(other, ctypes.c_void_p).value
		elif not isinstance(other, int):
			other = ctypes.cast(other, ctypes.c_void_p).value
		return self.__class__(other)

	@classmethod
	def new(cls, name, restype=None, argtypes=None, flags=0):
		new = type(name, (cls,), {
			'_argtypes_': argtypes,
			'_restype_': restype,
			'_flags_': flags
		})
		return new

class MayhemStructure(ctypes.Structure):
	@classmethod
	def from_bytes(cls, value):
		instance = cls()
		if len(value) != ctypes.sizeof(instance):
			raise ValueError('Value is not the correct size')
		ctypes.memmove(ctypes.byref(instance), value, ctypes.sizeof(instance))
		return instance

	@classmethod
	def from_cast(cls, value):
		return ctypes.cast(value, ctypes.POINTER(cls)).contents

# defined here so it can use the function cache
# using this variant causes MayhemCFuncPtr to be used which adds useful properties
def _WINFUNCTYPE(restype, *argtypes, use_errno=False, use_last_error=False):
	flags = _ctypes.FUNCFLAG_STDCALL
	if use_errno:
		flags |= _ctypes.FUNCFLAG_USE_ERRNO
	if use_last_error:
		flags |= _ctypes.FUNCFLAG_USE_LASTERROR
	cache_entry = _function_cache_entry(restype=restype, argtypes=argtypes, flags=flags)
	function = _function_cache.get(cache_entry)
	if function is not None:
		return function
	FunctionType = MayhemCFuncPtr.new('CFunctionType', **cache_entry._asdict())
	_function_cache[cache_entry] = FunctionType
	return FunctionType
