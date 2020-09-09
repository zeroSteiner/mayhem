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
import itertools
import re

_function_cache = {}
_function_cache_entry = collections.namedtuple('FunctionCacheEntry', ('restype', 'argtypes', 'flags'))

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

# defined here so it can use the function cache
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


_Ref = type(ctypes.byref(ctypes.c_int()))
_Ints = tuple(getattr(ctypes, name) for name in dir(ctypes) if re.match(r'c_int\d*', name))
_Uints = tuple(getattr(ctypes, name) for name in dir(ctypes) if re.match(r'c_uint\d*', name))
_Pointer = ctypes.pointer(ctypes.c_int()).__class__.__bases__[0]
_PointerType = type(ctypes.POINTER(ctypes.c_int))
def repr_cvalue(value, value_type):
	# handle value when it is a ctypes value
	if isinstance(value, ctypes.Structure):
		values = (getattr(value, field[0]) for field in value._fields_)
		value_types = (field[1] for field in value._fields_)
		return '{' + ', '.join(itertools.starmap(repr_cvalue, zip(values, value_types))) + '}'
	if isinstance(value, ctypes.c_bool):
		return repr(value.value).upper()
	if isinstance(value, ctypes.c_void_p):
		return "0x{:0{}x}".format(value.value, ctypes.sizeof(ctypes.c_void_p) * 2)
	if isinstance(value, (_Pointer, _Ref)):
		return "0x{:0{}x}".format(ctypes.cast(value, ctypes.c_void_p).value, ctypes.sizeof(ctypes.c_void_p) * 2)
	if isinstance(value, _Ints):
		return str(value.value)
	if isinstance(value, _Uints):
		return "0x{:0{}x}".format(value.value, ctypes.sizeof(value) * 2)

	# handle value when it is a native python value
	if value is None:
		return 'NULL'
	if isinstance(value, str):
		return "\"{}\"".format(re.sub(r'([\\"])', r'\\\1', value))
	if isinstance(value, bool):
		return repr(value).upper()
	if isinstance(value, int):
		if isinstance(value_type, _Pointer) or value_type is ctypes.c_void_p:
			if value == 0:
				return 'NULL'
			return "0x{:0{}x}".format(value, ctypes.sizeof(ctypes.c_void_p) * 2)
		return "0x{:0{}x}".format(value, ctypes.sizeof(value_type) * 2)
	return repr(value)
