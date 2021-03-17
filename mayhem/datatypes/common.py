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
		# this attempts to emulate what Microsoft's Visual C environment does
		if min(cls) < 0:
			return ctypes.c_uint32
		return ctypes.c_int32

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

class _Field(object):
	@staticmethod
	def help_wrapper(field):
		class Field2(field.__class__):
			__doc__ = field.desc

			def __repr__(self):
				return self.__doc__
		return Field2(field.name, field.type_, desc=field.desc, repr=field.repr, enum=field.enum)

	@staticmethod
	def repr_wrapper(value, transform):
		class ReprWrapper(type(value)):
			def __new__(cls, value):
				return super().__new__(cls, value)

			def __repr__(self):
				return transform(self)
		return ReprWrapper(value)

	def __init__(self, name, type_, **kwargs):
		self.name = name
		self.type_ = type_
		self.real_name = '_' + name
		self.desc = kwargs.pop('doc', 'Proxy structure field ' + name)
		self.enum = kwargs.pop('enum', None)
		self.repr = kwargs.pop('repr', None)
		self.size = ctypes.sizeof(type_)

	def __get__(self, instance, owner):
		if not instance:
			return self.help_wrapper(self)
		value = getattr(instance, self.real_name)
		if self.enum:
			return self.enum(value)
		if self.repr:
			return self.repr_wrapper(value, self.repr)
		return value

	def __set__(self, instance, value):
		if self.enum:
			if isinstance(value, int):
				value = self.enum(value)
			elif isinstance(value, str):
				if not hasattr(self.enum, value):
					raise ValueError("{} is not a valid {}".format(value, self.enum.__name__))
				value = getattr(self.enum, value)
			elif isinstance(value, self.enum):
				pass
			else:
				raise TypeError('unknown value')
			value = value.value
		setattr(instance, self.real_name, value)

def _patch_fields(cls_name, bases, namespace):
	anonymous = namespace.get('_anonymous_', ())
	_fields = namespace.get('_fields_', ())
	new_fields = []
	for args in _fields:
		args = collections.deque(args)
		# Create the set of descriptors for the new-style fields:
		name = args.popleft()
		if name in anonymous:
			anon_field = args.popleft()
			new_fields.append((name, anon_field))
			for anon_name, anon_ctype in anon_field._fields_:
				anon_name = anon_name[1:]
				namespace[anon_name] = getattr(anon_field, anon_name)
		else:
			kwargs = {}
			if isinstance(args[-1], dict):
				kwargs = args.pop()
			if issubclass(args[0], MayhemEnum):
				kwargs['enum'] = enum = args.popleft()
				args.insert(0, enum.get_ctype())
			namespace[name] = _Field(name, args[0], **kwargs)
			args.appendleft('_' + name)
			new_fields.append(tuple(args))
	namespace['_fields_'] = new_fields
	return cls_name, bases, namespace

class _MayhemStructureMeta(type(ctypes.Structure)):
	def __new__(metacls, name, bases, namespace):
		return super().__new__(metacls, *_patch_fields(name, bases, namespace))

class MayhemStructure(ctypes.Structure, metaclass=_MayhemStructureMeta):
	__slots__ = ()
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

class _MayhemUnionMeta(type(ctypes.Union)):
	def __new__(metacls, name, bases, namespace):
		return super().__new__(metacls, *_patch_fields(name, bases, namespace))

class MayhemUnion(ctypes.Union, metaclass=_MayhemUnionMeta):
	__slots__ = ()

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
