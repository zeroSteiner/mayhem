#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/proc/linux.py
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

import os
import collections
import ctypes
import ctypes.util
import select
import struct
import signal
import platform
import subprocess

import mayhem.datatypes.elf
import mayhem.proc
import mayhem.utilities

elf = mayhem.datatypes.elf
libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
ptrace = libc.ptrace
ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
ptrace.restype = ctypes.c_long

CONSTANTS = {
	'PROT_NONE': 0x00,
	'PROT_READ': 0x01,
	'PROT_WRITE': 0x02,
	'PROT_EXEC': 0x04,
	'PROT_SEM': 0x08,

	'MAP_SHARED': 0x01,
	'MAP_PRIVATE': 0x02,
	'MAP_FIXED': 0x10,
	'MAP_ANONYMOUS': 0x20,

	'RTLD_LOCAL': 0x00,
	'RTLD_LAZY': 0x01,
	'RTLD_NOW': 0x02,
	'RTLD_DEEPBIND': 0x0008,
	'RTLD_GLOBAL': 0x0100,
}

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSR = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSR = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24

class LinuxMemoryRegion(mayhem.proc.MemoryRegion):
	"""Describe a memory region on Linux."""
	def __init__(self, addr_low, addr_high, perms, pathname=None):
		self.pathname = pathname
		"""The file which mapped the region, if known."""
		super(LinuxMemoryRegion, self).__init__(addr_low, addr_high, perms)

	def __repr__(self):
		if self.pathname:
			return "{0:08x}-{1:08x} {2} {3}".format(self.addr_low, self.addr_high, self.perms, self.pathname)
		else:
			return "{0:08x}-{1:08x} {2}".format(self.addr_low, self.addr_high, self.perms)

class LinuxProcessError(mayhem.proc.ProcessError):
	def __init__(self, *args, **kwargs):
		self.errno = kwargs.pop('errno', None)
		"""The libc error number at the time the exception was raised."""
		super(LinuxProcessError, self).__init__(*args, **kwargs)

def get_errno():
	"""
	Get the value of the error from the last function call.

	:return: The error number from libc.
	:rtype: int
	"""
	get_errno_loc = libc.__errno_location
	get_errno_loc.restype = ctypes.POINTER(ctypes.c_int)
	return get_errno_loc()[0]

def parse_proc_maps(pid):
	"""
	Parse the memory maps file for *pid* into a dictionary of
	:py:class:`.LinuxMemoryRegion` objects with keys of their starting
	address.

	:param int pid: The pid to parse the maps file from /proc for.
	:return: The parsed memory regions for *pid*.
	:rtype: dict
	"""
	_maps = collections.deque()
	maps_h = open('/proc/' + str(pid) + '/maps', 'r')
	for memory_region in maps_h:
		memory_region = memory_region[:-1]
		pathname = None
		if memory_region.find('/') != -1:
			pathname = memory_region[memory_region.find('/'):]
		memory_region = memory_region.split()
		addr_low, _, addr_high = memory_region[0].partition('-')
		addr_low = int(addr_low, 16)
		addr_high = int(addr_high, 16)
		perms = memory_region[1]
		if pathname is None and len(memory_region) == 6:
			pathname = memory_region[5]
		_maps.append(LinuxMemoryRegion(addr_low, addr_high, perms, pathname))
	return collections.OrderedDict((mr.addr_low, mr) for mr in sorted(_maps, key=lambda mr: mr.addr_low))

def architecture_is_supported(arch):
	return mayhem.utilities.architecture_is_32bit(arch) or mayhem.utilities.architecture_is_64bit(arch)

def flags(flags):
	supported_operators = ['|', '+', '-', '^']
	if isinstance(flags, int):
		return flags
	if flags[0] == '(' and flags[-1] == ')':
		flags = flags[1:-1]
	for sop in supported_operators:
		flags = flags.replace(sop, ' ' + sop + ' ')
	flags
	flags = flags.split()
	parsed_flags = 0
	last_operator = None
	for part in flags:
		if part in CONSTANTS:
			part = CONSTANTS[part]
		elif part in supported_operators:
			last_operator = part
			continue
		else:
			if part.isdigit():
				part = int(part)
			elif part.startswith('0x'):
				part = int(part[2:], 16)
			else:
				raise ValueError('unknown token: ' + part)
		if last_operator is None:
			parsed_flags = part
		else:
			parsed_flags = eval(str(parsed_flags) + last_operator + str(part))
	return parsed_flags

class LinuxProcess(mayhem.proc.ProcessBase):
	"""This class represents a process in a POSIX Linux environment."""
	def __init__(self, pid=None, exe=None):
		if platform.system() != 'Linux':
			raise RuntimeError('incompatible platform')
		# Ensure that we are running in a version of python that matches the native architecture of the system.
		if platform.architecture()[0] == '32bit':
			if not mayhem.utilities.architecture_is_32bit(platform.machine()):
				raise LinuxProcessError('Running a 32-bit version of Python on a non x86 system is not supported')
		elif platform.architecture()[0] == '64bit':
			if not mayhem.utilities.architecture_is_64bit(platform.machine()):
				raise LinuxProcessError('Running a 64-bit version of Python on a non x86-64 system is not supported')
		else:
			raise LinuxProcessError('Could not determine the Python version')
		self._proc_h = None
		signal.signal(signal.SIGCHLD, self._signal_sigchld)
		if exe:
			self._proc_h = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
			pid = self._proc_h.pid
		if pid == -1:
			pid = os.fork()
			if pid == 0:
				select.select([], [], [], None)
			select.select([], [], [], 0.50)
		self.handle = pid
		self.pid = pid
		self.exe_file = os.readlink('/proc/' + str(self.pid) + '/exe')
		ei_ident = open(self.exe_file, 'rb').read(elf.constants.EI_NIDENT)
		if ei_ident[elf.constants.EI_CLASS] == elf.constants.ELFCLASS32:
			self.__arch__ = 'x86'
		elif ei_ident[elf.constants.EI_CLASS] == elf.constants.ELFCLASS64:
			if mayhem.utilities.architecture_is_32bit(platform.machine()):
				raise LinuxProcessError('Controlling a 64-bit process from a 32-bit process is not supported')
			self.__arch__ = 'x86_64'
		else:
			raise LinuxProcessError('Unsupported EI_CLASS ' + str(ei_ident[elf.constants.EI_CLASS]))
		if self._ptrace(PTRACE_ATTACH) != 0:
			Exception('could not open PID')
		os.waitpid(pid, 0)
		self._installed_hooks = []

	def _signal_sigchld(self, signum, frame):
		os.waitpid(self.pid, os.WNOHANG)

	@property
	def maps(self):
		return parse_proc_maps(self.pid)

	def get_proc_attribute(self, attribute):
		requested_attribute = attribute
		if attribute.startswith('&'):
			attribute = attribute[1:] + '_addr'
		if attribute.startswith('elf_'):
			if mayhem.utilities.architecture_is_32bit(self.__arch__):
				attribute = 'elf32_' + attribute[4:]
			elif mayhem.utilities.architecture_is_64bit(self.__arch__):
				attribute = 'elf64_' + attribute[4:]
		if hasattr(self, '_get_attr_' + attribute):
			return getattr(self, '_get_attr_' + attribute)()
		elif not attribute.endswith('_addr') and attribute.startswith('elf32_'):
			if hasattr(self, '_get_attr_' + attribute + '_addr'):
				address = getattr(self, '_get_attr_' + attribute + '_addr')()
				attribute = 'Elf32_' + attribute[6:].title()
				if hasattr(elf, attribute):
					return self._read_structure_from_memory(address, getattr(elf, attribute))
		elif not attribute.endswith('_addr') and attribute.startswith('elf64_'):
			if hasattr(self, '_get_attr_' + attribute + '_addr'):
				address = getattr(self, '_get_attr_' + attribute + '_addr')()
				attribute = 'Elf64_' + attribute[6:].title()
				if hasattr(elf, attribute):
					return self._read_structure_from_memory(address, getattr(elf, attribute))
		raise mayhem.proc.ProcessError('Unknown Attribute: ' + requested_attribute)

	def _get_attr_elf32_ehdr_addr(self):
		for mem_region in self.maps.values():
			if mem_region.pathname != self.exe_file:
				continue
			if self.read_memory(mem_region.addr_low, 4) == b'\x7fELF':
				return mem_region.addr_low
		raise LinuxProcessError('could not locate ehdr')

	def _get_attr_elf32_phdr_addr(self):
		ehdr = self.get_proc_attribute('elf32_ehdr')
		return self.get_proc_attribute('elf32_ehdr_addr') + ehdr.e_phoff

	def _get_attr_elf32_shdr(self):
		ehdr = self.get_proc_attribute('elf32_ehdr')
		with open('/proc/' + str(self.pid) + '/exe', 'rb') as handle:
			handle.seek(ehdr.e_shoff, os.SEEK_SET)
			data = handle.read(ehdr.e_shnum * ehdr.e_shentsize)
		_shdr = (elf.Elf32_Shdr * ehdr.e_shnum)
		shdr = _shdr()
		ctypes.memmove(ctypes.byref(shdr), data, len(data))
		return shdr

	def _get_attr_elf32_dyn_addr(self):
		phdr_addr = self.get_proc_attribute('elf32_phdr_addr')
		phdr = self._read_structure_from_memory(phdr_addr, elf.Elf32_Phdr)
		idx = 0
		while phdr.p_type != elf.constants.PT_DYNAMIC:
			idx += 1
			next_phdr_addr = phdr_addr + (ctypes.sizeof(elf.Elf32_Phdr) * idx)
			phdr = self._read_structure_from_memory(next_phdr_addr, elf.Elf32_Phdr)
		return phdr.p_vaddr

	def _get_attr_elf64_ehdr_addr(self):
		for mem_region in self.maps.values():
			if mem_region.pathname != self.exe_file:
				continue
			if self.read_memory(mem_region.addr_low, 4) == b'\x7fELF':
				return mem_region.addr_low
		raise LinuxProcessError('could not locate ehdr')

	def _get_attr_elf64_phdr_addr(self):
		ehdr = self.get_proc_attribute('elf64_ehdr')
		return self.get_proc_attribute('elf64_ehdr_addr') + ehdr.e_phoff

	def _get_attr_elf64_shdr(self):
		ehdr = self.get_proc_attribute('elf64_ehdr')
		with open('/proc/' + str(self.pid) + '/exe', 'rb') as handle:
			handle.seek(ehdr.e_shoff, os.SEEK_SET)
			data = handle.read(ehdr.e_shnum * ehdr.e_shentsize)
		_shdr = (elf.Elf64_Shdr * ehdr.e_shnum)
		shdr = _shdr()
		ctypes.memmove(ctypes.byref(shdr), data, len(data))
		return shdr

	def _get_attr_elf64_dyn_addr(self):
		phdr_addr = self.get_proc_attribute('elf64_phdr_addr')
		phdr = self._read_structure_from_memory(phdr_addr, elf.Elf64_Phdr)
		idx = 0
		while phdr.p_type != elf.constants.PT_DYNAMIC:
			idx += 1
			next_phdr_addr = phdr_addr + (ctypes.sizeof(elf.Elf64_Phdr) * idx)
			phdr = self._read_structure_from_memory(next_phdr_addr, elf.Elf64_Phdr)
		return phdr.p_vaddr

	def _get_attr_got_addr(self):
		if mayhem.utilities.architecture_is_32bit(self.__arch__):
			dyn_struct = elf.Elf32_Dyn
		elif mayhem.utilities.architecture_is_64bit(self.__arch__):
			dyn_struct = elf.Elf64_Dyn
		else:
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))
		dyn_addr = self.get_proc_attribute('elf_dyn_addr')
		dyn = self._read_structure_from_memory(dyn_addr, dyn_struct)
		idx = 0
		while dyn.d_tag != elf.constants.DT_PLTGOT:
			idx += 1
			next_dyn_addr = dyn_addr + (ctypes.sizeof(dyn_struct) * idx)
			dyn = self._read_structure_from_memory(next_dyn_addr, dyn_struct)
		return dyn.d_un.d_ptr

	def _get_attr_link_map_addr(self):
		got_addr = self.get_proc_attribute('got_addr')
		if mayhem.utilities.architecture_is_32bit(self.__arch__):
			return struct.unpack('II', self.read_memory(got_addr, 8))[1]
		elif mayhem.utilities.architecture_is_64bit(self.__arch__):
			return struct.unpack('QQ', self.read_memory(got_addr, 16))[1]
		else:
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))

	def _get_function_address(self, mod_name, func_name):
		if mayhem.utilities.architecture_is_32bit(self.__arch__):
			ehdr_struct = elf.Elf32_Ehdr
			shdr_struct = elf.Elf32_Shdr
			sym_struct = elf.Elf32_Sym
		elif mayhem.utilities.architecture_is_64bit(self.__arch__):
			ehdr_struct = elf.Elf64_Ehdr
			shdr_struct = elf.Elf64_Shdr
			sym_struct = elf.Elf64_Sym
		else:
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))

		func_name = func_name.encode('utf-8') + b'\x00'
		if os.path.isabs(mod_name):
			exe_maps = tuple(mr for mr in self.maps.values() if mr.pathname == mod_name)
			filename = mod_name
		else:
			exe_maps = tuple(mr for mr in self.maps.values() if mr.pathname and os.path.basename(mr.pathname).startswith(mod_name))
			filename = exe_maps[0].pathname
		handle = open(filename, 'rb')
		ehdr = mayhem.utilities.struct_unpack(ehdr_struct, handle.read(ctypes.sizeof(ehdr_struct)))

		# get the shdrs
		handle.seek(ehdr.e_shoff, os.SEEK_SET)
		data = handle.read(ehdr.e_shnum * ehdr.e_shentsize)
		_shdrs = (shdr_struct * ehdr.e_shnum)
		shdrs = _shdrs()
		ctypes.memmove(ctypes.byref(shdrs), data, len(data))

		symtab = strtab = 0
		for idx, shdr in enumerate(shdrs):
			if shdr.sh_type == elf.constants.SHT_SYMTAB or shdr.sh_type == elf.constants.SHT_DYNSYM:
				if not (shdr.sh_entsize and shdr.sh_size):
					continue
				symtab = idx
			elif shdr.sh_type == elf.constants.SHT_STRTAB:
				if idx != ehdr.e_shstrndx:
					strtab = idx
			if not (symtab and strtab):
				continue
			symh = shdrs[symtab]
			strh = shdrs[strtab]
			handle.seek(strh.sh_offset, os.SEEK_SET)
			strsymtbl = handle.read(strh.sh_size)
			sym_num = symh.sh_size // symh.sh_entsize
			_syms = (sym_struct * sym_num)
			syms = _syms()
			handle.seek(symh.sh_offset, os.SEEK_SET)
			ctypes.memmove(ctypes.byref(syms), handle.read(ctypes.sizeof(syms)), ctypes.sizeof(syms))
			for sym in syms[1:]:
				if sym.st_name == 0:
					continue
				if strsymtbl[sym.st_name:(sym.st_name + len(func_name))] != func_name:
					continue
				return sym.st_value
			symtab = strtab = 0
		raise LinuxProcessError('unable to locate function')

	def _call_function(self, function_address, *args):
		if len(args) > 6:
			raise Exception('can not pass more than 6 arguments')
		registers_backup = self._get_registers()
		if mayhem.utilities.architecture_is_32bit(self.__arch__):
			registers = {'eip': function_address, 'eax': function_address}
			self._set_registers(registers)
			backup_sp = self.read_memory(registers_backup['esp'], 4)
			self.write_memory(registers_backup['esp'], b'\x00\x00\x00\x00')
			for i in range(len(args)):
				stack_cursor = registers_backup['esp'] + ((i + 1) * 4)
				backup_sp += self.read_memory(stack_cursor, 4)
				if args[i] < 0:
					self.write_memory(stack_cursor, struct.pack('i', args[i]))
				else:
					self.write_memory(stack_cursor, struct.pack('I', args[i]))
			self._ptrace(PTRACE_CONT)
			wait_result = os.waitpid(self.pid, 0)
			self.write_memory(registers_backup['esp'], backup_sp)
			ending_ip = self._get_registers()['eip']
			result = self._get_registers()['eax']
		elif mayhem.utilities.architecture_is_64bit(self.__arch__):
			registers = {'rip': function_address, 'rax': function_address}
			arg_registers = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
			for i in range(len(args)):
				registers[arg_registers[i]] = args[i]
			self._set_registers(registers)
			backup_sp = self.read_memory(registers_backup['rsp'], 8)
			self.write_memory(registers_backup['rsp'], b'\x00\x00\x00\x00\x00\x00\x00\x00')
			self._ptrace(PTRACE_CONT)
			wait_result = os.waitpid(self.pid, 0)
			self.write_memory(registers_backup['rsp'], backup_sp)
			ending_ip = self._get_registers()['rip']
			result = self._get_registers()['rax']
		self._set_registers(registers_backup)
		if os.WSTOPSIG(wait_result[1]) == signal.SIGSEGV and ending_ip != 0:
			raise LinuxProcessError('segmentation fault')
		return result

	def _read_structure_from_memory(self, address, structure):
		structure_data = self.read_memory(address, ctypes.sizeof(structure))
		return mayhem.utilities.struct_unpack(structure, structure_data)

	def _ptrace(self, command, arg1=0, arg2=0, check_error=True):
		return ptrace(command, self.pid, arg1, arg2, check_error=check_error)

	def _get_registers(self):
		if not architecture_is_supported(self.__arch__):
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))
		_raw_registers = (ctypes.c_ulong * 32)
		raw_registers = _raw_registers()
		if self._ptrace(PTRACE_GETREGS, 0, ctypes.byref(raw_registers)) != 0:
			raise LinuxProcessError('Error: PTRACE_GETREGS', errno=get_errno())
		registers = {}
		# constants from sys/reg.h
		if mayhem.utilities.architecture_is_32bit(platform.machine()):
			registers['ebx'] = raw_registers[0]
			registers['ecx'] = raw_registers[1]
			registers['edx'] = raw_registers[2]
			registers['esi'] = raw_registers[3]
			registers['edi'] = raw_registers[4]
			registers['ebp'] = raw_registers[5]
			registers['eax'] = raw_registers[6]
			registers['ds'] = raw_registers[7]
			registers['es'] = raw_registers[8]
			registers['fs'] = raw_registers[9]
			registers['gs'] = raw_registers[10]
			registers['orig_eax'] = raw_registers[11]
			registers['eip'] = raw_registers[12]
			registers['cs'] = raw_registers[13]
			registers['eflags'] = raw_registers[14]
			registers['esp'] = raw_registers[15]
			registers['ss'] = raw_registers[16]
		elif mayhem.utilities.architecture_is_64bit(platform.machine()):
			registers['r15'] = raw_registers[0]
			registers['r14'] = raw_registers[1]
			registers['r13'] = raw_registers[2]
			registers['r12'] = raw_registers[3]
			registers['rbp'] = raw_registers[4]
			registers['rbx'] = raw_registers[5]
			registers['r11'] = raw_registers[6]
			registers['r10'] = raw_registers[7]
			registers['r9'] = raw_registers[8]
			registers['r8'] = raw_registers[9]
			registers['rax'] = raw_registers[10]
			registers['rcx'] = raw_registers[11]
			registers['rdx'] = raw_registers[12]
			registers['rsi'] = raw_registers[13]
			registers['rdi'] = raw_registers[14]
			registers['orig_rax'] = raw_registers[15]
			registers['rip'] = raw_registers[16]
			registers['cs'] = raw_registers[17]
			registers['eflags'] = raw_registers[18]
			registers['rsp'] = raw_registers[19]
			registers['ss'] = raw_registers[20]
			registers['fs_base'] = raw_registers[21]
			registers['gs_base'] = raw_registers[22]
			registers['ds'] = raw_registers[23]
			registers['es'] = raw_registers[24]
			registers['fs'] = raw_registers[25]
			registers['gs'] = raw_registers[26]
			if mayhem.utilities.architecture_is_32bit(self.__arch__):
				converted_registers = {}
				converted_registers['ebx'] = registers['rbx']
				converted_registers['ecx'] = registers['rcx']
				converted_registers['edx'] = registers['rdx']
				converted_registers['esi'] = registers['rsi']
				converted_registers['edi'] = registers['rdi']
				converted_registers['ebp'] = registers['rbp']
				converted_registers['eax'] = registers['rax']
				converted_registers['ds'] = registers['ds']
				converted_registers['es'] = registers['es']
				converted_registers['fs'] = registers['fs']
				converted_registers['gs'] = registers['gs']
				converted_registers['orig_eax'] = registers['orig_rax']
				converted_registers['eip'] = registers['rip']
				converted_registers['cs'] = registers['cs']
				converted_registers['eflags'] = registers['eflags']
				converted_registers['esp'] = registers['rsp']
				converted_registers['ss'] = registers['ss']
				registers = converted_registers
		return registers

	def _set_registers(self, registers={}):
		if not architecture_is_supported(self.__arch__):
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))
		old_registers = self._get_registers()
		old_registers.update(registers)
		_raw_registers = (ctypes.c_ulong * 32)
		raw_registers = _raw_registers()
		# constants from sys/reg.h
		if mayhem.utilities.architecture_is_32bit(platform.machine()):
			raw_registers[0] = old_registers['ebx']
			raw_registers[1] = old_registers['ecx']
			raw_registers[2] = old_registers['edx']
			raw_registers[3] = old_registers['esi']
			raw_registers[4] = old_registers['edi']
			raw_registers[5] = old_registers['ebp']
			raw_registers[6] = old_registers['eax']
			raw_registers[7] = old_registers['ds']
			raw_registers[8] = old_registers['es']
			raw_registers[9] = old_registers['fs']
			raw_registers[10] = old_registers['gs']
			raw_registers[11] = old_registers['orig_eax']
			raw_registers[12] = old_registers['eip']
			raw_registers[13] = old_registers['cs']
			raw_registers[14] = old_registers['eflags']
			raw_registers[15] = old_registers['esp']
			raw_registers[16] = old_registers['ss']
		elif mayhem.utilities.architecture_is_64bit(platform.machine()):
			if mayhem.utilities.architecture_is_32bit(self.__arch__):
				_raw_registers = (ctypes.c_ulong * 32)
				raw_registers = _raw_registers()
				if self._ptrace(PTRACE_GETREGS, 0, ctypes.byref(raw_registers)) != 0:
					raise LinuxProcessError('Error: PTRACE_GETREGS', errno=get_errno())
				raw_registers[4] = old_registers['ebp']
				raw_registers[5] = old_registers['ebx']
				raw_registers[10] = old_registers['eax']
				raw_registers[11] = old_registers['ecx']
				raw_registers[12] = old_registers['edx']
				raw_registers[13] = old_registers['esi']
				raw_registers[14] = old_registers['edi']
				raw_registers[15] = old_registers['orig_eax']
				raw_registers[16] = old_registers['eip']
				raw_registers[17] = old_registers['cs']
				raw_registers[18] = old_registers['eflags']
				raw_registers[19] = old_registers['esp']
				raw_registers[20] = old_registers['ss']
				raw_registers[23] = old_registers['ds']
				raw_registers[24] = old_registers['es']
				raw_registers[25] = old_registers['fs']
				raw_registers[26] = old_registers['gs']
			else:
				raw_registers[0] = old_registers['r15']
				raw_registers[1] = old_registers['r14']
				raw_registers[2] = old_registers['r13']
				raw_registers[3] = old_registers['r12']
				raw_registers[4] = old_registers['rbp']
				raw_registers[5] = old_registers['rbx']
				raw_registers[6] = old_registers['r11']
				raw_registers[7] = old_registers['r10']
				raw_registers[8] = old_registers['r9']
				raw_registers[9] = old_registers['r8']
				raw_registers[10] = old_registers['rax']
				raw_registers[11] = old_registers['rcx']
				raw_registers[12] = old_registers['rdx']
				raw_registers[13] = old_registers['rsi']
				raw_registers[14] = old_registers['rdi']
				raw_registers[15] = old_registers['orig_rax']
				raw_registers[16] = old_registers['rip']
				raw_registers[17] = old_registers['cs']
				raw_registers[18] = old_registers['eflags']
				raw_registers[19] = old_registers['rsp']
				raw_registers[20] = old_registers['ss']
				raw_registers[21] = old_registers['fs_base']
				raw_registers[22] = old_registers['gs_base']
				raw_registers[23] = old_registers['ds']
				raw_registers[24] = old_registers['es']
				raw_registers[25] = old_registers['fs']
				raw_registers[26] = old_registers['gs']
		if self._ptrace(PTRACE_SETREGS, 0, ctypes.byref(raw_registers)) != 0:
			raise LinuxProcessError('Error: PTRACE_SETREGS', errno=get_errno())
		return

	def _allocate_malloc(self, size):
		malloc_addr = None
		for lib in ('libc-', 'ld-linux.so'):
			try:
				malloc_addr = self._get_function_address(lib, 'malloc')
			except mayhem.proc.ProcessError:
				continue
			break
		if malloc_addr is None:
			raise mayhem.proc.ProcessError('unable to locate function')
		return self._call_function(malloc_addr, size)

	def _free_free(self, address):
		free_addr = None
		for lib in ('libc-', 'ld-linux.so'):
			try:
				free_addr = self._get_function_address(lib, 'free')
			except mayhem.proc.ProcessError:
				continue
			break
		if free_addr is None:
			raise LinuxProcessError('unable to locate function')
		self._call_function(free_addr, address)
		return

	def _allocate_mmap(self, size, address, permissions, mmap_flags=None):
		mmap_addr = self._get_function_address('libc-', 'mmap')
		address = (address or 0)
		permissions = (permissions or 'PROT_READ | PROT_WRITE | PROT_EXEC')
		permissions = flags(permissions)
		if mmap_flags is None:
			if address == 0:
				mmap_flags = flags('MAP_ANONYMOUS | MAP_PRIVATE')
			else:
				mmap_flags = flags('MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED')
		else:
			mmap_flags = flags(mmap_flags)
		return self._call_function(mmap_addr, address, size, permissions, mmap_flags, -1, 0)

	def _free_munmap(self, address, size):
		munmap_addr = self._get_function_address('libc-', 'munmap')
		result = self._call_function(munmap_addr, address, size)
		if result != 0:
			raise LinuxProcessError('Error: munmap')
		return

	def install_hook(self, mod_name, new_address, name=None, ordinal=None):
		if mayhem.utilities.architecture_is_32bit(self.__arch__):
			lm_struct = elf.Elf32_Link_Map
			dyn_struct = elf.Elf32_Dyn
			sym_struct = elf.Elf32_Sym
		elif mayhem.utilities.architecture_is_64bit(self.__arch__):
			lm_struct = elf.Elf64_Link_Map
			dyn_struct = elf.Elf64_Dyn
			sym_struct = elf.Elf64_Sym
		else:
			raise LinuxProcessError('unsupported architecture: ' + repr(self.__arch__))
		if ordinal:
			raise NotImplementedError('an ordinal is not supported for this implementation')
		if not name:
			raise RuntimeError('a name is required for this implementation')
		lm = self._read_structure_from_memory(self.get_proc_attribute('link_map_addr'), lm_struct)
		if os.path.isabs(mod_name):
			validate_name = lambda lm: bool(self.read_memory_string(lm.l_name) == mod_name)
		else:
			validate_name = lambda lm: bool(os.path.split(self.read_memory_string(lm.l_name))[-1].startswith(mod_name))
		while not validate_name(lm):
			if lm.l_next == 0:
				raise mayhem.proc.ProcessError('unable to locate shared library')
			lm = self._read_structure_from_memory(lm.l_next, lm_struct)
		idx = 0
		dyn = self._read_structure_from_memory(lm.l_ld, dyn_struct)
		nchains = 0
		strtab = 0
		symtab = 0
		while dyn.d_tag:
			idx += 1
			if dyn.d_tag == elf.constants.DT_HASH:
				nchains = struct.unpack('I', self.read_memory(dyn.d_un.d_ptr + ctypes.sizeof(ctypes.c_int), ctypes.sizeof(ctypes.c_int)))[0]
			elif dyn.d_tag == elf.constants.DT_STRTAB:
				strtab = dyn.d_un.d_ptr
			elif dyn.d_tag == elf.constants.DT_SYMTAB:
				symtab = dyn.d_un.d_ptr
			dyn = self._read_structure_from_memory(lm.l_ld + (ctypes.sizeof(dyn_struct) * idx), dyn_struct)
		for idx in range(0, nchains):
			sym = self._read_structure_from_memory(symtab + (ctypes.sizeof(sym_struct) * idx), sym_struct)
			if (sym.st_info & 0xf) != elf.constants.STT_FUNC:
				continue
			if self.read_memory_string(strtab + sym.st_name) == name:
				sym_addr = (symtab + (ctypes.sizeof(sym_struct) * idx))
				old_address = lm.l_addr + sym.st_value
				sym.st_value = (lm.l_addr - new_address)
				self.write_memory(sym_addr, mayhem.utilities.struct_pack(sym))
				hook = mayhem.proc.Hook('eat', (sym_addr + sym_struct.st_value.offset), old_address, new_address)
				self._installed_hooks.append(hook)
				return hook
		raise mayhem.proc.ProcessError('unable to locate function')

	def allocate(self, size=0x400, address=None, permissions=None):
		permissions = (permissions or 'PROT_READ | PROT_WRITE | PROT_EXEC')
		if address is not None or permissions is not None:
			return self._allocate_mmap(size, address, permissions)
		try:
			return self._allocate_malloc(size)
		except mayhem.proc.ProcessError:
			return self._allocate_mmap(size, address, permissions)

	def free(self, address):
		memregion = self.maps.get(address)
		if memregion:
			self._free_munmap(address, (memregion.addr_high - memregion.addr_low))
		else:
			self._free_free(address)

	def protect(self, address, permissions=None, size=0x400):
		permissions = (permissions or 'PROT_READ | PROT_WRITE | PROT_EXEC')
		mprotect_addr = self._get_function_address('libc-', 'mprotect')
		permissions = flags(permissions)
		result = self._call_function(mprotect_addr, address, size, permissions)
		if result != 0:
			raise LinuxProcessError('Error: mprotect')
		return

	def start_thread(self, address, targ=None):
		thread_create_addr = self._get_function_address('libpthread', 'pthread_create')
		thread_id_addr = self._allocate_malloc(0x10)
		result = self._call_function(thread_create_addr, thread_id_addr, 0, address, targ)
		if result != 0:
			raise LinuxProcessError('Error: pthread_create')
		thread_id = struct.unpack('L', self.read_memory(thread_id_addr, ctypes.sizeof(ctypes.c_long)))[0]
		self._free_free(thread_id_addr)
		return thread_id

	def join_thread(self, thread_id):
		thread_join_addr = self._get_function_address('libpthread', 'pthread_join')
		if self._call_function(thread_join_addr, thread_id, 0) != 0:
			raise LinuxProcessError('Error: pthread_join')
		return

	def close(self):
		self._ptrace(PTRACE_DETACH)

	def kill(self):
		signal.signal(signal.SIGCHLD, signal.SIG_DFL)
		os.kill(self.pid, signal.SIGKILL)
		os.waitpid(self.pid, 0)

	def load_library(self, libpath):
		libpath = os.path.abspath(libpath)
		libpath = libpath + "\x00"
		dlopen_addr = self._get_function_address('libc-', '__libc_dlopen_mode')
		readable_address = self._allocate_malloc(0x400)
		readdata_backup = self.read_memory(readable_address, len(libpath))
		self.write_memory(readable_address, libpath)
		dlopen_flags = flags('RTLD_LAZY | RTLD_GLOBAL')
		result = self._call_function(dlopen_addr, readable_address, dlopen_flags)
		self.write_memory(readable_address, readdata_backup)
		if result == 0:
			raise LinuxProcessError('Error: failed to load: ' + repr(libpath))
		self._free_free(readable_address)
		return result

	def read_memory(self, address, size=0x400):
		data = b''
		address_cursor = address
		size_of_long = ctypes.sizeof(ctypes.c_long)
		while len(data) < size:
			value = self._ptrace(PTRACE_PEEKDATA, address_cursor)
			if value == -1:
				errno = get_errno()
				if errno != 0:
					raise LinuxProcessError('Error: PTRACE_PEEKDATA', errno=get_errno())
			data += struct.pack('l', value)
			address_cursor += size_of_long
		data = data[:size]
		return data

	def write_memory(self, address, data):
		address_cursor = address
		size_of_long = ctypes.sizeof(ctypes.c_long)
		sz_overlap = address_cursor % size_of_long
		if sz_overlap:
			address_cursor -= sz_overlap
			data = self.read_memory(address_cursor, sz_overlap) + data
		sz_overlap = size_of_long - ((address_cursor + len(data)) % size_of_long)
		if 0 < sz_overlap < 8:
			data = data + self.read_memory(address_cursor + len(data), sz_overlap)
		for idx in range(0, len(data), size_of_long):
			data_chunk = data[idx:(idx + size_of_long)]
			data_chunk = struct.unpack('l', data_chunk)[0]
			if self._ptrace(PTRACE_POKEDATA, address_cursor + idx, data_chunk) != 0:
				raise LinuxProcessError('Error: PTRACE_POKEDATA', errno=get_errno())
		return
