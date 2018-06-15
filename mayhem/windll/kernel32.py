import _ctypes
import collections
import ctypes
import functools

import mayhem.datatypes.windows as wintypes

class CFuncPtr(_ctypes.CFuncPtr):
	_argtypes_ = ()
	_restype_ = None
	_flags_ = 0
	@property
	def address(self):
		return ctypes.cast(self, ctypes.c_void_p).value

	@classmethod
	def new(cls, name, restype=None, argtypes=None, flags=0):
		new = type(name, (cls,), {
			'_argtypes_': argtypes,
			'_restype_': restype,
			'_flags_': flags
		})
		return new

_function_cache = {}
_function_cache_entry = collections.namedtuple('FunctionCacheEntry', ('restype', 'argtypes', 'flags'))
_kernel32 = ctypes.windll.kernel32

def WINFUNCTYPE(restype, *argtypes, use_errno=False, use_last_error=False):
	flags = _ctypes.FUNCFLAG_STDCALL
	if use_errno:
		flags |= _ctypes.FUNCFLAG_USE_ERRNO
	if use_last_error:
		flags |= _ctypes.FUNCFLAG_USE_LASTERROR
	cache_entry = _function_cache_entry(restype=restype, argtypes=argtypes, flags=flags)
	function = _function_cache.get(cache_entry)
	if function is not None:
		return function
	WinFunctionType = CFuncPtr.new('WinFuncType', **cache_entry._asdict())
	_function_cache[cache_entry] = WinFunctionType
	return WinFunctionType

def _patch_winfunctype(address, restype, argtypes=(), **kwargs):
	prototype = WINFUNCTYPE(restype, *argtypes, **kwargs)
	return prototype(address)

GetModuleHandleA = _patch_winfunctype(
	ctypes.cast(_kernel32.GetModuleHandleA, ctypes.c_void_p).value,
	wintypes.HANDLE,
	(wintypes.LPSTR,)
)

GetModuleHandleW = _patch_winfunctype(
	ctypes.cast(_kernel32.GetModuleHandleW, ctypes.c_void_p).value,
	wintypes.HANDLE,
	(wintypes.LPWSTR,)
)

GetProcAddress = _patch_winfunctype(
	ctypes.cast(_kernel32.GetProcAddress, ctypes.c_void_p).value,
	ctypes.c_void_p,
	(wintypes.HMODULE, wintypes.LPSTR)
)

address = GetModuleHandleW('kernel32.dll')
_resolve = functools.partial(GetProcAddress, address)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx
CloseHandle = _patch_winfunctype(
	_resolve(b'CloseHandle\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365146(v=vs.85).aspx
ConnectNamedPipe = _patch_winfunctype(
	_resolve(b'ConnectNamedPipe\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.POVERLAPPED)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
CreateFileA = _patch_winfunctype(
	_resolve(b'CreateFileA\x00'),
	wintypes.HANDLE,
	(
		wintypes.LPSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.HANDLE
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
CreateFileW = _patch_winfunctype(
	_resolve(b'CreateFileW\x00'),
	wintypes.HANDLE,
	(
		wintypes.LPWSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.HANDLE
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx
CreateNamedPipeA = _patch_winfunctype(
	_resolve(b'CreateNamedPipeA\x00'),
	wintypes.HANDLE,
	(
		wintypes.LPSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365150(v=vs.85).aspx
CreateNamedPipeW = _patch_winfunctype(
	_resolve(b'CreateNamedPipeW\x00'),
	wintypes.HANDLE,
	(
		wintypes.LPWSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.PSECURITY_ATTRIBUTES
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcessA = _patch_winfunctype(
	_resolve(b'CreateProcessA\x00'),
	wintypes.BOOL,
	(
		wintypes.LPSTR,
		wintypes.LPSTR,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.BOOL,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.LPSTR,
		wintypes.PSTARTUPINFO,
		wintypes.PPROCESS_INFORMATION
	)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
CreateProcessW = _patch_winfunctype(
	_resolve(b'CreateProcessW\x00'),
	wintypes.BOOL,
	(
		wintypes.LPWSTR,
		wintypes.LPWSTR,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.PSECURITY_ATTRIBUTES,
		wintypes.BOOL,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.LPWSTR,
		wintypes.PSTARTUPINFO,
		wintypes.PPROCESS_INFORMATION
	)
)

CreateRemoteThread = _patch_winfunctype(
	_resolve(b'CreateRemoteThread\x00'),
	wintypes.HANDLE,
	(wintypes.HANDLE, wintypes.PSECURITY_ATTRIBUTES, wintypes.SIZE_T, ctypes.c_void_p, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD),
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453(v=vs.85).aspx
CreateThread = _patch_winfunctype(
	_resolve(b'CreateThread\x00'),
	wintypes.HANDLE,
	(wintypes.PSECURITY_ATTRIBUTES, wintypes.SIZE_T, ctypes.c_void_p, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724251(v=vs.85).aspx
DuplicateHandle = _patch_winfunctype(
	_resolve(b'DuplicateHandle\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE, wintypes.LPHANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658(v=vs.85).aspx
ExitProcess = _patch_winfunctype(
	_resolve(b'ExitProcess\x00'),
	wintypes.VOID,
	(wintypes.UINT,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682659(v=vs.85).aspx
ExitThread = _patch_winfunctype(
	_resolve(b'ExitThread\x00'),
	wintypes.VOID,
	(wintypes.DWORD,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683152(v=vs.85).aspx
FreeLibrary = _patch_winfunctype(
	_resolve(b'FreeLibrary\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
GetCurrentProcess = _patch_winfunctype(
	_resolve(b'GetCurrentProcess\x00'),
	wintypes.HANDLE
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683180(v=vs.85).aspx
GetCurrentProcessId = _patch_winfunctype(
	_resolve(b'GetCurrentProcessId\x00'),
	wintypes.DWORD
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683182(v=vs.85).aspx
GetCurrentThread = _patch_winfunctype(
	_resolve(b'GetCurrentThread\x00'),
	wintypes.HANDLE
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683183(v=vs.85).aspx
GetCurrentThreadId = _patch_winfunctype(
	_resolve(b'GetCurrentThreadId\x00'),
	wintypes.DWORD
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683189(v=vs.85).aspx
GetExitCodeProcess = _patch_winfunctype(
	_resolve(b'GetExitCodeProcess\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683190(v=vs.85).aspx
GetExitCodeThread = _patch_winfunctype(
	_resolve(b'GetExitCodeThread\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError = _patch_winfunctype(
	_resolve(b'GetLastError\x00'),
	wintypes.DWORD
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
GetModuelHandleExA = _patch_winfunctype(
	_resolve(b'GetModuleHandleExA\x00'),
	wintypes.BOOL,
	(wintypes.DWORD, wintypes.LPSTR, wintypes.PHMODULE)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
GetModuelHandleExW = _patch_winfunctype(
	_resolve(b'GetModuleHandleExW\x00'),
	wintypes.BOOL,
	(wintypes.DWORD, wintypes.LPWSTR, wintypes.PHMODULE)
)

GetProcessId = _patch_winfunctype(
	_resolve(b'GetProcessId\x00'),
	wintypes.DWORD,
	(wintypes.HANDLE,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724381(v=vs.85).aspx
GetSystemInfo = _patch_winfunctype(
	_resolve(b'GetSystemInfo\x00'),
	wintypes.VOID,
	(wintypes.PSYSTEM_INFO,)
)

if hasattr(ctypes.windll.kernel32, 'IsWow64Process'):
	# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684139(v=vs.85).aspx
	IsWow64Process = _patch_winfunctype(
		_resolve(b'IsWow64Process\x00'),
		wintypes.BOOL,
		(wintypes.HANDLE, wintypes.PBOOL)
	)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx
LoadLibraryA = _patch_winfunctype(
	_resolve(b'LoadLibraryA\x00'),
	wintypes.HMODULE,
	(wintypes.LPSTR,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx
LoadLibraryW = _patch_winfunctype(
	_resolve(b'LoadLibraryW\x00'),
	wintypes.HMODULE,
	(wintypes.LPWSTR,)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
LoadLibraryExA = _patch_winfunctype(
	_resolve(b'LoadLibraryExA\x00'),
	wintypes.HMODULE,
	(wintypes.LPSTR, wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
LoadLibraryExW = _patch_winfunctype(
	_resolve(b'LoadLibraryExW\x00'),
	wintypes.HMODULE,
	(wintypes.LPWSTR, wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess = _patch_winfunctype(
	_resolve(b'OpenProcess\x00'),
	wintypes.HANDLE,
	(wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
OpenThread = _patch_winfunctype(
	_resolve(b'OpenThread\x00'),
	wintypes.HANDLE,
	(wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365467(v=vs.85).aspx
ReadFile = _patch_winfunctype(
	_resolve(b'ReadFile\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.POVERLAPPED)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
ReadProcessMemory = _patch_winfunctype(
	_resolve(b'ReadProcessMemory\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.SIZE_T, wintypes.SIZE_T)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms686714(v=vs.85).aspx
TerminateProcess = _patch_winfunctype(
	_resolve(b'TerminateProcess\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.UINT)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx
VirtualAlloc = _patch_winfunctype(
	_resolve(b'VirtualAlloc\x00'),
	wintypes.LPVOID,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD)
)

VirtualAllocEx = _patch_winfunctype(
	_resolve(b'VirtualAllocEx\x00'),
	wintypes.SIZE_T,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366892(v=vs.85).aspx
VirtualFree = _patch_winfunctype(
	_resolve(b'VirtualFree\x00'),
	wintypes.BOOL,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD)
)

VirtualFreeEx = _patch_winfunctype(
	_resolve(b'VirtualFreeEx\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366898(v=vs.85).aspx
VirtualProtect = _patch_winfunctype(
	_resolve(b'VirtualProtect\x00'),
	wintypes.BOOL,
	(wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx
VirtualProtectEx = _patch_winfunctype(
	_resolve(b'VirtualProtectEx\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.PDWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366902(v=vs.85).aspx
VirtualQuery = _patch_winfunctype(
	_resolve(b'VirtualQuery\x00'),
	wintypes.SIZE_T,
	(wintypes.LPVOID, wintypes.PMEMORY_BASIC_INFORMATION, wintypes.SIZE_T)
)

VirtualQueryEx = _patch_winfunctype(
	_resolve(b'VirtualQueryEx\x00'),
	wintypes.SIZE_T,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.PMEMORY_BASIC_INFORMATION, wintypes.SIZE_T)
)

WaitForSingleObject = _patch_winfunctype(
	_resolve(b'WaitForSingleObject\x00'),
	wintypes.DWORD,
	(wintypes.HANDLE, wintypes.DWORD)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms687036(v=vs.85).aspx
WaitForSingleObjectEx = _patch_winfunctype(
	_resolve(b'WaitForSingleObjectEx\x00'),
	wintypes.DWORD,
	(wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL)
)

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
WriteProcessMemory = _patch_winfunctype(
	_resolve(b'WriteProcessMemory\x00'),
	wintypes.BOOL,
	(wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.SIZE_T, wintypes.PSIZE_T)
)

#if hasattr(ctypes.windll.kernel32, 'GetModuleFileNameExA'):
	#GetModuleFileNameExA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
	#GetModuleFileNameExA.restype = wintypes.DWORD


