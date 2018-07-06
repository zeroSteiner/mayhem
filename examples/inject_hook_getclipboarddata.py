import ctypes
import platform
import struct

from mayhem import utilities
from mayhem.windll import kernel32 as m_k32
from mayhem.windll import user32 as m_u32

def py_GetClipboardData(uFormat):
	m_u32.MessageBoxW(None, 'Hooked!', 'Hooked!', 0)
	return -1

prototype = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_uint)
GetClipboardData = prototype(py_GetClipboardData)

def jump_stub(address):
	arch = platform.machine()
	if utilities.architecture_is_32bit(arch):
		stub = b'\xb8' + struct.pack('I', address)      # mov eax, address
		stub += b'\xff\xe0'                             # jmp eax
	elif utilities.architecture_is_64bit(arch):
		stub = b'\x48\xb8' + struct.pack('Q', address)  # mov rax, address
		stub += b'\xff\xe0'                             # jmp rax
	return stub

def mayhem():
	handle = -1  # -1 is always a handle to the current process
	module_handle = m_k32.GetModuleHandleW('user32.dll')
	if not module_handle:
		print('user32.dll is not loaded')
		return
	address = m_k32.GetProcAddress(module_handle, b'GetClipboardData')
	if not address:
		print('failed to resolve user32.dll!GetClipboardData')
		return

	stub = jump_stub(ctypes.cast(GetClipboardData, ctypes.c_void_p).value)
	if m_k32.WriteProcessMemory(handle, address, stub, len(stub), None):
		print("successfully installed the trampoline at 0x{0:x}".format(address))
	else:
		print('failed to install the trampoline')

if __name__ == '__main__':
	print('this script must be injected')
elif __name__ == '__mayhem__':
	mayhem()
