'''
1. python3 pyinstxtractor.py main
2. pycdc main.pyc
3. extract bytecode from checker.so (python3.10 bytecode_to_pyc.py)
4. decompile bytecodes -> z3
'''

from z3 import *

class Checker:
    def __init__(self):
        self.REG = [BitVec(f'flag_{i}', 64) for i in range(16)]

    def ROR(self, i, j):
        self.REG[i] = RotateRight(self.REG[i], j)

    def ROL(self, i, j):
        self.REG[i] = RotateLeft(self.REG[i], j)

    def ADD(self, i, j):
        self.REG[i] += j

    def SUB(self, i, j):
        self.REG[i] -= j

    def SHR(self, i, j):
        self.REG[i] = LShR(self.REG[i], j)

    def SHL(self, i, j):
        self.REG[i] <<= j

    def AND(self, i, j):
        self.REG[i] &= j

    def XOR(self, i, j):
        self.REG[i] ^= j

    def REG_ADD(self, i, j):
        self.REG[i] += self.REG[j]

    def REG_SUB(self, i, j):
        self.REG[i] -= self.REG[j]

    def REG_XOR(self, i, j):
        self.REG[i] ^= self.REG[j]

s = Solver()

checker = Checker()
orig_flag = [x for x in checker.REG]

# 1.py
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(6, 6)
checker.REG_ADD(4, 0)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 40)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 177)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 97)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 110)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 3)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 140)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 85)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 51)
checker.REG_XOR(6, 5)
checker.REG_XOR(0, 0)
checker.REG_ADD(0, 6)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(6, 6)
checker.REG_ADD(4, 1)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 202)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 90)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 189)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 163)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 138)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 206)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 163)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 133)
checker.REG_XOR(6, 5)
checker.REG_XOR(1, 1)
checker.REG_ADD(1, 6)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(6, 6)
checker.REG_ADD(4, 2)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 87)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 19)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 238)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 47)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 93)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 216)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 150)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 253)
checker.REG_XOR(6, 5)
checker.REG_XOR(2, 2)
checker.REG_ADD(2, 6)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(6, 6)
checker.REG_ADD(4, 3)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 115)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 140)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 123)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 251)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 174)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 217)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 167)
checker.REG_XOR(6, 5)
checker.SHL(6, 8)
checker.SHR(4, 8)
checker.REG_XOR(5, 5)
checker.REG_ADD(5, 4)
checker.AND(5, 255)
checker.XOR(5, 117)
checker.REG_XOR(6, 5)
checker.REG_XOR(3, 3)
checker.REG_ADD(3, 6)

# 2.py
checker.REG_SUB(3, 1)
checker.SUB(2, 0xA5B577C2FB57F719)
checker.REG_SUB(0, 3)
checker.ADD(0, 0x92BFDDFEC2F52F3B)
checker.XOR(2, 0xCADC9BA99A2AE444)
checker.SUB(3, 0x37E4241DF14718D)
checker.REG_XOR(3, 1)
checker.ROL(3, 45)
checker.REG_SUB(3, 0)
checker.XOR(2, 0xA324444E39C3E7E7)
checker.ROR(0, 44)
checker.ROR(1, 9)
checker.REG_SUB(0, 2)
checker.REG_ADD(1, 2)
checker.ROR(1, 52)
checker.SUB(2, 0x5350EA4003B419E1)
checker.REG_SUB(3, 1)
checker.REG_ADD(3, 2)
checker.XOR(3, 0x7D27118487B24A4C)
checker.ROL(2, 38)
checker.REG_SUB(3, 0)
checker.XOR(1, 0xB948CBBF8C616936)
checker.ROR(1, 60)
checker.ROL(0, 57)
checker.XOR(0, 0x8C27C187B5925EA7)
checker.REG_SUB(0, 3)
checker.REG_ADD(1, 0)
checker.SUB(2, 0x6011664A1FEADD72)
checker.SUB(3, 0xC6B76B35DC565F4B)
checker.ROL(0, 58)
checker.ROR(1, 56)
checker.REG_XOR(2, 3)
checker.XOR(2, 0x5D13D65E4A7935DD)
checker.REG_XOR(0, 2)
checker.ROL(3, 30)
checker.XOR(2, 0x78F00494B1FD4117)
checker.REG_ADD(2, 0)
checker.REG_XOR(1, 0)
checker.ROL(1, 13)
checker.SUB(1, 0x15A37CDF4F1C5ECE)
checker.ROL(3, 63)
checker.ROL(1, 26)
checker.REG_XOR(3, 0)
checker.SUB(0, 0x23683B20A006C3F1)
checker.REG_SUB(3, 0)
checker.REG_SUB(1, 3)
checker.ROR(0, 42)
checker.ADD(2, 0x3F3CD0B931FB83BA)
checker.ADD(2, 0x24ACE0DA2A14EF6D)
checker.REG_SUB(1, 0)
checker.ROR(2, 46)
checker.SUB(0, 0x9E69F9D52FE5A72A)
checker.REG_XOR(3, 1)
checker.ROL(2, 57)
checker.REG_SUB(0, 3)
checker.XOR(1, 0x9F0093FA7D70E962)
checker.REG_SUB(1, 3)
checker.REG_XOR(2, 0)
checker.ADD(0, 0x79584D73A695110C)
checker.REG_SUB(1, 2)
checker.ROL(3, 39)
checker.ROL(2, 55)
checker.REG_XOR(1, 2)
checker.XOR(2, 0x7B66780079BCF18D)
checker.REG_SUB(0, 1)
checker.ADD(3, 0x273E52F26CEB226B)
checker.XOR(1, 0xA1D8A9D784041E4)
checker.REG_ADD(1, 3)
checker.ADD(3, 0x54ACA4906A29539B)
checker.REG_SUB(2, 1)
checker.REG_ADD(0, 2)
checker.REG_ADD(2, 3)
checker.SUB(3, 0x982A5ED5AD23B3F5)
checker.ADD(0, 0x29DD2DB2114BF812)
checker.REG_SUB(0, 2)
checker.REG_XOR(0, 2)
checker.ROL(2, 13)
checker.ADD(0, 0x14051B581BA4A8EC)
checker.ROR(3, 58)
checker.XOR(1, 0x498E0B410BEE2B9E)

# 3.py
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(4, 0)
checker.SHR(4, 32)
checker.REG_XOR(5, 0)
checker.XOR(4, 0xBA885960)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 0xEFAC3C8C)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 509917840)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 256360629)
checker.SHL(4, 32)
checker.REG_XOR(0, 0)
checker.REG_XOR(0, 4)
checker.REG_XOR(0, 5)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(4, 1)
checker.SHR(4, 32)
checker.REG_XOR(5, 1)
checker.XOR(4, 0xBA885960)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 0xEFAC3C8C)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 509917840)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 256360629)
checker.SHL(4, 32)
checker.REG_XOR(1, 1)
checker.REG_XOR(1, 4)
checker.REG_XOR(1, 5)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(4, 2)
checker.SHR(4, 32)
checker.REG_XOR(5, 2)
checker.XOR(4, 0xBA885960)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 0xEFAC3C8C)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 509917840)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 256360629)
checker.SHL(4, 32)
checker.REG_XOR(2, 2)
checker.REG_XOR(2, 4)
checker.REG_XOR(2, 5)
checker.REG_XOR(4, 4)
checker.REG_XOR(5, 5)
checker.REG_XOR(4, 3)
checker.SHR(4, 32)
checker.REG_XOR(5, 3)
checker.XOR(4, 0xBA885960)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 0xEFAC3C8C)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 509917840)
checker.REG_XOR(4, 5)
checker.REG_XOR(5, 4)
checker.REG_XOR(4, 5)
checker.XOR(4, 256360629)
checker.SHL(4, 32)
checker.REG_XOR(3, 3)
checker.REG_XOR(3, 4)
checker.REG_XOR(3, 5)

s.add(checker.REG[2] == 0xFDF61CB53A00DAA8)
s.add(checker.REG[1] == 0x273AED9AEFD29A3C)
s.add(checker.REG[0] == 0x7AB48E39E26BE2A7)
s.add(checker.REG[3] == 0xFC796489FC8864EE)

assert s.check() == sat

m = s.model()
flag = [m[x].as_long() for x in orig_flag[:4]]
flag = [int.to_bytes(flag[i], 8, 'little') for i in range(4)]

print(b''.join(flag))