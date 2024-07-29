import marshal
import types

def bytecode_to_pyc(bytecode, consts, names, output_filename):
    code_obj = types.CodeType(
        0,
        0,
        0,
        0,
        0,
        0,
        bytecode,
        consts,
        names,
        (),
        '',
        '',
        0,
        b'',
        (),
        ()
    )

    with open(output_filename, "wb") as f:
        # pyc header from main.pyc
        f.write(b'\x6F\x0D\x0D\x0A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        marshal.dump(code_obj, f)

with open("./checker.so", "rb") as f:
    data = f.read()

names = [b'\xf0\x90\x8a\x90', b'\xce\xa7', b'X', b'A', b'\xe1\x97\x85', b'\xe1\x8e\xaa', b'\xd0\xa5', b'\xd0\x90', b'\xce\x91', b'\xf0\x90\x8a\xa0', b'\xe1\xb4\x80']
# names = [n.decode() for n in names]

funcs = {
    b'checker': 'checker',
    b'\xe1\xb4\x80': 'ROR',
    b'\xf0\x90\x8a\xa0': 'ROL',
    b'\xce\x91': 'ADD',
    b'\xd0\x90': 'SUB',
    b'A': 'XOR',
    b'\xe1\x8e\xaa': 'SHR',
    b'\xe1\x97\x85': 'SHL',
    b'X': 'AND',
    b'\xce\xa7': 'REG_ADD',
    b'\xd0\xa5': 'REG_SUB',
    b'\xf0\x90\x8a\x90': 'REG_XOR'
}

names = [funcs[n] for n in names]

# 1
co_consts = (None, 4, 5, 6, 0, 255, 40, 8, 177, 97, 110, 3, 140, 85, 51, 1, 202, 90, 189, 163, 138, 206, 133, 2, 87, 19, 238, 47, 93, 216, 150, 253, 115, 123, 251, 174, 217, 167, 117)
co_code = data[0x44c0:0x44c0+0xb14]
co_names = ('checker', names[0], names[1], names[2], names[3], names[4], names[5])
bytecode_to_pyc(co_code, co_consts, co_names, '1.pyc')

# 2
co_consts = (None, 3, 1, 2, 0xA5B577C2FB57F719, 0, 0x92BFDDFEC2F52F3B, 0xCADC9BA99A2AE444, 0x37E4241DF14718D, 45, 0xA324444E39C3E7E7, 44, 9, 52, 0x5350EA4003B419E1, 0x7D27118487B24A4C, 38, 0xB948CBBF8C616936, 60, 57, 0x8C27C187B5925EA7, 0x6011664A1FEADD72, 0xC6B76B35DC565F4B, 58, 56, 0x5D13D65E4A7935DD, 30, 0x78F00494B1FD4117, 13, 0x15A37CDF4F1C5ECE, 63, 26, 0x23683B20A006C3F1, 42, 0x3F3CD0B931FB83BA, 0x24ACE0DA2A14EF6D, 46, 0x9E69F9D52FE5A72A, 0x9F0093FA7D70E962, 0x79584D73A695110C, 39, 55, 0x7B66780079BCF18D, 0x273E52F26CEB226B, 0xA1D8A9D784041E4, 0x54ACA4906A29539B, 0x982A5ED5AD23B3F5, 0x29DD2DB2114BF812, 0x14051B581BA4A8EC, 0x498E0B410BEE2B9E)
co_code = data[0x40e0:0x40e0+0x3c4]
co_names = ('checker', names[6], names[7], names[8], names[3], names[0], names[9], names[10], names[1])
bytecode_to_pyc(co_code, co_consts, co_names, '2.pyc')

# 3
co_consts = (None, 4, 5, 0, 32, 3129497952, 4021042316, 509917840, 256360629, 1, 2, 3)
co_code = data[0x4fe0:0x4fe0+0x424]
co_names = ('checker', names[0], names[5], names[3], names[4])
bytecode_to_pyc(co_code, co_consts, co_names, '3.pyc')
