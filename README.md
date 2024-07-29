# rev/FlagChecker (8 solves)

> A simple flag checker

## Solution

### Attachments

[main](./main) : ELF binary created using PyInstaller

### Stage 1

You can determine python version through magic number of `main.pyc`. (or  `libpython3.10.so`)

```python
$ python3.10
>>> import marshal, dis
>>> with open("main.pyc", "rb") as f:
...   data = f.read()[16:]
...   code = marshal.loads(data)
...
>>> dis.dis(code)
...
Disassembly of <code object main at 0x7f364566b3c0, file "main.py", line 5>:
  8           0 LOAD_CONST               1 (0)
              2 STORE_GLOBAL             0 (chk)

  9           4 BUILD_LIST               0
              6 LOAD_CONST               2 ((92, 138, 226, 248, 124, 187, 195, 106, 182, 233, 9, 79, 134, 101, 53, 240, 196, 183, 141, 83, 84, 118, 226, 6, 251, 74, 94, 37, 117, 90))
              8 LIST_EXTEND              1
             10 STORE_GLOBAL             1 (t)

 10          12 SETUP_FINALLY           10 (to 34)

 11          14 LOAD_GLOBAL              2 (list)
             16 LOAD_GLOBAL              3 (input)
             18 LOAD_CONST               3 ('Flag : ')
             20 CALL_FUNCTION            1
             22 LOAD_METHOD              4 (encode)
             24 CALL_METHOD              0
             26 CALL_FUNCTION            1
             28 STORE_GLOBAL             5 (FLAG)
             30 POP_BLOCK
             32 JUMP_FORWARD             9 (to 52)

 12     >>   34 POP_TOP
             36 POP_TOP
             38 POP_TOP

 13          40 LOAD_GLOBAL              6 (print)
             42 CALL_FUNCTION            0
             44 POP_TOP

 14          46 POP_EXCEPT
             48 LOAD_CONST               0 (None)
             50 RETURN_VALUE

 16     >>   52 LOAD_CONST               1 (0)
             54 LOAD_CONST               0 (None)
             56 IMPORT_NAME              7 (checker)
             58 STORE_GLOBAL             7 (checker)

 18          60 LOAD_GLOBAL              0 (chk)
             62 LOAD_CONST               4 (4919)
             64 COMPARE_OP               2 (==)
             66 POP_JUMP_IF_FALSE       69 (to 138)
...
 27     >>  138 LOAD_GLOBAL              6 (print)
            140 LOAD_CONST               7 ('Wrong')
            142 CALL_FUNCTION            1
            144 POP_TOP

 29         146 LOAD_CONST               0 (None)
            148 RETURN_VALUE
```

If `chk != 4919`, it prints `'Wrong'`

`main.pyc` doesn't modifies `chk` so we need to analyze `checker.so`

#### PyInit_checker

```c
__int64 *PyInit_checker()
{
  ...
  module_main = PyImport_ImportModule("__main__");
  emulate = GetAttrString(module_main, emulate_encoded);// PyObject_GetAttrString(module_main, "emulate")
  module = PyModule_Create2(&unk_6480);
  if ( !module )
    return 0LL;
  if ( (int)PyModule_AddFunctions(module, &off_6500) >= 0 )
  {
    FLAG = GetAttrString(module_main, FLAG_encoded);// PyObject_GetAttrString(module_main, "FLAG")
    if ( PyList_Size(FLAG) == 32 )
    {
      Item = PyList_GetItem(FLAG, 31LL);
      v2 = PyLong_AsLong(Item) == '}';
      for ( i = 0; i <= 4; ++i )
      {
        c = PyList_GetItem(FLAG, i);
        if ( (unsigned int)PyLong_AsLong(c) != flag_prefix[i] )// flag_prefix = "DEAD{"
          v2 = 0;
      }
    }
    else
    {
      v2 = 0;
    }
    if ( v2 )
    {
      GetAttrString(module_main, chk_encoded);  // PyObject_GetAttrString(module_main, "chk") -> unused
      const_4919 = PyLong_FromLong(0x1337LL);
      PyObject_SetAttrString(module_main, &chk, const_4919); // chk = 4919
    }
    ++dword_6790;
    return module;
  }
  ...
```

Here, we can get this information
- `sub_13ED` decodes string and calls `PyObject_GetAttrString`
- `len(FLAG)` should be 32
- `FLAG` starts with `DEAD{` and ends with `}`

### Stage 2

In `main.pyc`, it calls `checker.check()` and prints something.

Since it seems to always print `'Wrong'`, we need to check `checker.check()`.

#### Where is `checker.check()`?

We can find `PyInit_checker` calls `PyModule_AddFunctions`, which exports functions to python module.

After searching `PyModule_AddFunctions` API, we can match functions with their names by looking at `off_6500`.

It exports `checker`, `ᴀ`(ROR), `𐊠`(ROL), `Α`(ADD), `А`(SUB), `A`(XOR), etc.

#### sub_2B3C (checker.check)

```c
__int64 sub_2B3C()
{
  __int64 v0; // rax
  int i; // [rsp+0h] [rbp-10h]
  signed int j; // [rsp+4h] [rbp-Ch]
  __int64 t; // [rsp+8h] [rbp-8h]

  sub_1F3B();                                   // initialize components of code object
  for ( i = 0; i <= 2; ++i )
    sub_1DBC();                                 // create code object and calls `emulate`
  if ( !(qword_66F0 ^ 0xFDF61CB53A00DAA8LL | qword_66E8 ^ 0x273AED9AEFD29A3CLL | qword_66E0 ^ 0x7AB48E39E26BE2A7LL | qword_66F8 ^ 0xFC796489FC8864EELL) )
  {
    t = GetAttrString(module_main, t_encoded);  // PyObject_GetAttrString(module_main, "t")
    for ( j = 0; (unsigned int)j <= 0x1D; ++j )
    {
      v0 = PyLong_FromUnsignedLongLong(byte_6410[j]);
      PyList_SetItem(t, j, v0);
    }
  }
  return sub_13CF(&Py_NoneStruct);
}
```

`sub_1F3B` initializes components of code object and `sub_1DBC` calls `emulate` with code object as parameter.

We can create code object by analyzing `sub_1F3B`, `sub_1DBC`.

#### bytecode_to_pyc.py

```python
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
```

By analyzing decompiled bytecodes, you can find that it modifies `qword_66E0`~`qword_66F8` through VM operations.

You can get flag by setting decompiled bytecodes and `checker.check()`'s constraints, and solving them with z3.

Solver code: [sol.py](sol.py)
