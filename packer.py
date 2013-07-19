#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pefile
from tornado.template import Template

pe = pefile.PE("putty.exe")
pe.add_last_section(size=1024)
pe.sections[0].xor_data(1)

pe.data_copy(pe.sections[0].PointerToRawData, pe.sections[-1].PointerToRawData, 512)

imports = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        imports[imp.name] = imp.address

asm = Template(open("pack.tpl.asm", "r").read()).generate(
    imports=imports,
    go=pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress+512,
)

with open("pack.asm", "w") as f:
    f.write(asm)
os.system(r"c:\fasmw\FASM.EXE pack.asm")

asm = Template(open("copy.tpl.asm", "r").read()).generate(
    imports=imports,
    copy_from=pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress,
    copy_to=pe.OPTIONAL_HEADER.ImageBase+pe.sections[0].VirtualAddress,
    copy_len=512,
    xor_len=pe.sections[0].Misc_VirtualSize,
    key_encode=1,
    original_eop=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint,
)
with open("copy.asm", "w") as f:
    f.write(asm)
os.system(r"c:\fasmw\FASM.EXE copy.asm")

new_pack = open("pack.bin", "rb").read()
new_copy = open("copy.bin", "rb").read()

pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[0].VirtualAddress

pe.data_replace(offset=pe.sections[0].PointerToRawData, new_data=new_pack)

pe.data_replace(offset=pe.sections[-1].PointerToRawData+512, new_data=new_copy)

pe.sections[0].Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]

pe.write(filename="result.exe")
