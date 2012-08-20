#!/usr/bin/env python3

from elfparser.elf import Elf
from sys import exit,argv


if len(argv) < 2:
	print('Usage:  {} FILENAME'.format(argv[0]))
	exit(2)

binary = Elf(argv[1])

if not binary.isElf():
	print("Not an ELF file")
	exit(1)

# Showing all writable sections
print("Writable sections:")
writable = binary.getSections(lambda x:x.isWritable())
for s in writable:
	print(s.name)

# Showing all executable sections
print("Executable sections:")
executable = binary.getSections(lambda x:x.isExecutable())
for s in executable:
	print(s.name)

# Find where an address exist
addr = 0x08049880
sect = binary.whereIs(addr)
if sect is not None:
	print(hex(addr),'is at {} which is "{}"'.format(sect.name,sect.getFlags(True)))