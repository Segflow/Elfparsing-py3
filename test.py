

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
writable = binary.getSections(lambda x:x.isWritable())
for s in writable:
	print(s.name)