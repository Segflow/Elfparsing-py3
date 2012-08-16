Elfparsing-py3
==============

Parsing ELF file


```python
from elfparser.elf import Elf

binary = Elf('Binfile')

if not binary.isElf():
	print("Not an ELF file")
	exit(1)

# Showing all executables sections
executables = binary.getSections(lambda x:x.isExecutable())
for s in executables:
	print(s.name)
```