#Elfparsing-py3

Python3 package for Parsing ELF file

##Installation


    git clone https://github.com/xGeek/Elfparsing-py3
    cd ./Elfparsing-py3
    python3 setup.py install  [as root]


##Exemple
-------

```python
from elfparser.elf import Elf

binary = Elf('Binfile') # Elf is the main class

if not binary.isElf():
	print("Not an ELF file")
	exit(1)

# Showing all executables sections
executables = binary.getSections(lambda x:x.isExecutable()) # we can use 'isWritable()' to select only writable sections ;)
for s in executables:
	print(s.name)
```