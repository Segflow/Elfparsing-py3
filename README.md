#Elfparsing-py3

Python3 package for Parsing ELF file

##Installation


    git clone https://github.com/xGeek/Elfparsing-py3
    cd ./Elfparsing-py3
    python3 setup.py install  [as root]


##Exemples


###Getting all Executable sections (Useful for wargame player ;))

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

###Interactive Python

```python
>>> from elfparser.elf import Elf
>>> hbin = Elf('hbinary2') # loading the file
>>> entry = hbin.getEntryPoint()
>>> print(hex(entry)) # the entry poin
0x80484d0

>>> addr = 0x08049edc # let look where this addr is ;)
>>> addr_sect = hbin.whereIs(addr) # whereIs return an Section object
>>> print('{} is in {}'.format(hex(addr),addr_sect.name))
0x8049edc is in .ctors     
>>> ctors = hbin.getSectionByName('.ctors') # just for checking 
>>> addr in ctors # also we can use 'in' ([addr] in [section])
True
>>> # it return True, great ;)
```