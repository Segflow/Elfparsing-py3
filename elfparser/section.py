
from elfparser.flags import *
from struct import pack,unpack

class Section(object):
	"""Class representing a Section"""
	def __init__(self, data,arch = ELFCLASS32):
		self.data      = data
		self.str_name     = None
		self.sh_name      = None
		self.sh_type      = None
		self.sh_flags     = None
		self.sh_addr      = None
		self.sh_offset    = None
		self.sh_size      = None
		self.sh_link      = None
		self.sh_info      = None
		self.sh_addralign = None
		self.sh_entsize   = None

		self._parseRawData(arch)


	def _parseRawData(self,arch):
		try:
			if arch == ELFCLASS32:
				self.str_name     = None
				self.sh_name      = unpack("<I", self.data[0:4])[0]
				self.sh_type      = unpack("<I", self.data[4:8])[0]
				self.sh_flags     = unpack("<I", self.data[8:12])[0]
				self.sh_addr      = unpack("<I", self.data[12:16])[0]
				self.sh_offset    = unpack("<I", self.data[16:20])[0]
				self.sh_size      = unpack("<I", self.data[20:24])[0]
				self.sh_link      = unpack("<I", self.data[24:28])[0]
				self.sh_info      = unpack("<I", self.data[28:32])[0]
				self.sh_addralign = unpack("<I", self.data[32:36])[0]
				self.sh_entsize   = unpack("<I", self.data[36:40])[0]
			
			elif arch == ELFCLASS64:
				self.str_name     = None
				self.sh_name      = unpack("<I", self.data[0:4])[0]
				self.sh_type      = unpack("<I", self.data[4:8])[0]
				self.sh_flags     = unpack("<Q", self.data[8:16])[0]
				self.sh_addr      = unpack("<Q", self.data[16:24])[0]
				self.sh_offset    = unpack("<Q", self.data[24:32])[0]
				self.sh_size      = unpack("<Q", self.data[32:40])[0]
				self.sh_link      = unpack("<Q", self.data[40:48])[0]
				self.sh_info      = unpack("<Q", self.data[48:56])[0]
				self.sh_addralign = unpack("<Q", self.data[56:64])[0]
				self.sh_entsize   = unpack("<Q", self.data[64:72])[0]
				
		except Exception as err:
			print(err)