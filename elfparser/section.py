#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#    Copyright (C) 2012-08 Assel Meher - http://www.twitter.com/asselmeher
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


from elfparser.flags import *
from struct import pack,unpack

class Section(object):
	"""Class representing a Section"""
	def __init__(self, data,arch = ELFCLASS32):
		self.data         = data
		self._arch        = arch
		self.name         = None
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

		self._parseRawData()

	def _parseRawData(self):
		try:
			self.sh_name      = unpack("<I", self.data[0:4])[0]
			self.sh_type      = unpack("<I", self.data[4:8])[0]
			if self._arch == ELFCLASS32:
				self.name         = None
				self.sh_flags     = unpack("<I", self.data[8:12])[0]
				self.sh_addr      = unpack("<I", self.data[12:16])[0]
				self.sh_offset    = unpack("<I", self.data[16:20])[0]
				self.sh_size      = unpack("<I", self.data[20:24])[0]
				self.sh_link      = unpack("<I", self.data[24:28])[0]
				self.sh_info      = unpack("<I", self.data[28:32])[0]
				self.sh_addralign = unpack("<I", self.data[32:36])[0]
				self.sh_entsize   = unpack("<I", self.data[36:40])[0]
			
			elif self._arch == ELFCLASS64:
				self.name         = None
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

	def __contains__(self,addr):
		end = self.sh_addr + self.sh_size
		return (self.sh_addr != 0 and addr >= self.sh_addr and addr < end)

	def __repr__(self):
		return str("Section: '{}'".format(self.name))

	def isExecutable(self):
		"""
		Return True if the section is executable, False esle
		"""
		return self.sh_flags & (1 << 2) == SHF_EXECINSTR

	def isWritable(self):
		"""
		Return True if the section is writable, False esle
		"""
		return self.sh_flags & (1 << 0) == SHF_WRITE
