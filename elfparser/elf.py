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
from elfparser.section import Section
from struct import pack,unpack

class Elf():
	"""Class representing an ELF file"""
	
	def __init__(self, filename = None):
		# Core
		self.filename     = filename
		self._mmapBinary  = bytes()

		# ElfHeader
		self.e_ident      = None
		self.e_type       = 0x0000
		self.e_machine    = 0x0000
		self.e_version    = 0x00000000
		self.e_entry      = 0x0000000000000000
		self.e_phoff      = 0x0000000000000000
		self.e_shoff      = 0x0000000000000000
		self.e_flags      = 0x00000000
		self.e_ehsize     = 0x0000
		self.e_phentsize  = 0x0000
		self.e_phnum      = 0x0000
		self.e_shentsize  = 0x0000
		self.e_shnum      = 0x0000
		self.e_shstrndx   = 0x0000

		# Program Header
		self.phdr_l = []
		# Section Header
		self.shdr_l = []
		# Symbos Header
		self.sym_l  = []

		if filename is not None:
			self.loadFile(filename)

	def loadFile(self, filename):
		""" Load Binary File """
		try:
			with open(filename, "rb") as File:
				self._mmapBinary = bytes(File.read())
		except Exception as err:
			print(err)
			return False

		if self.isElf(): # Don't go forward if it's not an ELF file ;)
			self._setHeaderElf()
			self._setShdr()
			#self._setPhdr()
			#self._setSym()
		return True
		
	def isElf(self):
		""" Return false or true if is a ELF file """
		try:
			res = self._mmapBinary[:4] == ELFMAG
		except:
			return False
		else:
			return res

	def getArch(self):
		""" Return architecture code """
		try:
			return self.e_ident[EI_CLASS]
		except:
			print("Error - getArch()")

	def getMmapBinary(self):
		""" Return binary maped """
		if self._mmapBinary is None:
			print("Error - getMmapBinary(): No file loaded")
		else:
			return self._mmapBinary

	def whereIs(self,addr):
		"""
		Look out in which section the address 'addr' exist
		"""
		for sect in self.shdr_l:
			if addr in sect:
				return sect

	def _setHeaderElf(self):
		""" Parse ELF header """
		try:
			self.e_ident   = self._mmapBinary[:15]
			self.e_type    = unpack("<H", self._mmapBinary[16:18])[0]
			self.e_machine = unpack("<H", self._mmapBinary[18:20])[0]
			self.e_version = unpack("<I",self._mmapBinary[20:24])[0]
			if self.getArch() == ELFCLASS32:
				self.e_entry      = unpack("<I",self._mmapBinary[24:28])[0]
				self.e_phoff      = unpack("<I",self._mmapBinary[28:32])[0]
				self.e_shoff      = unpack("<I",self._mmapBinary[32:36])[0]
				self.e_flags      = unpack("<I",self._mmapBinary[36:40])[0]
				self.e_ehsize     = unpack("<H",self._mmapBinary[40:42])[0]
				self.e_phentsize  = unpack("<H",self._mmapBinary[42:44])[0]
				self.e_phnum      = unpack("<H",self._mmapBinary[44:46])[0]
				self.e_shentsize  = unpack("<H",self._mmapBinary[46:48])[0]
				self.e_shnum      = unpack("<H",self._mmapBinary[48:50])[0]
				self.e_shstrndx   = unpack("<H",self._mmapBinary[50:52])[0]
			elif self.getArch() == ELFCLASS64:
				self.e_entry      = unpack("<Q",self._mmapBinary[24:32])[0]
				self.e_phoff      = unpack("<Q",self._mmapBinary[32:40])[0]
				self.e_shoff      = unpack("<Q",self._mmapBinary[40:48])[0]
				self.e_flags      = unpack("<I",self._mmapBinary[48:52])[0]
				self.e_ehsize     = unpack("<H",self._mmapBinary[52:54])[0]
				self.e_phentsize  = unpack("<H",self._mmapBinary[54:56])[0]
				self.e_phnum      = unpack("<H",self._mmapBinary[56:58])[0]
				self.e_shentsize  = unpack("<H",self._mmapBinary[58:60])[0]
				self.e_shnum      = unpack("<H",self._mmapBinary[60:62])[0]
				self.e_shstrndx   = unpack("<H",self._mmapBinary[62:64])[0]
			return True
		except Exception as err:
			print("Error - _setHeaderElf()")
			print(err)
			return False


	def _setShdr(self):
		""" Parse Section header """
		shdr_num = self.e_shnum
		arch = self.getArch()
		base = self._mmapBinary[self.e_shoff:]
		for i in range(shdr_num):
			rawData = base[:self.e_shentsize]
			sect = Section(rawData,arch)
			#print(sect.__dict__)
			self.shdr_l.append(sect)
			base = base[self.e_shentsize:]
			
		# set name in section table from string table
		stroff = self.shdr_l[self.e_shstrndx].sh_offset
		string_table = self._mmapBinary[stroff:]
		for i in range(shdr_num):
			self.shdr_l[i].name = string_table[self.shdr_l[i].sh_name:].decode('utf8',errors='ignore').split('\0')[0]

	def loadCode(self, code):
		""" Load Binary code """
		self._mmapBinary = code

		if self.isElf():
			self._setHeaderElf()
			self._setShdr()
			#self._setPhdr()
			#self._setSym()

	def saveBinary(self, filename):
		"""
		save mmapBinary in file
		Ex: elf.saveBinary("./newFile.bin")
		"""
		try:
			with  open(filename, "wb") as File:
				File.write(self._mmapBinary)
		except Exception as err:
			print(err)
			return False
		else:
			self.filename = filename
			return True

	def __eq__(self,other):
		"""
			check if two Elf file are the same.
			Ex: x = Elf('bin1') == Elf('bin2')
			x contain True if 'bin1' and 'bin2' are the same, False else.
		"""
		if isinstance(other,Elf):
			return self._mmapBinary == other._mmapBinary
		elif isinstance(other,bytes):
			return self._mmapBinary == other
		else:
			raise TypeError('Only bytes objects or Elf objects can be compared')

	def getEntryPoint(self):
		"""
		Return entry Point address
		"""
		return self.e_entry

	def getFileSize(self):
		"""
		Return the file size
		"""
		return (len(self._mmapBinary))

	def getSectionByName(self, section_name):
		"""
		Return the Section named 'section_name'
		Exemple - getSectionByName(".text")
		"""
		for shdr in self.shdr_l:
			if shdr.name == section_name:
				return shdr

	def getSections(self, filter_fn = None):
		"""
		Return the Sections list
		if the 'filter_fn'parametre is provided, it will be used as a filter
		Exemple : 
			getSections(lambda sect: sect.isExecutable()) # return only executable Sections
		"""
		if filter_fn is None:
			return self.shdr_l
		else:
			filtred = [shdr for shdr in self.shdr_l if filter_fn(shdr)]
			return filtred