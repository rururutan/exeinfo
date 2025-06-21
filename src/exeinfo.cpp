#include<cstdio>
#include<cstdint>
#include<string>

enum MZHeaderOffset {
	MZ_MAGIC       = 0x00, // Signature "MZ"
	MZ_CBLP        = 0x02, // Bytes on last page of file
	MZ_CP          = 0x04, // Pages in file
	MZ_CRLC        = 0x06, // Relocations
	MZ_CPARHDR     = 0x08, // Size of header in paragraphs
	MZ_MINALLOC    = 0x0A, // Minimum extra paragraphs needed
	MZ_MAXALLOC    = 0x0C, // Maximum extra paragraphs needed
	MZ_SS          = 0x0E, // Initial (relative) SS
	MZ_SP          = 0x10, // Initial SP
	MZ_CHECKSUM    = 0x12, // Checksum
	MZ_IP          = 0x14, // Initial IP
	MZ_CS          = 0x16, // Initial (relative) CS
	MZ_RELOC_TABLE = 0x18, // Offset of relocation table
	MZ_OVNO        = 0x1A, // Overlay number
};

static uint16_t GetU16LE(uint8_t*ptr)
{
	return ptr[0] + (ptr[1]<<8);
}

static uint32_t GetU32LE(uint8_t*ptr)
{
	return ptr[0] + (ptr[1]<<8) + (ptr[2]<<16) + (ptr[3]<<24);
}

static bool checkDOS(FILE *fp, std::string &information, uint8_t *oldStyleHeader, long fileSize) {
	uint8_t dwordBuf[4] = {};

	if (memcmp("diet", &oldStyleHeader[0x1c], 4) == 0) {
		information += " (DIET)";
	} else
	if (memcmp("LZ91", &oldStyleHeader[0x1c], 4) == 0) {
		information += " (LZEXE)";
	} else
	if (memcmp("LZ09", &oldStyleHeader[0x1c], 4) == 0) {
		information += " (LZEXE)";
	} else
	if (memcmp("WWP ", &oldStyleHeader[0x1c], 4) == 0) {
		information += " (WWPACK)";
	} else
	if (memcmp("UC2X", &oldStyleHeader[0x1c], 4) == 0) {
		information += " (UCEXE)";
	} else
	if (memcmp("PK", &oldStyleHeader[0x1e], 2) == 0) {
		fseek(fp, 0x20, SEEK_SET);
		fread(dwordBuf, 4, 1, fp);
		if (memcmp("LITE", dwordBuf, 4) == 0) {
			information += " (PKLite)";
		}
	} else
	{
		uint8_t exepack_header[18] = {};
		uint32_t exepack_header_ofs = GetU16LE(&oldStyleHeader[MZ_CPARHDR]) * 0x10;
		exepack_header_ofs += GetU16LE(&oldStyleHeader[MZ_CS]) * 0x10;
		fseek(fp, exepack_header_ofs, SEEK_SET);
		if (fread(exepack_header, 18, 1, fp) == 1) {
			if (memcmp("RB", &exepack_header[0x10], 2) == 0 ||
				memcmp("RB", &exepack_header[0x0e], 2) == 0) {
				information += " (EXEPACK)";
			}
		}
	}
	if (fileSize > 0x30) {
		uint8_t axeBuf[7] {};
		fseek(fp, 0x20, SEEK_SET);
		fread(axeBuf, 7, 1, fp);
		if (memcmp("-AXE", axeBuf+3, 4) == 0) {
			// AXE 2.0 'SEA-AXE'
			// AXE 1.1(JP) as 瞬間AXE '\0MD-AXEJ'
			information += " (AXE)";
		}
	} else
	if (fileSize > 0x60) {
		fseek(fp, 0x55, SEEK_SET);
		fread(dwordBuf, 4, 1, fp);
		if (memcmp("UPX!", dwordBuf, 4) == 0) {
			information += " (UPX)";
		}
	}
	{
		uint32_t go32_header_ofs = GetU16LE(&oldStyleHeader[MZ_CPARHDR]) * 0x10;
		uint8_t go32Buf[8] = {};
		fseek(fp, go32_header_ofs, SEEK_SET);
		if (fread(go32Buf, 8, 1, fp) == 1) {
			if (memcmp("go32stub", go32Buf, 8) == 0) {
				information += " (DJGPP DOS Extender)";
			}
		}
	}
	return true;
}

static bool checkNE(FILE *fp, std::string &information, uint32_t offsSegmentExeHeader) {
	uint8_t wordBuf[2] = {};
	uint8_t dwordBuf[4] = {};
	// https://wiki.osdev.org/NE
	fseek(fp, offsSegmentExeHeader+0x36, SEEK_SET);
	uint8_t targOS;
	fread(&targOS, 1, 1, fp);
	switch (targOS) {
	case 0:
	{
		fseek(fp, offsSegmentExeHeader+0x3e, SEEK_SET);
		fread(&wordBuf, 2, 1, fp);
		if (GetU16LE(wordBuf) != 0) {
			information += "Windows ";
			information += std::to_string((int)wordBuf[1]) + "." + std::to_string((int)wordBuf[0]);
		} else {
			information += "OS/2 1.0 or Windows 1~2";
		}
	}
		break;
	case 1:
		information += "OS/2 1.x";
		break;
	case 2:
	{
		information += "Windows ";
		fseek(fp, offsSegmentExeHeader+0x3e, SEEK_SET);
		fread(&wordBuf, 2, 1, fp);
		information += std::to_string((int)wordBuf[1]) + "." + std::to_string((int)wordBuf[0]);
	}
		break;
	case 3:
		information += "MS-DOS 4.x(multitasking)";
		break;
	case 4:
		information += "Windows 386";
		break;
	case 5:
		information += "Borland Operating System Service";
		break;
	case 0x81:
		information += "Phar Lap 286|DOS Extender(OS/2)";
		break;
	case 0x82:
		information += "Phar Lap 286|DOS Extender(Windows)";
		break;
	case 0xC4:
		// Only some files of WIndows 1.x (USER.EXE, CALENDAR.EXE, etc.)
		information += "Windows 1";
		break;
	default:
		break;
	}
	fseek(fp, offsSegmentExeHeader+0x0c, SEEK_SET);
	fread(dwordBuf, 2, 1, fp);
	if (dwordBuf[1] & 0x80) {
		information += " DLL";
	}
	switch (dwordBuf[1] & 0x07) {
	case 1:
		information += " FullScreen";
		break;
	case 2:
		information += " Console";
		break;
	case 3:
		information += " GUI";
		break;
	default:
		break;
	}
	if (dwordBuf[0] & 0x10) {
		information += " 8086";
	}
	if (dwordBuf[0] & 0x20) {
		information += " 80286";
	}
	if (dwordBuf[0] & 0x40) {
		information += " i386";
	}
	if (dwordBuf[0] & 0x80) {
		information += " x87";
	}

	if (offsSegmentExeHeader>=0x80) {
		fseek(fp, 0x42, SEEK_SET);
		uint8_t pklBuf[6] = {};
		fread(pklBuf, 6, 1, fp);
		if (memcmp("PKlite", pklBuf, 6) == 0) {
			information += " (PKLite)";
		}
	}
	return true;
}

static bool checkLE(FILE *fp, std::string &information, uint32_t offsSegmentExeHeader) {
	uint8_t wordBuf[2] = {};

	fseek(fp, offsSegmentExeHeader+8, SEEK_SET);
	fread(wordBuf, 2, 1, fp);
	uint16_t cpuType = GetU16LE(wordBuf);
	fread(wordBuf, 2, 1, fp);
	uint16_t osType = GetU16LE(wordBuf);

	switch (cpuType) {
	case 01:
		information += "80286";
		break;
	case 02:
		information += "i386";
		break;
	case 03:
		information += "i486";
		break;
	case 04:
		information += "Pentium";
		break;
	case 0x20:
		information += "i860 XR";
		break;
	case 0x21:
		information += "i860 XP";
		break;
	case 0x40:
		information += "MIPS I(R2000/R3000)";
		break;
	case 0x41:
		information += "MIPS II(R6000)";
		break;
	case 0x42:
		information += "MIPS III(R4000)";
		break;
	default:
		information += "Unknown CPU";
		printf("Unknown CPU 0x%x ", cpuType);
		break;
	}
	information += " ";
	switch (osType) {
	case 01:
		information += "OS/2";
		break;
	case 02:
		information += "Windows";
		break;
	case 03:
		information += "Multitasking MS-DOS";
		break;
	case 04:
	{
		information += "Windows ";
		fseek(fp, offsSegmentExeHeader+0xc2, SEEK_SET);
		fread(wordBuf, 2, 1, fp);
		information += std::to_string((int)wordBuf[1]) + "." + std::to_string((int)wordBuf[0]);
	}
		break;
	case 05:
		information += "IBM Microkernel Personality Neutral";
		break;
	default:
		information += "Unknown OS";
		break;
	}
	information += " ";

	fseek(fp, offsSegmentExeHeader+12, SEEK_SET);
	fread(wordBuf, 1, 2, fp);
	uint16_t kind = GetU16LE(wordBuf);
	if ((kind & 0x28000) == 0x8000) {
		// Library module
		information += "DLL";
	}
	if ((kind & 0x20000) > 0) {
		information += "Device Driver";
	}
	if ((kind & 0x300) == 0x300) {
		information += "GUI";
	}
	if ((kind & 0x28300) < 0x300) {
		information += "Console";
	}

	return true;
}

static bool checkPE(FILE *fp, std::string &information, uint32_t offsSegmentExeHeader) {
	uint8_t wordBuf[2] = {};

	fseek(fp, offsSegmentExeHeader+0x4, SEEK_SET);
	fread(wordBuf, 2, 1, fp);
	uint16_t machine = GetU16LE(wordBuf);
	fread(wordBuf, 2, 1, fp);
	uint16_t numberOfSections = GetU16LE(wordBuf);

	fseek(fp, offsSegmentExeHeader+0x14, SEEK_SET);
	fread(wordBuf, 2, 1, fp);
	uint16_t sizeOfOptionalHeader = GetU16LE(wordBuf);

	fread(wordBuf, 2, 1, fp);
	uint16_t characteristics = GetU16LE(wordBuf);

	fread(wordBuf, 2, 1, fp);
	uint16_t peFormat = GetU16LE(wordBuf);

	// PE format header + 18h
	switch (peFormat) {
	case 0x10b:
		// PE32
		information += "Portable Executable (32bit) : ";
		break;
	case 0x20b:
		// PE32+
		information += "Portable Executable (64bit) : ";
		break;
	default:
		// Unknown
		information += "Portable Executable (unknown) : ";
		printf("Unknown PE 0x%x ", peFormat);
		break;
	}

	// PE: Segment header + 4 (word)
	// machine
	switch (machine) {
	case 0x14c:
		// IA32
		information += "x86";
		break;
	case 0x8664:
		// AMD64
		information += "x86-64";
		break;
	case 0x200:
		// Itanium
		information += "Itanium";
		break;
	case 0x184:
		// Alpha
		information += "Alpha64";
		break;
	case 0x284:
		// Alpha AXP64
		information += "AXP64";
		break;
	case 0x1c0:
		// ARM little endian
		information += "ARM";
		break;
	case 0x1c2:
		// ARM Thumb
		information += "ARM Thumb";
		break;
	case 0x1c4:
		// ARM Thumb-2 little endian
		information += "ARM Thumb-2";
		break;
	case 0xaa64:
		// ARM64 little endian
		information += "ARM64";
		break;
	case 0x162:
		// MIPS (R3000)
		information += "MIPS R3000";
		break;
	case 0x166:
		// MIPS little endian (R4000)
		information += "MIPS little endian";
		break;
	case 0x168:
		// MIPS (R10000)
		information += "MIPS R10000";
		break;
	case 0x169:
		// MIPS little endian WCE v2
		information += "MIPS little endian WCE v2";
		break;
	case 0x266:
		// MIPS16
		information += "MIPS16";
		break;
	case 0x366:
		// MIPS with FPU (MIPS IV)
		information += "MIPS with FPU";
		break;
	case 0x466:
		// MIPS16 with FPU
		information += "MIPS16 with FPU";
		break;
	case 0x268:
		// M68K
		information += "M68K";
		break;
	case 0x1f0:
		// PowerPC little endian
		information += "PowerPC";
		break;
	case 0x1f1:
		// PowerPC with FPU
		information += "PowerPC with FPU";
		break;
	case 0x1f2:
		// PowerPC big-endian
		information += "PowerPC (big-endian)";
		break;
	case 0x520:
		// Infineon TriCore
		information += "TriCore";
		break;
	case 0x5032:
		// Risc-V 32bit
		information += "RISC-V 32bit";
		break;
	case 0x5064:
		// Risc-V 64bit
		information += "RISC-V 64bit";
		break;
	case 0x5128:
		// Risc-V 128bit
		information += "RISC-V 128bit";
		break;
	case 0x1a2:
		// SH3
		information += "Hitachi SH3";
		break;
	case 0x1a3:
		// SH3 DSP
		information += "Hitachi SH3 DSP";
		break;
	case 0x1a6:
		// SH4
		information += "Hitachi SH4";
		break;
	case 0x1a8:
		// SH5
		information += "Hitachi SH5";
		break;
	case 0x6232:
		// LoongArch 32bit
		information += "LoongArch 32bit";
		break;
	case 0x6264:
		// LoongArch 64bit
		information += "LoongArch 64bit";
		break;
	case 0x1d3:
		// Matsushita AM33
		information += "Matsushita AM33";
		break;
	case 0x9041:
		// Mitsubishi M32R
		information += "Mitsubishi M32R";
		break;
	case 0xebc:
		// EFI byte code
		information += "EFI byte code";
		break;
	case 0:
		// Unkown
		information += "Unknown CPU";
		break;
	default:
		// Unkown machine id
		information += "Unknown";
		printf("Unknown Machine 0x%x", machine);
		break;
	}

	// PE: Segment header + 0x5c (word)
	// Subsystem
	fseek(fp, offsSegmentExeHeader+0x5c, SEEK_SET);
	fread(wordBuf, 2, 1, fp);
	uint16_t peSubSystem = GetU16LE(wordBuf);
	// machine
	switch (peSubSystem) {
	case 1:
		information += " Device Driver";
		break;
	case 2:
		information += " GUI";
		break;
	case 3:
		information += " Console";
		break;
	default:
		break;
	}

	if ((characteristics & 0x2000) > 0) {
		information += " DLL";
	}

	// Search section
	fseek(fp, offsSegmentExeHeader+0x18+sizeOfOptionalHeader, SEEK_SET);
	uint8_t sectionData[0x28] {};
	for (int i = 0; i < numberOfSections; i++) {
		fread(sectionData, 0x28, 1, fp);
		if (memcmp(".a64xrm", sectionData, 7) == 0) {
			information += " (ARM64EC)";
		}
		if (memcmp("UPX0", sectionData, 4) == 0) {
			information += " (UPX)";
		}
		if (memcmp(".pklstb", sectionData, 7) == 0) {
			information += " (PKLite32)";
		}
		if (memcmp(".WWP32", sectionData, 6) == 0) {
			information += " (WWPACK32)";
		}
	}

	return true;
}

bool exeInfo(FILE *fp, std::string &information)
{ 
	if (fp == NULL) {
		return false;
	}

	fseek(fp, 0, SEEK_END);
	long fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	uint8_t oldStyleHeader[0x20];
	size_t readed = fread(oldStyleHeader, sizeof(oldStyleHeader), 1, fp);
	if (readed != 1) {
		information += "Header size error\n";
		return false;
	}

	if (oldStyleHeader[0] != 'M' || oldStyleHeader[1] != 'Z') {
		if ((oldStyleHeader[0] == 'P' && oldStyleHeader[1] == '2') ||
			(oldStyleHeader[0] == 'P' && oldStyleHeader[1] == '3') ||
			(oldStyleHeader[0] == 'D' && oldStyleHeader[1] == 'L') ||
			(oldStyleHeader[0] == 'M' && oldStyleHeader[1] == 'P') ||
			(oldStyleHeader[0] == 'M' && oldStyleHeader[1] == 'Q')) {
			information += "Phar Lap DOS Extender\n";
			return true;
		}
		if ((oldStyleHeader[0] == 'A' && oldStyleHeader[1] == 'd') &&
			(oldStyleHeader[2] == 'a'  && oldStyleHeader[3] == 'm') ) {
			information += "DOS32 Extender\n";
			return true;
		}
		if ((oldStyleHeader[0] == 0x7f && oldStyleHeader[1] == 'E') &&
			(oldStyleHeader[2] == 'L'  && oldStyleHeader[3] == 'F') ) {
			information += "ELF (OS/2 PowerPC?)\n";
			return true;
		}
		if ((oldStyleHeader[0] == 'L' && oldStyleHeader[1] == 'X')) {
			information += "Linear Executable (32bit No MZ header) : ";
			return checkLE(fp, information, 0);
		}

		information += "Unknown EXE format\n";
		return false;
	}

	uint16_t offsRelocationTable = GetU16LE(&oldStyleHeader[MZ_RELOC_TABLE]);

	uint8_t dwordBuf[4] = {};
	fseek(fp, 0x3c, SEEK_SET);
	if (fread(dwordBuf, 4, 1, fp) != 1) {
		printf("Size error\n");
		return false;
	}

	uint32_t offsSegmentExeHeader = GetU32LE(dwordBuf);

	fseek(fp, offsSegmentExeHeader, SEEK_SET);
	if (fread(dwordBuf, 4, 1, fp) == 1) {

		if (dwordBuf[0] == 'N' && dwordBuf[1] == 'E') {
			information += "New Executable version.";
			information += std::to_string((int)dwordBuf[2]);
			information += ": ";
			return checkNE(fp, information, offsSegmentExeHeader);
		}

		if ((dwordBuf[0] == 'L' && dwordBuf[1] == 'E') ||
			(dwordBuf[0] == 'L' && dwordBuf[1] == 'X') ) {
			if (dwordBuf[1] == 'E') {
				// LE OS/2 2.0 later, Win3.x Win9x VXD
				information += "Linear Executable (16/32bit mixed) : ";
			} else {
				// LX OS/2 2.0 later
				information += "Linear Executable (32bit) : ";
			}
			return checkLE(fp, information, offsSegmentExeHeader);
		}

		if (dwordBuf[0] == 'P' && dwordBuf[1] == 'E') {
			return checkPE(fp, information, offsSegmentExeHeader);
		}

		if (dwordBuf[0] == 'P' && dwordBuf[1] == 'M') {
			information = "MS-DOS PMODE/W DOS Extender";
			return true;
		}
	}

	// Judged to be old format unless 0x40 is stored at offset 0x1C.
	if (offsRelocationTable != 0x40) {
		information = "MS-DOS";
		return checkDOS(fp, information, oldStyleHeader, fileSize);
	}

	information += "Unknown EXE format\n";
	return false;
}

#ifdef CUI_BUILD
int main(int argc, char* argv[])
{
	if (argc <= 1) {
		printf("Usage: exeinfo [filename]\n");
		return 0;
	}

	for (int i=1; i<argc; i++) {
		FILE* fp = fopen(argv[i], "rb");
		if (fp) {
			printf(argv[i]);
			printf(":\n");
			std::string info;
			exeInfo(fp, info);
			printf(info.c_str());
			printf("\n");
			fclose(fp);
		}
	}

	return 0;
}
#endif
