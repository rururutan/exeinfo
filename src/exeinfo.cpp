#include<cstdio>
#include<cstdint>
#include<string>

static uint16_t GetU16LE(uint8_t*ptr)
{
	return ptr[0] + (ptr[1]<<8);
}

static uint32_t GetU32LE(uint8_t*ptr)
{
	return ptr[0] + (ptr[1]<<8) + (ptr[2]<<16) + (ptr[3]<<24);
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
			information += "Phar Lap DOS Extenders";
			return true;
		}
		if ((oldStyleHeader[0] == 0x7f && oldStyleHeader[1] == 'E') &&
			(oldStyleHeader[2] == 'L'  && oldStyleHeader[3] == 'F') ) {
			information += "ELF (OS/2 PowerPC?)\n";
			return true;
		}

		information += "Unknown EXE format\n";
		return false;
	}

	uint16_t offsRelocationTable = GetU16LE(&oldStyleHeader[0x18]);

	uint8_t wordBuf[2] = {};
	uint8_t dwordBuf[4] = {};

	// Judged to be old format unless 0x40 is stored at offset 0x1C.
	if (offsRelocationTable != 0x40) {
		information = "MS-DOS";

		if (memcmp("diet", &oldStyleHeader[0x1c], 4) == 0) {
			information += " (DIET)";
		}
		if (memcmp("LZ91", &oldStyleHeader[0x1c], 4) == 0) {
			information += " (LZEXE)";
		}
		if (memcmp("LZ09", &oldStyleHeader[0x1c], 4) == 0) {
			information += " (LZEXE)";
		}
		if (memcmp("WWP ", &oldStyleHeader[0x1c], 4) == 0) {
			information += " (WWPACK)";
		}
		if (memcmp("PK", &oldStyleHeader[0x1e], 2) == 0) {
			fread(dwordBuf, 4, 1, fp);
			if (memcmp("LITE", dwordBuf, 4) == 0) {
				information += " (PKLite)";
			}
		}
		if (fileSize > 0x30) {
			uint8_t axeBuf[7] {};
			fseek(fp, 0x20, SEEK_SET);
			fread(axeBuf, 7, 1, fp);
			if (memcmp("-AXE", axeBuf+3, 4) == 0) {
				// AXE 2.0 'SEA-AXE'
				// AXE 1.1(JP) '\0MD-AXEJ'
				information += " (AXE)";
			}
		}
		if (fileSize > 0x60) {
			fseek(fp, 0x55, SEEK_SET);
			fread(dwordBuf, 4, 1, fp);
			if (memcmp("UPX!", dwordBuf, 4) == 0) {
				information += " (UPX)";
			}
		}
		return true;
	}

	fseek(fp, 0x3c, SEEK_SET);
	if (fread(dwordBuf, 4, 1, fp) != 1) {
		printf("Size error\n");
		return false;
	}
	uint32_t offsSegmentExeHeader = GetU32LE(dwordBuf);

	fseek(fp, offsSegmentExeHeader, SEEK_SET);
	fread(dwordBuf, 4, 1, fp);
	if (dwordBuf[0] == 'N' && dwordBuf[1] == 'E') {
		// https://wiki.osdev.org/NE
		information += "New Executable : ";

		fseek(fp, 0x32, SEEK_CUR);
		uint8_t targOS;
		fread(&targOS, 1, 1, fp);
		switch(targOS) {
		  case 0:
			information += "OS/2 1.0 or MS Windows 1~2";
			break;
		  case 1:
			information += "OS/2 1.x";
			break;
		  case 2:
			information += "MS Windows 2~3";
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
			information += "MS Windows 1";
			break;
		  default:
			break;
		}
		return true;
	}

	if ((dwordBuf[0] == 'L' && dwordBuf[1] == 'E') ||
		(dwordBuf[0] == 'L' && dwordBuf[1] == 'X') ) {

		if (dwordBuf[1] == 'E') {
			// OS/2 2.0 later, Win3.x Win9x VXD
			information += "Linear Executable (16/32bit mixed) : ";
		} else {
			// OS/2 2.0 later
			information += "Linear Executable (32bit) : ";
		}

		fseek(fp, 4, SEEK_CUR);
		fread(wordBuf, 1, 2, fp);
		uint16_t cpuType = GetU16LE(wordBuf);
		fread(wordBuf, 1, 2, fp);
		uint16_t osType = GetU16LE(wordBuf);

		switch(cpuType) {
		  case 01:
			information += "80286";
			break;
		  case 02:
			information += "80386";
			break;
		  case 03:
			information += "80486";
			break;
		  case 04:
			information += "80586";
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
		switch(osType) {
		  case 01:
			information += "OS/2";
			break;
		  case 02:
			information += "Windows";
			break;
		  case 03:
			information += "MS-DOS 4.x(multitasking)";
			break;
		  case 04:
			information += "Windows 386";
			break;
		  case 05:
			information += "IBM Microkernel Personality Neutral";
			break;
		  default:
			information += "Unknown OS";
			break;
		}
		information += " ";

		fseek(fp, 4, SEEK_CUR);
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

	if (dwordBuf[0] == 'P' && dwordBuf[1] == 'E') {

		fread(wordBuf, 2, 1, fp);
		uint16_t machine = GetU16LE(wordBuf);
		fread(wordBuf, 2, 1, fp);
		uint16_t numberOfSections = GetU16LE(wordBuf);

		fseek(fp, 0x0c, SEEK_CUR);

		fread(wordBuf, 2, 1, fp);
		uint16_t sizeOfOptionalHeader = GetU16LE(wordBuf);

		fread(wordBuf, 2, 1, fp);
		uint16_t characteristics = GetU16LE(wordBuf);

		fread(wordBuf, 2, 1, fp);
		uint16_t peFormat = GetU16LE(wordBuf);

		// PE format header + 18h
		switch(peFormat) {
		  case 0x10b:
		  	// PE32
			information += "Portable Executable(32bit) : ";
			break;
		  case 0x20b:
			// PE32+
			information += "Portable Executable(64bit) : ";
			break;
		  default:
		  	// Unknown
			information += "Portable Executable(unknown) : ";
			printf("Unknown PE 0x%x ", peFormat);
			break;
		}

		// PE: Segment header + 4 (word)
		// machine
		switch(machine) {
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
		fseek(fp, 0x42, SEEK_CUR);
		fread(wordBuf, 2, 1, fp);
		uint16_t peSubSystem = GetU16LE(wordBuf);
		// machine
		switch(peSubSystem) {
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
		for (int i=0; i < numberOfSections; i++) {
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

	if (dwordBuf[0] == 'P' && dwordBuf[1] == 'M') {
		information = "MS-DOS PMODE/W DOS Extender";
		return true;
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
		printf(argv[i]);
		printf(":\n");
		FILE* fp = fopen(argv[i], "rb");
		if (fp) {
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
