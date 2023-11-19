#include<cstdio>
#include<cstdint>
#include<string>

static uint16_t GetWord(unsigned char*ptr)
{
	return ptr[0] + (ptr[1]<<8);
}

static uint32_t GetDword(unsigned char*ptr)
{
	return ptr[0] + (ptr[1]<<8) + (ptr[2]<<16) + (ptr[3]<<24);
}


bool exeInfo(FILE *fp, std::string &information)
{ 
	if (fp == NULL) {
		return false;
	}

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
			information += "Phar Lap DOS extenders";
			return true;
		}
		information += "Unknown EXE format\n";
		return false;
	}

	uint16_t offsRelocationTable = GetWord(&oldStyleHeader[0x18]);

	uint8_t wordBuf[2] = {0};

	// 0x1Cに0x40が格納されていなければ旧形式
	if (offsRelocationTable != 0x40) {
		information = "MS-DOS";
		return true;
	}

	uint8_t dwordBuf[4];
	fseek(fp, 0x3c, SEEK_SET);
	if (fread(dwordBuf, 4, 1, fp) != 1) {
		printf("Size error\n");
		return false;
	}
	uint32_t offsSegmentExeHeader = GetDword(dwordBuf);

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
			information += "MS Windows 3.x";
			break;
		  case 3:
			information += "MS-DOS";
			break;
		  case 4:
			information += "Windows 386";
			break;
		  case 5:
			information += "Borland Operating System Service";
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
		uint16_t cpuType = GetWord(wordBuf);
		fread(wordBuf, 1, 2, fp);
		uint16_t osType = GetWord(wordBuf);

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
			information += "DOS 4.x";
			break;
		  case 04:
			information += "Windows 386";
			break;
		  default:
			information += "Unknown OS";
			break;
		}
		information += " ";

		fseek(fp, 4, SEEK_CUR);
		fread(wordBuf, 1, 2, fp);
		uint16_t kind = GetWord(wordBuf);
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
		uint16_t machine = GetWord(wordBuf);
		fseek(fp, 0x12, SEEK_CUR);
		fread(wordBuf, 2, 1, fp);
		uint16_t peFormat = GetWord(wordBuf);

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
			information += "Alpha";
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

		return true;
	}

	if (dwordBuf[0] == 'P' && dwordBuf[1] == 'M') {
		information = "MS-DOS PMODE/W";
		return true;
	}

	information += "Unknown EXE format\n";
	return false;
}

#if 0
int main(int argc, char* argv[])
{
	if (argc <= 1) {
		printf("Usage: exeinfo [filename]\n");
		return 0;
	}

	for (int i=1; i<argc; i++) {
		printf(argv[i]);
		printf(":\n");
		FILE* fp = fopen(fileName, "rb");
		std::string info;
		exeInfo(fp, info);
		printf(info.c_str());
		printf("\n");
	}

	return 0;
}
#endif
