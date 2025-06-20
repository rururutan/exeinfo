
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <locale.h>
#include <stdbool.h>
#include <wchar.h>
#include <vector>
#include "exeinfo.h"
#include "messagebox.h"

#define DIALOG_TITLE L"ExeInfo"

static void ShowLastError(DWORD _code){
	LPWSTR lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, _code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMsgBuf,
		0,
		NULL);
	ShowCustomMessage(NULL, lpMsgBuf, DIALOG_TITLE);
	LocalFree(lpMsgBuf);
}

static bool UTF16toUTF8(const wchar_t* _inPtr, std::string& _outStr)
{
	const int u8Len = WideCharToMultiByte(CP_UTF8, 0, _inPtr, -1, nullptr, 0, nullptr, nullptr);

	auto u8Buf = std::vector<char>(u8Len + 1);
	WideCharToMultiByte(CP_UTF8, 0, _inPtr, -1, u8Buf.data(), u8Len, nullptr, nullptr);

	_outStr = u8Buf.data();
	return true;
}

static bool UTF8toUTF16(const char* _inPtr, std::wstring& _outStr)
{
	const int u16Len = MultiByteToWideChar(CP_UTF8, 0, _inPtr, -1, nullptr, 0);
	if (u16Len <= 0) {
		_outStr.clear();
		return false;
	}

	auto u16Buf = std::vector<wchar_t>(u16Len + 1);
	MultiByteToWideChar(CP_UTF8, 0, _inPtr, -1, u16Buf.data(), u16Len);

	_outStr = u16Buf.data();

	return true;
}


int WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
	setlocale(LC_ALL, ".utf8");

	// check parameter
	int argc;
	LPTSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == NULL) {
		ShowLastError(GetLastError());
		return -1;
	}

	if (argc < 2) {
		// usage
		MessageBox(NULL, L"Usage : exeinfo [filename]", DIALOG_TITLE, MB_ICONWARNING);
		return 1;
	}

	wchar_t fileName[MAX_PATH] = {0};
	std::string information;
	for (int i=1; i<argc; i++) {
		// check file name
		// make full path name
		DWORD result = GetFullPathName(argv[i], MAX_PATH-1, fileName, NULL);
		if (result > MAX_PATH-1) {
			MessageBox(NULL, L"Path name longer than MAX_PATH.", DIALOG_TITLE, MB_ICONERROR);
			return 2;
		}
		if (result == 0) {
			ShowLastError(GetLastError());
			return 2;
		}

		if (GetLongPathName(fileName, fileName, MAX_PATH) == 0) {
			ShowLastError(GetLastError());
			return 3;
		}

		FILE *fp = _wfopen(fileName, L"rb");
		if (fp == NULL) {
			continue;
		}

		std::string info;
		exeInfo(fp, info);
		std::string u8FileName;
		UTF16toUTF8(fileName, u8FileName);
		information += std::string(u8FileName);
		information += "\n ";
		information += info;
		information += "\n\n";

		fclose(fp);
	}

	std::wstring informationW;
	UTF8toUTF16(information.c_str(), informationW);
	ShowCustomMessage(NULL, informationW.c_str(), DIALOG_TITLE);
	LocalFree(argv);

	return 0;
}
