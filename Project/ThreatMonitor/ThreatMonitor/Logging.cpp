#include "stdafx.h"

#include <iostream>
#include <ctime>
#include <windows.h>

#include "DataTypes.h"

using namespace std;

VOID WINAPI getDateTime(PCHAR ret_timeBuffer = NULL, LPWSTR wRet_timeBuffer = NULL) {
	time_t rawtime;
	struct tm * timeinfo;
	PCHAR timeBuffer = (PCHAR) calloc(80, sizeof(CHAR));

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timeBuffer, 80, "[%d-%m-%Y %I:%M:%S] ", timeinfo);

	//Copy to arguments in Ascii
	if (ret_timeBuffer)
		strncpy(ret_timeBuffer, timeBuffer, sizeof(timeBuffer));

	//Conver to Unicode
	LPWSTR lpTimeBuffer = NULL;
	INT cbByteNeeded = MultiByteToWideChar(CP_UTF8, 0, timeBuffer, -1, lpTimeBuffer, 0);
	lpTimeBuffer = (LPWSTR) calloc(cbByteNeeded, sizeof(LPWSTR));
	MultiByteToWideChar(CP_UTF8, 0, timeBuffer, -1, lpTimeBuffer, cbByteNeeded);
	//Copy to arguments in Unicode
	if(wRet_timeBuffer)
		_tcsncpy(wRet_timeBuffer, lpTimeBuffer, cbByteNeeded);
	delete(timeBuffer);
}

VOID WINAPI writeLog(DWORD dwLogType, LPWSTR wchLogBuffer) {
	LPWSTR wchLogFile = L"Logs/APTLog.log";
	HANDLE hFile;
	hFile = CreateFileW(wchLogFile, GENERIC_READ | GENERIC_WRITE | FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
	DWORD dwErrorCode;
	dwErrorCode = GetLastError();

	wcscat(wchLogBuffer, L"\n\0");

	// Write to end of file
	DWORD dwByteNeeded = _tcslen(wchLogBuffer);
	LPOVERLAPPED lpOverLapped = (LPOVERLAPPED) calloc(1, sizeof(OVERLAPPED));
	lpOverLapped->Offset = 0xffffffff;
	lpOverLapped->OffsetHigh = 0xffffffff;
	WriteFileEx(hFile, (LPWSTR)wchLogBuffer, dwByteNeeded*2, lpOverLapped, 0);
	CloseHandle(hFile);
	return;
}


