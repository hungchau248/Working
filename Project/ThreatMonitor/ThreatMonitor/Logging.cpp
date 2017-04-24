#include "stdafx.h"

#include <iostream>
#include <ctime>
#include <windows.h>

#include "DataTypes.h"

using namespace std;

VOID WINAPI getDateTime(PCHAR ret_timeBuffer = NULL, LPWSTR wRet_timeBuffer = NULL) {
	time_t rawtime;
	struct tm * timeinfo;
	CHAR timeBuffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timeBuffer, sizeof(timeBuffer), "[%d-%m-%Y %I:%M:%S] ", timeinfo);

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

}

VOID WINAPI writeLog(DWORD dwLogType, LPWSTR wchLogBuffer) {
	LPWSTR wchLogFile = L"Logs/APTLog.log";
	HANDLE hFile;
	hFile = CreateFileW(wchLogFile, GENERIC_WRITE, 0, 0, CREATE_NEW, 0, 0);
	DWORD dwByteNeeded = wcslen(wchLogBuffer);
	WriteFileEx(hFile, wchLogBuffer, dwByteNeeded, 0, 0);
	DWORD dwErrorCode = GetLastError();
	printf("[ERROR] Error code %d\n", dwErrorCode);
	CloseHandle(hFile);
}


