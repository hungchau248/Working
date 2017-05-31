#include "stdafx.h"

#include <iostream>
#include <ctime>
#include <windows.h>

#include "DataTypes.h"
#include "Networking.h"
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

DWORD WINAPI WriteLog(DWORD dwLogType, LPWSTR wchLogBuffer) {
	LPWSTR wchLogFile = NULL;
	LPWSTR wchLogTmpFile = NULL;
	HANDLE hFile;

	switch (dwLogType) {
		case LOG_TYPE_REGISTRY:
			wchLogFile = L"Logs/Registry.log";
			wchLogTmpFile = L"Logs/tmpRegistry.log";
			break;
		case LOG_TYPE_SERVICE:
			wchLogFile = L"Logs/Services.log";
			wchLogTmpFile = L"Logs/tmpService.Log";
			break;

	}
	//OPEN AND WRITE TO MAIN LOG FILE
	hFile = CreateFileW(wchLogFile, GENERIC_WRITE | FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
	DWORD dwErrorCode;
	dwErrorCode = GetLastError();


	// Write to end of file
	DWORD dwByteNeeded = _tcslen(wchLogBuffer);
	LPOVERLAPPED lpOverLapped = (LPOVERLAPPED)calloc(1, sizeof(OVERLAPPED));
	lpOverLapped->Offset = 0xffffffff;
	lpOverLapped->OffsetHigh = 0xffffffff;
	dwByteNeeded *= 2;
	WriteFile(hFile, (LPWSTR)wchLogBuffer, dwByteNeeded, NULL, lpOverLapped);
	CloseHandle(hFile);

	hFile = CreateFileW(wchLogTmpFile, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	WriteFile(hFile, (LPWSTR)wchLogBuffer, dwByteNeeded, NULL, 0);
	CloseHandle(hFile);
	//Write log to Server
	Networking(dwLogType);

	delete(lpOverLapped);
																	
	return 0;
}


