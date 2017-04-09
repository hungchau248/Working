#include "stdafx.h"

#include <iostream>
#include <ctime>
#include <windows.h>

using namespace std;

VOID getDateTime(PCHAR ret_timeBuffer = NULL, LPWSTR wRet_timeBuffer = NULL) {
	time_t rawtime;
	struct tm * timeinfo;
	char timeBuffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timeBuffer, sizeof(timeBuffer), "%d-%m-%Y %I:%M:%S", timeinfo);

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


