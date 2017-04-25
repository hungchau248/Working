// ThreatMonitor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// Include system header files
#include <windows.h>
#include <winevt.h>
#include <stdio.h>

// Include local header files
#include "DataTypes.h"
#include "GetSystemInfo.h"
#include "SvcChangeNotify.h"
#include "RegMonitor.h"
#include "RegQuery.h"
#include "Logging.h"
#include "Networking.h"

#pragma comment (lib, "Wevtapi.lib")

#define MAX_THREADS 1
#define UNICODE_DEFAULT_STRINGS_LENGTH 512

int main() {

	GetSystemInfo();
	Sleep(500);

	PCHAR timeBuffer = (PCHAR) calloc(60,1);
	LPWSTR lpTimeBuffer = (LPWSTR)calloc(UNICODE_DEFAULT_STRINGS_LENGTH, sizeof(LPWSTR));
	getDateTime(timeBuffer, lpTimeBuffer);
	printf("Test Date Time : %s\n", timeBuffer);
	_tprintf(L"Test Date Time in Unicode: %s\n", lpTimeBuffer);


	//Calling Networking Function
	//Networking();

	//Current Running
	Sleep(500);
	DWORD dwThreadIdArray[MAX_THREADS];
	HANDLE hThreadArray[MAX_THREADS];

	hThreadArray[0] = CreateThread(
	NULL,
	0,
	(LPTHREAD_START_ROUTINE)RegMon,
	NULL,
	0,
	&dwThreadIdArray[0]
	);

	Sleep(500);
	//RegMon();
	SvcChangeNotify();
	int a;
	_tprintf(L"Enter any thing to exit: ");
	scanf("%d", &a);

	Sleep(10000);
	return 0;
}
