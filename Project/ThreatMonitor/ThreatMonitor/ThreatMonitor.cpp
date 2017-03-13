// ThreatMonitor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// Include system header files
#include <windows.h>
#include <winevt.h>
#include <stdio.h>

// Include local header files
#include "SvcChangeNotify.h"
#include "RegMonitor.h"
#include "RegQuery.h"

#pragma comment (lib, "Wevtapi.lib")

#define MAX_THREADS 1

int main() {
	
	DWORD dwThreadIdArray[MAX_THREADS];
	HANDLE hThreadArray[MAX_THREADS];

	hThreadArray[0] = CreateThread(
	NULL,
	0,
	(LPTHREAD_START_ROUTINE)SvcChangeNotify,
	NULL,
	0,
	&dwThreadIdArray[0]
	);

	//SvcChangeNotify();
	Sleep(10);
	RegMon();
	int a;
	_tprintf(L"Enter any thing to exit: ");
	scanf("%d", &a);
	return 0;
}
