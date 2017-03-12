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

int main() {
	SvcChangeNotify();
	//RegMon();
	int a;
	_tprintf(L"Enter any thing to exit: ");
	scanf("%d", &a);
	return 0;
}
