
#include "stdafx.h"

#include <windows.h>
#include <winevt.h>
#include <stdio.h>

void ErrorDescription(DWORD p_dwError) {

	HLOCAL hLocal = NULL;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, p_dwError, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPTSTR)&hLocal,
		0, NULL);

	MessageBox(NULL, (LPCTSTR)LocalLock(hLocal), TEXT("Error"), MB_OK | MB_ICONERROR);
	LocalFree(hLocal);
}

DWORD WINAPI SubscribeCallback(
	_In_ EVT_SUBSCRIBE_NOTIFY_ACTION Action,
	_In_ PVOID UserContext,
	_In_ EVT_HANDLE Event
)
{
	return 0;
}

VOID CALLBACK NotifyCallback(
	_In_ PVOID pParameter
)
{
	PSERVICE_NOTIFY notifyBuffer = (PSERVICE_NOTIFY)pParameter;
	if (notifyBuffer->dwNotificationStatus == ERROR_SUCCESS) {
		if (notifyBuffer->dwNotificationTriggered & SERVICE_NOTIFY_CREATED) {
			LocalFree(notifyBuffer->pszServiceNames);
		}
	}

	notifyBuffer->pContext = NULL;
}



int SvcChangeNotify() {

	EVT_HANDLE subscriptionHandle;
	SC_HANDLE scManageHandle;
	HANDLE notifyEventHandle;
	SERVICE_NOTIFY notifyBuffer;
	DWORD dwResult;

	subscriptionHandle = EvtSubscribe(
		NULL,
		NULL,
		L"System",
		L"*[System[Provider[@Name='Service Control Manager']]]",
		NULL,
		NULL,
		SubscribeCallback,
		EvtSubscribeToFutureEvents
	);

	return 0;
}
