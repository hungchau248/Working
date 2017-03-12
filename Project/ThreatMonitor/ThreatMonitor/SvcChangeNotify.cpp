
#include "stdafx.h"

#include <windows.h>
#include <winevt.h>
#include <ntstatus.h>

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
	EVT_SUBSCRIBE_NOTIFY_ACTION Action,
	PVOID UserContext,
	EVT_HANDLE Event
)
{
	return 0;
}

VOID CALLBACK NotifyCallback(
	IN PVOID pParameter
)
{
	PSERVICE_NOTIFYW notifyBuffer = (PSERVICE_NOTIFYW)pParameter;
	if (notifyBuffer->dwNotificationStatus == ERROR_SUCCESS) {
		_tprintf(L"System Services Modified !\n");

		switch (notifyBuffer->dwNotificationTriggered) {
		case SERVICE_NOTIFY_CREATED:
			_tprintf(L"Service Created: %s \n", notifyBuffer->pszServiceNames + (CHAR)1);
			break;

		case SERVICE_NOTIFY_DELETED:
			_tprintf(L"Service Deleted: %s \n", notifyBuffer->pszServiceNames);
			break;
		}
	}
	LocalFree(notifyBuffer->pszServiceNames);
	notifyBuffer->pContext = NULL;
}



int SvcChangeNotify(){

	EVT_HANDLE subscriptionHandle;
	SC_HANDLE scManagerHandle;
	HANDLE notifyEventHandle;
	SERVICE_NOTIFYW notifyBuffer;
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

	if (!subscriptionHandle) {
		return 1;
	}

	SECURITY_ATTRIBUTES secAttribute;
	secAttribute.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttribute.lpSecurityDescriptor = NULL;
	secAttribute.bInheritHandle = FALSE;

	notifyEventHandle = CreateEventEx(&secAttribute, NULL, CREATE_EVENT_INITIAL_SET, EVENT_ALL_ACCESS);

	if (notifyEventHandle == NULL){
		EvtClose(subscriptionHandle);
		return 1;
	}

	while (TRUE) {
		scManagerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
		
		if (scManagerHandle == NULL) {
			_tprintf(L"Cannot open SC Manager ! \n");
			return 1;
		}
		_tprintf(L"Monitoring System Service !\n");
		while (TRUE) {
			memset(&notifyBuffer, 0, sizeof(SERVICE_NOTIFYW));
			notifyBuffer.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
			notifyBuffer.pfnNotifyCallback = &NotifyCallback;
			notifyBuffer.pContext = notifyEventHandle;

			dwResult = NotifyServiceStatusChangeW(
							scManagerHandle, 
							SERVICE_NOTIFY_CREATED |
							SERVICE_NOTIFY_DELETED ,
							&notifyBuffer);

			if (dwResult == ERROR_SUCCESS) {
				// Wait for Notify Callback function
				WaitForSingleObjectEx(notifyBuffer.pContext, INFINITE, TRUE);

				
			}
			else if (dwResult == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING) {
				// Service lag
				_tprintf(L"Client Lagging !\n");
				break;
			}
			else {
				Sleep(5);
				break;
			}

		} //End while

		CloseServiceHandle(scManagerHandle);

	} //End while

	CloseHandle(notifyEventHandle);
	EvtClose(subscriptionHandle);

	return 0;
}
