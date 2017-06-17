
#include "stdafx.h"

#include <windows.h>
#include <winevt.h>
#include <ntstatus.h>

#include <stdio.h>

#include "DataTypes.h"
#include "Logging.h"

typedef struct CALLBACK_CONTEXT {
	HANDLE hNotifyEventHandler;
	LPWSTR wchLogBuffer;

};


VOID WINAPI ErrorDescription(DWORD p_dwError) {

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

	LPWSTR wchLogBuffer,
		wchTime;
	PSERVICE_NOTIFYW notifyBuffer = (PSERVICE_NOTIFYW)pParameter;

	struct CALLBACK_CONTEXT* pstCallbackContext 
		= (struct CALLBACK_CONTEXT *) notifyBuffer->pContext;

	wchLogBuffer = (LPWSTR) calloc (MAX_BUFFER_LEN, 1);
	wchTime = (LPWSTR)calloc(MAX_BUFFER_LEN, 1);

	getDateTime(NULL, wchTime);

	wcscat(wchLogBuffer, wchTime);
	wcscat(wchLogBuffer, L"[SERVICE] ");
	wcscat(wchLogBuffer, L"[ALERT] ");

	if (notifyBuffer->dwNotificationStatus == ERROR_SUCCESS) {
		_tprintf(L"System Services Modified !\n");

		switch (notifyBuffer->dwNotificationTriggered) {
		case SERVICE_NOTIFY_CREATED:
			wcscat(wchLogBuffer, L"Service Created: ");
			wcscat(wchLogBuffer, notifyBuffer->pszServiceNames + (CHAR)1);
			wcscat(wchLogBuffer, L"\n\0");
			WriteLog(LOG_TYPE_SERVICE, wchLogBuffer);
			_tprintf(L"%s", wchLogBuffer);
			break;

		case SERVICE_NOTIFY_DELETED:
			wcscat(wchLogBuffer, L"Service Deleted: ");
			wcscat(wchLogBuffer, notifyBuffer->pszServiceNames);
			wcscat(wchLogBuffer, L"\n\0");
			WriteLog(LOG_TYPE_SERVICE, wchLogBuffer);
			_tprintf(L"%s", wchLogBuffer);

			break;
		}
	}
	LocalFree(notifyBuffer->pszServiceNames);
	notifyBuffer->pContext = NULL;
	wcscpy(pstCallbackContext->wchLogBuffer, wchLogBuffer);
}

DWORD WINAPI SvcChangeNotify(){

	EVT_HANDLE subscriptionHandle;
	SC_HANDLE scManagerHandle;
	HANDLE notifyEventHandle;
	SERVICE_NOTIFYW notifyBuffer;
	DWORD dwResult;

	HANDLE hHeap;

	SECURITY_ATTRIBUTES secAttribute;
	hHeap = HeapCreate(0, sizeof(struct CALLBACK_CONTEXT), 0);
	struct CALLBACK_CONTEXT * pstCallbackContext 
		= (struct CALLBACK_CONTEXT*) HeapAlloc(hHeap, 
			0, 
			sizeof(struct CALLBACK_CONTEXT));

	pstCallbackContext->wchLogBuffer = (LPWSTR)calloc(MAX_BUFFER_LEN, 1);

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

	secAttribute.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttribute.lpSecurityDescriptor = NULL;
	secAttribute.bInheritHandle = FALSE;

	notifyEventHandle 
		= CreateEventEx(&secAttribute, 
			NULL, 
			CREATE_EVENT_INITIAL_SET, 
			EVENT_ALL_ACCESS
		);

	if (notifyEventHandle == NULL){
		EvtClose(subscriptionHandle);
		return 1;
	}

	pstCallbackContext->hNotifyEventHandler = notifyEventHandle;

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
			notifyBuffer.pContext = (struct CALLBACK_CONTEXT*) pstCallbackContext;

			dwResult = NotifyServiceStatusChangeW(
					scManagerHandle, 
					SERVICE_NOTIFY_CREATED |
					SERVICE_NOTIFY_DELETED ,
					&notifyBuffer);

			if (dwResult == ERROR_SUCCESS) {
				// Wait for Notify Callback function
				WaitForSingleObjectEx(pstCallbackContext->hNotifyEventHandler, INFINITE, TRUE);
					
			}
			else if (dwResult == ERROR_SERVICE_NOTIFY_CLIENT_LAGGING) {
				// In case SCM lags
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

	CloseHandle(pstCallbackContext->hNotifyEventHandler);
	EvtClose(subscriptionHandle);

	return 0;
}

