#include "stdafx.h"

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>


#include "RegQuery.h"
#include "DataTypes.h"
 
int WINAPI RegMonitor(LPVOID lpRegKey)
{
	PREGKEY pRegKey;
	pRegKey = (PREGKEY)lpRegKey;
	PCHAR achMainKey = (PCHAR) calloc(5,1);
	PCHAR achSubKey = (PCHAR) calloc(MAX_KEY_LEN, 1);
	snprintf(achMainKey, 5, "%s", pRegKey->stlpMainKey);
	snprintf(achSubKey, MAX_KEY_LEN, "%s", pRegKey->stlpKey);
	
   DWORD  dwFilter = REG_NOTIFY_CHANGE_NAME |
                     REG_NOTIFY_CHANGE_ATTRIBUTES |
                     REG_NOTIFY_CHANGE_LAST_SET |
                     REG_NOTIFY_CHANGE_SECURITY; 

   HANDLE hEvent;
   HKEY   hMainKey;
   HKEY   hKey;
   LONG   lErrorCode;

   // Convert parameters to appropriate handles.
   if (strcmp("HKLM", achMainKey) == 0) hMainKey=HKEY_LOCAL_MACHINE;
   else if(strcmp("HKU", achMainKey) == 0) hMainKey=HKEY_USERS;
   else if(strcmp("HKCU", achMainKey) == 0) hMainKey=HKEY_CURRENT_USER;
   else if(strcmp("HKCR", achMainKey) == 0) hMainKey=HKEY_CLASSES_ROOT;
   else if(strcmp("HCC", achMainKey) == 0) hMainKey=HKEY_CURRENT_CONFIG;
   else 
   	{
      printf("Usage: notify [HKLM|HKU|HKCU|HKCR|HCC] [<subkey>]\n");
      return 1;
   	}
   
    int nSubKeys = 0, nValues = 0;

	static LPWSTR lpLastSubkeyName = NULL,
		lpLastValueName = NULL;
	lpLastSubkeyName = (LPWSTR)calloc(255, sizeof(wchar_t));
	lpLastValueName = (LPWSTR)calloc(16383, sizeof(wchar_t));
   
   while(1){
		printf("\n===> Monitoring Key: %s\\%s\n",achMainKey, achSubKey);
		// Open a key.
		lErrorCode = RegOpenKeyExA(hMainKey, achSubKey, 0, KEY_NOTIFY|KEY_READ|KEY_QUERY_VALUE, &hKey);
		if (lErrorCode != ERROR_SUCCESS)
		{
			printf("Error in RegOpenKeyEx (%d).\n", lErrorCode);
			return 1;
		}
		// Variable for storing last Subkey and Value in chain
		memset(lpLastSubkeyName, 0, 255);
		memset(lpLastValueName, 0, 16383);

		//Snapshot Registry Before Change
		RegQuery(hKey, &nSubKeys, &nValues, FALSE, achMainKey, achSubKey, lpLastSubkeyName, lpLastValueName);
		_tprintf(L"Last SubKey Debug: %s\n", lpLastSubkeyName); //Debug
		_tprintf(L"Last Value Debug: %s\n", lpLastValueName); //Debug

	    // Create an event.
	    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	    if (hEvent == NULL)
	    {
	      printf("Error in CreateEvent (%d).\n", GetLastError());
	      return 1;
	    }
	
	   // Watch the registry key for a change of value.
	   lErrorCode = RegNotifyChangeKeyValue(hKey, 
	                                        TRUE, 
	                                        dwFilter, 
	                                        hEvent, 
	                                        TRUE);
	   if (lErrorCode != ERROR_SUCCESS)
	   {
	      printf("Error in RegNotifyChangeKeyValue (%d).\n", lErrorCode);
	      return 1;
	   }
	
	   // Wait for an event to occur.
		printf("Waiting for a change in the specified key...\n");
		if (WaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
		{
		    printf("Error in WaitForSingleObject (%d).\n", GetLastError());
		    return 1;
		}
		else printf("\nChange has occurred.\n");
		
		//Snapshot Registry After Change
		RegQuery(hKey, &nSubKeys, &nValues, TRUE, achMainKey, achSubKey, lpLastSubkeyName, lpLastValueName);
	
	   // Close the key.
	   lErrorCode = RegCloseKey(hKey);
	   if (lErrorCode != ERROR_SUCCESS)
	   {
	      printf("Error in RegCloseKey (%d).\n", GetLastError());
	      return 1;
	   }
	   
	   // Close the handle.
	   if (!CloseHandle(hEvent))
	   {
	      printf("Error in CloseHandle.\n");
	      return 1;
	   }

	}
   
   return 0;
}

 DWORD WINAPI RegMon(){
	LPCSTR szRegConfig = "Config/RegConfig.conf";
	HANDLE hFile = CreateFileA(szRegConfig, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
	DWORD dwErrorCode = GetLastError();
	if(dwErrorCode == ERROR_FILE_NOT_FOUND){
		printf("Cannot open Registry Configuration file: ERROR_FILE_NOT_FOUND !\n");
		return 1;
	}
	DWORD dwResult, dwByteRead;
	PCHAR lpBuffer = (PCHAR) calloc(MAX_BUFFER_LEN, 1);
	dwResult = ReadFile(hFile, lpBuffer, MAX_BUFFER_LEN, &dwByteRead, NULL);
	if(dwByteRead == 0){
		printf("Registry Configuration file contains NULL !\n");
		return 1;
	}
	
	//printf("Data: %s\n",lpBuffer);
	
	PREGKEY pRegKey[MAX_REG_THREADS];
	DWORD dwThreadIdArray[MAX_REG_THREADS];
	HANDLE hThreadArray[MAX_REG_THREADS];
	DWORD iThread = 0;
 	
	while(true){
		
		pRegKey[iThread] = (PREGKEY) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(REGKEY));
		if(pRegKey[iThread] == NULL){
			ExitProcess(1);
		}
		
		if(strstr(lpBuffer, "#") != NULL){
			lpBuffer = (PCHAR)strstr(lpBuffer, "\n") + strlen("\n");
		}
		PCHAR lpKeyStart =  (PCHAR)strstr((LPCSTR)lpBuffer, "<Key>");
		PCHAR lpKeyEnd =  (PCHAR)strstr(lpBuffer, "</Key>"); 
		if(lpKeyStart == NULL | lpKeyEnd == NULL){
			break;
		}
		lpKeyStart += strlen("<Key>");
		
		pRegKey[iThread]->stlpKey = (PCHAR) calloc(MAX_KEY_LEN, 1);
		PCHAR lpKey = (PCHAR) calloc(MAX_KEY_LEN, 1);
		
		strncpy((char *) lpKey, lpKeyStart, (size_t)(lpKeyEnd - lpKeyStart));
		printf("Key: %s \n", lpKey);
		lpBuffer = (char *)lpKeyEnd + strlen("</Key>");
		
		pRegKey[iThread]->stlpMainKey = (PCHAR) calloc(5,1);
		PCHAR lpMainKey = (PCHAR) calloc(5,1);
		
		PCHAR lpTmp = (PCHAR)strstr( lpKey, "\\");
		
		strncpy(lpMainKey, lpKey, (size_t)(lpTmp - lpKey));
		lpKey = lpTmp + sizeof("\\");
		printf("Main Key: %s \n\n",lpMainKey);
		
		//Registry Monitor Threads
		
		strcpy(pRegKey[iThread]->stlpMainKey, lpMainKey);
		strcpy(pRegKey[iThread]->stlpKey, lpKey);
		
		hThreadArray[iThread] = CreateThread(
			NULL,
			0,
			(LPTHREAD_START_ROUTINE) RegMonitor,
			pRegKey[iThread],
			0,
			&dwThreadIdArray[iThread]
		);
		
		if(hThreadArray[iThread] == NULL){
			//ErrorHander(TEXT("CreateThread"));
			ExitProcess(1);
		}
		
		memset(lpKey, 0, sizeof(lpKey));
		memset(lpMainKey, 0, sizeof(lpMainKey));
		iThread++;
		Sleep(10);
	}
	
	WaitForMultipleObjects(iThread, hThreadArray, TRUE, INFINITE);
	
	for(int i = 0; i < iThread; i++){
		CloseHandle(hThreadArray[i]);
		if(pRegKey[i] != NULL){
			HeapFree(GetProcessHeap(), 0, pRegKey[i]);
			pRegKey[i] = NULL;
		}
	}
	
	return 0;
}
 
