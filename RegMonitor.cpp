#define MAX_BUF_LEN 65532

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "RegQuery.h"
 
int RegMonitor(const char* achMainKey, const char* achSubKey)
{
   DWORD  dwFilter = REG_NOTIFY_CHANGE_NAME |
                     REG_NOTIFY_CHANGE_ATTRIBUTES |
                     REG_NOTIFY_CHANGE_LAST_SET |
                     REG_NOTIFY_CHANGE_SECURITY; 

   HANDLE hEvent;
   HKEY   hMainKey;
   HKEY   hKey;
   LONG   lErrorCode;

   // Convert parameters to appropriate handles.
   if (_tcscmp(TEXT("HKLM"), achMainKey) == 0) hMainKey=HKEY_LOCAL_MACHINE;
   else if(_tcscmp(TEXT("HKU"), achMainKey) == 0) hMainKey=HKEY_USERS;
   else if(_tcscmp(TEXT("HKCU"), achMainKey) == 0) hMainKey=HKEY_CURRENT_USER;
   else if(_tcscmp(TEXT("HKCR"), achMainKey) == 0) hMainKey=HKEY_CLASSES_ROOT;
   else if(_tcscmp(TEXT("HCC"), achMainKey) == 0) hMainKey=HKEY_CURRENT_CONFIG;
   else 
   	{
      _tprintf(TEXT("Usage: notify [HKLM|HKU|HKCU|HKCR|HCC] [<subkey>]\n"));
      return 1;
   	}
   
    int nSubKeys = 0, nValues = 0;
   
   while(1){
   	_tprintf(TEXT("\n===> Monitoring Key: %s\\%s\n"),achMainKey, achSubKey);
   // Open a key.
    lErrorCode = RegOpenKeyEx(hMainKey, achSubKey, 0, KEY_NOTIFY|KEY_READ|KEY_QUERY_VALUE, &hKey);
   if (lErrorCode != ERROR_SUCCESS)
   {
      _tprintf(TEXT("Error in RegOpenKeyEx (%d).\n"), lErrorCode);
      return 1;
   }
   
    //Snapshot Registry Before Change
	RegQuery(hKey, &nSubKeys, &nValues, FALSE, achMainKey, achSubKey);
	
    // Create an event.
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL)
    {
      _tprintf(TEXT("Error in CreateEvent (%d).\n"), GetLastError());
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
      _tprintf(TEXT("Error in RegNotifyChangeKeyValue (%d).\n"), lErrorCode);
      return 1;
   }

   // Wait for an event to occur.
	_tprintf(TEXT("Waiting for a change in the specified key...\n"));
	if (WaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
	{
	    _tprintf(TEXT("Error in WaitForSingleObject (%d).\n"), GetLastError());
	    return 1;
	}
	else _tprintf(TEXT("\nChange has occurred.\n"));
	
	//Snapshot Registry After Change
	RegQuery(hKey, &nSubKeys, &nValues, TRUE, achMainKey, achSubKey);

   // Close the key.
   lErrorCode = RegCloseKey(hKey);
   if (lErrorCode != ERROR_SUCCESS)
   {
      _tprintf(TEXT("Error in RegCloseKey (%d).\n"), GetLastError());
      return 1;
   }
   
   // Close the handle.
   if (!CloseHandle(hEvent))
   {
      _tprintf(TEXT("Error in CloseHandle.\n"));
      return 1;
   }
}
   
   return 0;
}
