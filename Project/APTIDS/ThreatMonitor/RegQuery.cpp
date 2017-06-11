
#include "stdafx.h"

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_LEN 16383

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include "DataTypes.h"
#include "Logging.h"

void WINAPI RegDataType(DWORD cbValueType, char* lpValueType){
	switch(cbValueType){
		case REG_BINARY:
			strcpy(lpValueType, "REG_BINARY"); 					return;
		case REG_DWORD:
			strcpy(lpValueType, "REG_DWORD"); 					return;
		case REG_DWORD_BIG_ENDIAN:
			strcpy(lpValueType, "REG_DWORD_BIG_ENDIAN"); 		return;
		case REG_EXPAND_SZ:
			strcpy(lpValueType, "REG_EXPAND_SZ"); 				return;
		case REG_LINK:
			strcpy(lpValueType, "REG_LINK");					return;
		case REG_MULTI_SZ:
			strcpy(lpValueType, "REG_MULTI_SZ"); 				return;
		case REG_NONE:
			strcpy(lpValueType, "REG_NONE"); 					return;
		case REG_QWORD:
			strcpy(lpValueType, "REG_QWORD"); 					return;
		case REG_SZ:
			strcpy(lpValueType, "REG_SZ"); 						return;
	}
}


int WINAPI RegQuery(HKEY hKey, 
	int *nSubKeys, 
	int *nValues, 
	bool aft, 
	const char *achMainKey, 
	const char *achSubKey, 
	LPWSTR lpLastSubkeyName, 
	LPWSTR lpLastValueName)
{ 
	//printf("Running Enum Key\n");
	
    TCHAR	 achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = L"";  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    TCHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 
    // Enumerate the subkeys, until RegEnumKeyEx fails.

	printf("MAIN KEY: %s\n", achMainKey);
	printf("SUB KEY: %s\n", achSubKey);

	PCHAR chKey = (PCHAR)calloc(MAX_BUFFER_LEN,1);
	strcpy(chKey, achMainKey);
	strcat(chKey, "\\\\");
	strcat(chKey, achSubKey);

	LPWSTR wchLogKey = (LPWSTR)calloc(MAX_BUFFER_LEN, sizeof(TCHAR));
	MultiByteToWideChar(CP_UTF8, 0, chKey, -1, wchLogKey, strlen(chKey));

	LPWSTR wchLogBuffer = (LPWSTR)calloc(MAX_BUFFER_LEN, sizeof(TCHAR));
	LPWSTR wchTime = (LPWSTR)calloc(MAX_BUFFER_LEN, sizeof(TCHAR));

	// Return 0 in case of delete
	if (aft && (*nSubKeys > cSubKeys)) {
		return 0;
	}
    
    if (cSubKeys > 0)
    {
		_tprintf(TEXT("\nNumber of subkeys: %d\n"), cSubKeys);

    	int nCount = 0;
        
		if(aft && (*nSubKeys < cSubKeys)){
			nCount = (cSubKeys - *nSubKeys);
		
		}

		
        for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey,	// the current querying subkey name
                     &cbName,	// size of subkey name
                     NULL, 
                     NULL, 
                     NULL, 
                     &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {
                _tprintf(TEXT("(%d) %s\n"), i+1, achKey);
				if ((cSubKeys - 1 == i) && !aft && !i) {
					wcscpy(lpLastSubkeyName, achKey);
				}
				

                if((cSubKeys - 1 == i) && aft && (nCount > 0)){
					getDateTime(NULL, wchTime);
					_tprintf(L"DEBUG TIME: %s\n", wchTime);
					wcscat(wchLogBuffer, wchTime);
					wcscat(wchLogBuffer, L"[REGISTRY] ");
					wcscat(wchLogBuffer, L"[ALERT] ");
					wcscat(wchLogBuffer, L"Key added: ");
					wcscat(wchLogBuffer, wchLogKey);
					wcscat(wchLogBuffer, L"\\\\");
					wcscat(wchLogBuffer, achKey);
					wcscat(wchLogBuffer, L"\n\0");
					WriteLog(LOG_TYPE_REGISTRY, wchLogBuffer);
					_tprintf(L"%s", wchLogBuffer);
					memset(wchLogBuffer, 0, sizeof(wchLogBuffer));
					return 0;
				}
				else if ((cSubKeys - 1 == i) && aft && (nCount == 0) && (cSubKeys > 0)) {
					//If the name of the subkey in the last position is different
					//from the previous query
					if (wcscmp(lpLastSubkeyName, achKey)) {
						getDateTime(NULL, wchTime);
						_tprintf(L"DEBUG TIME: %s\n", wchTime);
						wcscat(wchLogBuffer, wchTime);
						wcscat(wchLogBuffer, L"[REGISTRY] ");
						wcscat(wchLogBuffer, L"[ALERT] ");
						wcscat(wchLogBuffer, L"Key modified: ");
						wcscat(wchLogBuffer, wchLogKey);
						wcscat(wchLogBuffer, L"\\\\");
						wcscat(wchLogBuffer, achKey);
						wcscat(wchLogBuffer, L"\n\0");
						WriteLog(LOG_TYPE_REGISTRY, wchLogBuffer);
						_tprintf(L"%s", wchLogBuffer);
						memset(wchLogBuffer, 0, sizeof(wchLogBuffer));
						return 0;
					}
				}
            }
        }
    } 

 	if(!aft)	
		*nSubKeys = cSubKeys;

	if (aft && (*nValues > cValues)) {
		return 0;
	}

    // Enumerate the key values. 
    if (cValues) 
    {
    	BYTE lpValueData[MAX_VALUE_LEN];
		DWORD cbValueData = MAX_VALUE_LEN;
    	DWORD cbValueType;
    	BYTE lpValueType[100]; 
    	
        printf( "\nNumber of values: %d\n\n", cValues);

		int nCount = 0;
        if((*nValues < cValues) && aft){
        	nCount = cValues - *nValues;
		}
        
        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
            retCode = RegEnumValue(hKey, i, 
                achValue,  // the return value name
                &cchValue, // value name's size
                NULL, 
                NULL,
                NULL,
                NULL);
 
            if (retCode == ERROR_SUCCESS) 
            { // listing value for monitor and debug
                memset(lpValueData, 0, MAX_VALUE_LEN);
				retCode = RegQueryValueEx(hKey, achValue, NULL, &cbValueType, lpValueData, &cbValueData);
				if (retCode == ERROR_SUCCESS){
					RegDataType(cbValueType, (char*)lpValueType);
					_tprintf(L"[%d]-Value Name: %s\n", i+1, achValue);
					printf("|-Value Type: %s\n", lpValueType);
					_tprintf(L"|-Value Data: %s\n", lpValueData);
					_tprintf(L"\n");

					if ((cValues - 1 == i) && !aft ) {
						wcscpy(lpLastValueName, achValue);
						_tprintf(L"Last Value: %s\n", lpLastValueName);
					}

					if((cValues - 1 == i) && aft && (cValues > *nValues)){
						getDateTime(NULL, wchTime);
						wcscpy(wchLogBuffer, wchTime);
						wcscat(wchLogBuffer, L"[ALERT] ");
						wcscat(wchLogBuffer, L"[REGISTRY] ");
						wcscat(wchLogBuffer, L" New value added at Key: ");
						wcscat(wchLogBuffer, wchLogKey);
						wcscat(wchLogBuffer, L"  -->Value Name added : ");
						wcscat(wchLogBuffer, achValue);
						wcscat(wchLogBuffer, L"  -->Value Data: ");
						wcscat(wchLogBuffer, (LPWSTR)lpValueData);
						wcscat(wchLogBuffer, L"\n\0");
						WriteLog(LOG_TYPE_REGISTRY, wchLogBuffer);
						_tprintf(L"%s", wchLogBuffer);
						memset(wchLogBuffer, 0, sizeof(wchLogBuffer));
					}
					else if((cValues - 1 == i) && aft && (*nValues == cValues) ){
						_tprintf(L"Last Value: %s\n", lpLastValueName);
						if (wcscmp(lpLastValueName, achValue)) {
							getDateTime(NULL, wchTime);
							wcscpy(wchLogBuffer, wchTime);
							wcscat(wchLogBuffer, L"[ALERT] ");
							wcscat(wchLogBuffer, L"[REGISTRY] ");
							wcscat(wchLogBuffer, L" New value modified at Key: ");
							wcscat(wchLogBuffer, wchLogKey);
							wcscat(wchLogBuffer, L"  -->Value Name: ");
							wcscat(wchLogBuffer, achValue);
							wcscat(wchLogBuffer, L"  -->Value Data: ");
							wcscat(wchLogBuffer, (LPWSTR)lpValueData);
							wcscat(wchLogBuffer, L"\n\0");
							WriteLog(LOG_TYPE_REGISTRY, wchLogBuffer);
							_tprintf(L"%s", wchLogBuffer);
							memset(wchLogBuffer, 0, sizeof(wchLogBuffer));
						}
					}
				}
            } 
        }
    }

	if(!aft)	
		*nValues = cValues;

    return 0;
}