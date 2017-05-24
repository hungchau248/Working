#include "stdafx.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Return XML type data with prefix
// If cbByteNeeded is 0, return 

PCHAR WINAPI ParseData(PCHAR pBuffer, CONST PCHAR pPrefix) {

	PCHAR pStart,
		pEnd,
		pSurfix,
		pData = NULL;

	pStart = (PCHAR)strstr(pBuffer, pPrefix);

	if(pStart != NULL){
		DWORD dwPrefixLen = strlen(pPrefix);
		pSurfix = (PCHAR)calloc(dwPrefixLen + 1, 1);
		strcpy(pSurfix, "</");
		strcat(pSurfix, pPrefix + 1);

		pStart += dwPrefixLen;
		pEnd = strstr(pStart, pSurfix);
		pData = (PCHAR)calloc(pEnd - pStart, 1);
		strncpy(pData, pStart, (size_t)(pEnd - pStart));
		pData[pEnd - pStart] = '\0';
	}

	return pData;
}