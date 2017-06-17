# include "stdafx.h"

#include <windows.h>

#include "DataTypes.h"
#include <VersionHelpers.h>

#define MACHINE_BUFLEN 512

DWORD WINAPI GetSystemInfo() {

	PCHAR pComputerName;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwNameSize;

	// Get Computer Name
	pComputerName = (PCHAR)calloc(MACHINE_BUFLEN, sizeof(CHAR));
	dwNameSize = MACHINE_BUFLEN;
	GetComputerNameA(pComputerName, &dwNameSize);

	// Get Windows Version
	//DWORD dwVersion = GetVersion();
	//dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	//dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	GetProductInfo(dwMajorVersion, dwMinorVersion, NULL, NULL, NULL);

	if (IsWindows10OrGreater) {
		dwMajorVersion = 10;
		dwMinorVersion = 0;
	}
	else if (IsWindows8Point1OrGreater) {
		dwMinorVersion = 3;
	}


	// Open System Infomation file for writing Information
	LPCSTR pInfoFile = "Config/System.info";
	HANDLE hInfoFile = CreateFileA(pInfoFile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0,0);

	// Writing Information to System.info 
	// Write Comment
	PCHAR pBuffer = (PCHAR) calloc(MAX_BUF_LEN, 1);
	strcpy(pBuffer,
		"## This is System Information File\n"\
		"## You can Modify it and save with ASCII or UTF8 encoding\n\n");
	DWORD cbByteWritten;
	
	WriteFile(hInfoFile, pBuffer, strlen(pBuffer), &cbByteWritten, 0);
	memset(pBuffer, 0, strlen(pBuffer));

	// Write Computer Name
	sprintf(pBuffer, "<ComputerName>%s</ComputerName>\n", pComputerName);
	WriteFile(hInfoFile, pBuffer, strlen(pBuffer), &cbByteWritten, 0);
	memset(pBuffer, 0, strlen(pBuffer));

	//Write Windows Version
	sprintf(pBuffer, "<WindowsVersion>%d.%d</WindowsVersion>\n", dwMajorVersion, dwMinorVersion);
	WriteFile(hInfoFile, pBuffer, strlen(pBuffer), &cbByteWritten, 0);
	memset(pBuffer, 0, strlen(pBuffer));

	CloseHandle(hInfoFile);

	return 0;
}
