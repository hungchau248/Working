#include "stdafx.h"

#pragma comment (lib, "Ws2_32.lib")

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "DataTypes.h"
#include "ProcessData.h"

#define SOCK_BUFLEN 512
#define INFO_BUFLEN 32767
#define MACHINE_BUFLEN 512

DWORD LittleToBig(DWORD in) {
	return (in << 8 | in >> 8) & 0xffff;
}

DWORD WINAPI SendLogToServer(PCHAR pServerIP, DWORD dwPort, DWORD dwLogType) {

	// === GETTING LOCAL SYSTEM INFORMATION === //
	DWORD dwErrorCode, 
		dwByteRead,
		dwResult;

	static PCHAR pComputerName = NULL, 
		pWindowsVersion;

	//Open System Infomatin File
	LPCSTR pInfoFile = "Config/System.info";
	HANDLE hInfoFile = CreateFileA(pInfoFile, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	dwErrorCode = GetLastError();

	//If file does not exist
	if (dwErrorCode == ERROR_FILE_NOT_FOUND) {
		_tprintf(L"Cannot open System Information file: ERROR_FILE_NOT_FOUND !\n");
		return 1;
	}

	//Read from Info File
	PCHAR pInfoBuffer = (PCHAR)calloc(MAX_BUFFER_LEN, sizeof(CHAR));
	dwResult = ReadFile(hInfoFile, pInfoBuffer, MAX_BUFFER_LEN, &dwByteRead, NULL);

	//Close File Handle
	CloseHandle(hInfoFile);

	// Check weather Config File contains NULL
	if (dwByteRead == 0) {
		_tprintf(L"System Information file contains NULL !\n");
		return 1;
	}


	// Getting Computer Name 
	pComputerName = ParseData(pInfoBuffer, "<ComputerName>");
	if (pComputerName == NULL) {
		printf("Computer Name was not set\n");
		return 1;
	}


	// Getting Windows Version

	pWindowsVersion = ParseData(pInfoBuffer, "<WindowsVersion>");
	if (pWindowsVersion == NULL) {
		printf("Windows Version was not set\n");
		return 1;
	}

	// CONNECTING TO SERVER FOR SENDING LOG
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct sockaddr_in sock;
	DWORD iResult = 0;

	printf("Creating Startup Connection! \n");

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("Winsock startup failed: %d\n", iResult);
		return 1;
	}

	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error in creating socket: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	sock.sin_family = AF_INET;
	sock.sin_port = LittleToBig(dwPort);
	sock.sin_addr.s_addr = inet_addr(pServerIP);

	iResult = connect(ConnectSocket, (SOCKADDR*)&sock, sizeof(sock));
	if (iResult != 0) {
		printf("Error connecting to %s:%d . With error code: %ld", pServerIP, dwPort, WSAGetLastError());
		WSACleanup();
		return 1;
	}

	printf("Connected to Server at [%s:%d]\n", pServerIP, dwPort);

	//Send ComputerName and WindowsVersion
	send(ConnectSocket, pComputerName, strlen(pComputerName), 0);
	Sleep(30);
	send(ConnectSocket, pWindowsVersion, strlen(pWindowsVersion), 0);

	//Receive a port to send log to
	PCHAR pBuf;


	pBuf = (PCHAR)calloc(SOCK_BUFLEN, 0);
	recv(ConnectSocket, pBuf, SOCK_BUFLEN, 0);
	dwPort = LittleToBig(atoi(pBuf));
	_tprintf(L"Receive Connection Port at: %d \n", dwPort);

	closesocket(ConnectSocket);
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error in creating socket: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	
	//Connect to that received port
	sock.sin_family = AF_INET;
	sock.sin_port = dwPort;
	sock.sin_addr.s_addr = inet_addr(pServerIP);

	iResult = connect(ConnectSocket, (SOCKADDR*)&sock, sizeof(sock));
	if (iResult != 0) {
		printf("Error connecting to %s:%d . With error code: %ld", pServerIP, dwPort, WSAGetLastError());
		WSACleanup();
		return 1;
	}

	printf("Connected to Server at [%s:%d] for Data Transfering \n", pServerIP, dwPort);

	//REad Tmp_Log File and send to Server

	HANDLE hRegFile = NULL,
		hSvcFile = NULL;
	DWORD dwRegByteRead = 0,
		dwSvcByteRead = 0;
	LPWSTR lpRegBuffer,
		lpSvcBuffer;

	PCHAR pRegBuffer = NULL,
		pSvcBuffer = NULL;
	DWORD dwByteNeeded = 0;

	lpRegBuffer = (LPWSTR)calloc(MAX_BUFFER_LEN, sizeof(LPWSTR));
	lpSvcBuffer = (LPWSTR)calloc(MAX_BUFFER_LEN, sizeof(LPWSTR));

	switch (dwLogType) {
	case LOG_TYPE_REGISTRY:
		hRegFile = CreateFileW(
			L"Logs/tmpRegistry.log", 
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			0, 
			NULL);
		dwErrorCode = GetLastError();
		if (dwErrorCode == ERROR_SUCCESS) {
			ReadFile(hRegFile, lpRegBuffer, MAX_BUFFER_LEN, &dwRegByteRead, 0);
			_tprintf(L"%s\n", lpRegBuffer);
		}
		CloseHandle(hRegFile);
		printf("Error Code: %d\n", dwErrorCode); // Debug

		//Start sending Log
		if (dwRegByteRead > 0) {
			dwByteNeeded = WideCharToMultiByte(
				CP_UTF8, 
				0, 
				lpRegBuffer, 
				-1, 
				pRegBuffer, 
				0, 
				NULL, 
				NULL);

			pRegBuffer = (LPSTR)calloc(dwByteNeeded, 1);
			WideCharToMultiByte(
				CP_UTF8, 
				0, 
				lpRegBuffer, 
				-1, 
				pRegBuffer, 
				dwByteNeeded, 
				NULL, 
				NULL);
			printf("Sending Registry Log to Server: %s \n", pRegBuffer);
			send(ConnectSocket, (LPSTR)pRegBuffer, dwByteNeeded, 0);
		}

		break;

	case LOG_TYPE_SERVICE:
		hSvcFile = CreateFileW(
			L"Logs/tmpService.log", 
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			0, 
			NULL);
		dwErrorCode = GetLastError();
		if (dwErrorCode == ERROR_SUCCESS) {
			ReadFile(hSvcFile, lpSvcBuffer, MAX_BUFFER_LEN, &dwSvcByteRead, 0);
			_tprintf(L"%s\n", lpSvcBuffer);
		}
		CloseHandle(hSvcFile);
		printf("Error Code: %d\n", dwErrorCode); // Debug

		//Start sending Log
		if (dwSvcByteRead > 0) {
			dwByteNeeded = WideCharToMultiByte(
				CP_UTF8, 
				0, 
				lpSvcBuffer, 
				-1, 
				pSvcBuffer, 
				0, 
				NULL, 
				NULL);
			pSvcBuffer = (LPSTR)calloc(dwByteNeeded, 1);
			WideCharToMultiByte(CP_UTF8, 
				0, 
				lpSvcBuffer, 
				-1, 
				pSvcBuffer, 
				dwByteNeeded, 
				NULL, 
				NULL);
			printf("%d\n", dwByteNeeded); //Debut
			printf("Sending Service Log to Server: %s \n", pSvcBuffer);
			send(ConnectSocket, (LPSTR)pSvcBuffer, dwByteNeeded, 0);
		}
	}
	
	_tprintf(L"Debug\n");

	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}


DWORD WINAPI Networking(DWORD dwLogType) {

	PCHAR pServerIP, pPort;
	PCHAR pStart, pEnd;
	DWORD dwPort;
	
	DWORD dwResult, dwByteRead;
	PCHAR pBuffer;
	DWORD dwErrorCode;

	// === GETTING CONFIGURATION FOR NETWORKING AND CONNECT TO SERVER ===
	//Open Configuration File for Network Connection
	LPCSTR pConfigFile = "Config/Networking.conf";
	HANDLE hConfigFile = CreateFileA(pConfigFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	dwErrorCode = GetLastError();

	//If file does not exist
	if (dwErrorCode == ERROR_FILE_NOT_FOUND) {
		_tprintf(L"Cannot open Network Configuration file: ERROR_FILE_NOT_FOUND !\n");
		return 1;
	}

	//Read from Config File
	pBuffer = (PCHAR)calloc(MAX_BUFFER_LEN, sizeof(CHAR));
	dwResult = ReadFile(hConfigFile, pBuffer, MAX_BUFFER_LEN, &dwByteRead, NULL);

	// Check weather Config File contains NULL
	if (dwByteRead == 0) {
		_tprintf(L"Networking Configuration file contains NULL !\n");
		return 1;
	}

	// Closing File Handle
	CloseHandle(hConfigFile);

	// Debug
	_tprintf(L"Configuration:\n");
	printf("%s", pBuffer);

	// Get Server IP
	pStart = strstr(pBuffer, "<Server>");

	if (pStart == NULL) {
		_tprintf(L"Server IP is not set !\n");
		return 1;
	}

	pStart += strlen("<Server>");
	pEnd = strstr(pStart, "</Server>");
	pServerIP = (PCHAR)calloc(size_t(pEnd - pStart), sizeof(CHAR));
	strncpy(pServerIP, pStart, size_t(pEnd - pStart));
	pServerIP[pEnd - pStart] = '\0';
	
	// Get Port
	pStart = strstr(pBuffer, "<Port>");

	if (pStart == NULL) {
		_tprintf(L"Server Port is not set !\n");
		return 1;
	}

	pStart += strlen("<Port>");
	pEnd = strstr(pStart, "</Port>");
	pPort = (PCHAR)calloc(size_t(pEnd - pStart), sizeof(CHAR));
	strncpy(pPort, pStart, size_t(pEnd - pStart));
	pPort[pEnd - pStart] = '\0';
	dwPort = atoi(pPort);
	

	//Connect to Server
	printf("Connecting to [%s:%d]\n", pServerIP, dwPort);
	SendLogToServer(pServerIP, dwPort, dwLogType);

	_tprintf(L"Finish Successfully ! \n");
}
