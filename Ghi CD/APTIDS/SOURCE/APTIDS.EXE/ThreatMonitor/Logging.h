#pragma once
#ifndef LOGGING_H
#define LOGGING_H
DWORD WINAPI WriteLog(DWORD dwLogType, LPWSTR wchLogBuffer);
VOID WINAPI getDateTime(PCHAR ret_timeBuffer = NULL, LPWSTR wRet_timeBuffer = NULL);
#endif