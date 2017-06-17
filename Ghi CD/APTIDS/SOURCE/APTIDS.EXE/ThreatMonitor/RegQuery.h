#ifndef REQQUERY_H
#define REQQUERY_H
int WINAPI RegQuery(HKEY hKey,
	int *nSubKeys,
	int *nValues,
	bool aft,
	const char *achMainKey,
	const char *achSubKey,
	LPWSTR lpLastSubkeyName,
	LPWSTR lpLastValueName
);
#endif


