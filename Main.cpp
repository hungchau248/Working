#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "RegMonitor.h"
//#include "RegQuery.h"

void *MonitorRegistry(void* vargp){
	const char * achMainKey[2] = {"HKLM", "HKCU"};
	const char * achSubKey[4] = {
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"	
	};
	int* iKey = (int*)vargp;
	
	RegMonitor(achMainKey[*iKey/4], achSubKey[*iKey%4]);
}

int main(){
	
	pthread_t tid[6];
	int i;
	for(i = 0; i < 5; ++i){
		sleep(1);
		pthread_create(&tid[i], NULL, MonitorRegistry, (void*)&i );
	}	
	pthread_join(tid[0],NULL);
	return 0;
}
