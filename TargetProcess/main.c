#include <Windows.h>
#include <stdio.h>

int main(int argc, char** argv) {

	STARTUPINFOA Si = { .cb = sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION Pi = { 0 };

	DWORD dwCurrentPid = GetCurrentProcessId();

	printf("[*] Process ID: %d\n", dwCurrentPid);

	printf("[*] Load DLL with injector, then press Enter...");
	getchar();

	printf("[*] Press enter to create a new process...");
	getchar();

	if (!CreateProcessA(NULL, "calc.exe", NULL, NULL, 0, 0, NULL, NULL, &Si, &Pi)) {
		printf("[-] Error creating a new process: %d\n", GetLastError());
		return -1;
	}

	printf("[+] New process created!\n");
	printf("[*] Press enter to allocate memory...");
	getchar();

	PVOID pTest = VirtualAlloc(NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pTest == NULL) {
		printf("[-] Error allocating memory: %d\n", GetLastError());
		return -1;
	}
	printf("[+] Memory allocated!\n");

	printf("[*] Press enter to exit...");
	getchar();

	if (pTest != NULL)
		VirtualFree(pTest, 0, MEM_RELEASE);

	CloseHandle(Pi.hProcess);
	CloseHandle(Pi.hThread);

	return 0;

}