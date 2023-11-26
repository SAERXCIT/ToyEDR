#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include "ToyEDR_injector.h"

#define TARGET_PROCESS_W L"TARGETPROCESS.EXE"

BOOL FindTargetProcessPid(PDWORD pdwPid) {

	int i = 0;
	BOOL bFOUND = FALSE;
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32W sctPE32 = { 0 };
	sctPE32.dwSize = sizeof(sctPE32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[-] Error in CreateToolhelp32Snapshot: %d\n", GetLastError());
		bFOUND = FALSE; goto _EndOfFunc;
	}

	if (!Process32FirstW(hProcessSnap, &sctPE32)) {
		printf("[-] Error in Process32FirstW: %d\n", GetLastError());
		bFOUND = FALSE; goto _EndOfFunc;
	}

	do {

		if (sctPE32.szExeFile && (lstrcmpiW(sctPE32.szExeFile, TARGET_PROCESS_W) == 0)) {
			*pdwPid = sctPE32.th32ProcessID;
			bFOUND = TRUE;
			break;
		}

	} while (Process32NextW(hProcessSnap, &sctPE32));


_EndOfFunc:
	if (hProcessSnap != NULL && hProcessSnap != INVALID_HANDLE_VALUE)
		CloseHandle(hProcessSnap);

	return bFOUND;

}

int main(int argc, char** argv) {

	int iRet = 0;
	DWORD dwTargetPid = 0;
	HANDLE hRemoteProcess = NULL;

	printf("[*] ToyEDR v 1.3.37\n");

	if (!FindTargetProcessPid(&dwTargetPid)) {
		printf("[-] Could not find TargetProcess.exe PID\n");
		iRet = -1; goto _EndOfFunc;
	}

	printf("[+] TargetProcess.exe PID: %d\n", dwTargetPid);
	printf("[*] Now opening a handle to the proces...\n");

	hRemoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwTargetPid);
	if (!hRemoteProcess) {
		printf("[-] Could not open handle to target process: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;
	}

	if(!InjectDLL(hRemoteProcess, HOOKS_DLL)) {
		printf("[-] Could not inject remote DLL\n");
		iRet = -1; goto _EndOfFunc;
	}

_EndOfFunc:
	if (hRemoteProcess)
		CloseHandle(hRemoteProcess);

	printf("Exiting with return code %d...\n", iRet);
	return iRet;

}