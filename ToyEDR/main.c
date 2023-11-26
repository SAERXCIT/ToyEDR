#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "ToyEDR_injector.h"

#define TARGET_PROCESS_W L"TARGETPROCESS.EXE"
#define NAMED_PIPE_NAME L"\\\\.\\pipe\\TOYEDR_COMM"
#define NAMED_PIPE_BUFSIZE MAXDWORD

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

BOOL InjectDLLInProcess(DWORD dwPid) {

	BOOL bSTATE = TRUE;
	HANDLE hRemoteProcess = NULL;

	hRemoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPid);
	if (!hRemoteProcess) {
		printf("[-] Could not open handle to target process: %d\n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	if (!InjectDLL(hRemoteProcess, HOOKS_DLL)) {
		printf("[-] Could not inject remote DLL\n");
		bSTATE = FALSE; goto _EndOfFunc;
	}

	printf("[+] Success injecting in process %d\n", dwPid);

_EndOfFunc:
	if (hRemoteProcess)
		CloseHandle(hRemoteProcess);

	return bSTATE;

}

BOOL InjectDLLThread(HANDLE hPipe) {

	BOOL bSTATE = TRUE;
	DWORD dwPid = 0;
	DWORD dwBytesRead = 0;

	if (!ReadFile(hPipe, &dwPid, sizeof(dwPid), &dwBytesRead, NULL) || dwBytesRead != sizeof(dwPid)) {
		printf("[-] Could not read PID from named pipe: %d", GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	CloseHandle(hPipe);

	printf("[+] New process pid: %d\n", dwPid);
	printf("[*] Injecting in process...\n");

	if (!InjectDLLInProcess(dwPid)) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

_EndOfFunc:

	return bSTATE;

}

int main(int argc, char** argv) {

	int iRet = 0;
	DWORD dwTargetPid = 0;
	HANDLE hPipe = NULL;
	HANDLE hClientThread = NULL;

	printf("[*] ToyEDR v 1.3.37\n");

	if (!FindTargetProcessPid(&dwTargetPid)) {
		printf("[-] Could not find TargetProcess.exe PID\n");
		iRet = -1; goto _EndOfFunc;
	}

	printf("[+] TargetProcess.exe PID: %d\n", dwTargetPid);

	if (!InjectDLLInProcess(dwTargetPid)) {
		iRet = -1; goto _EndOfFunc;
	}

	printf("[*] Now setting up main loop to listen for new processes\n");

	for (;;) {

		printf("[*] Creating new named pipe server handle\n");

		// TODO: Set ACL so pipe can be written to any process
		// Yes, it is **not a good idea** to allow any process to force the loading of a DLL into any other process,
		// but without a kernel-mode driver, this is what we have for now
		hPipe = CreateNamedPipeW(NAMED_PIPE_NAME, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			                     PIPE_UNLIMITED_INSTANCES, NAMED_PIPE_BUFSIZE, NAMED_PIPE_BUFSIZE, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("[-] Could not set up named pipe server: %d\n", GetLastError());
			break;
		}

		printf("[*] Waiting for connection...\n");

		if (ConnectNamedPipe(hPipe, NULL) || (GetLastError() == ERROR_PIPE_CONNECTED)) {

			printf("[*] New named pipe client connected\n");
			printf("[*] Creating new thread to deal with it...\n");

			hClientThread = CreateThread(NULL, NULL, InjectDLLThread, hPipe, 0, NULL);
			if (!hClientThread) {

				printf("[-] Could not create thread for DLL injection: %d\n", GetLastError());
				CloseHandle(hPipe);
				break;

			}

			printf("[+] New thread created!\n");
			CloseHandle(hClientThread);

		}
		else {

			printf("[-] Error in ConnectNamedPipe: %d\n", GetLastError());
			CloseHandle(hPipe);

		}

		printf("[*] Exiting this instance of loop\n");

	}

_EndOfFunc:

	printf("Exiting with return code %d...\n", iRet);
	return iRet;

}