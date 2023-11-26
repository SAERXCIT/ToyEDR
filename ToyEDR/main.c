#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "ToyEDR_injector.h"

#define TARGET_PROCESS_W L"TARGETPROCESS.EXE"
#define NAMED_PIPE_NAME L"\\\\.\\pipe\\TOYEDR_COMM"
#define NAMED_PIPE_BUFSIZE MAXDWORD


BOOL InjectDLLInProcess(DWORD dwPid) {

	BOOL bSTATE = TRUE;
	HANDLE hRemoteProcess = NULL;

	hRemoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPid);
	if (!hRemoteProcess) {
		printf("[- InjectDLLInProcess (%d)] Could not open handle to target process: %d\n", dwPid, GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	if (!InjectDLL(hRemoteProcess, HOOKS_DLL)) {
		printf("[- InjectDLLInProcess (%d)] Could not inject remote DLL\n", dwPid);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	printf("[+ InjectDLLInProcess (%d)] Success injecting in process\n", dwPid);

_EndOfFunc:
	if (hRemoteProcess)
		CloseHandle(hRemoteProcess);

	return bSTATE;

}

BOOL InjectDLLFromPipeThread(HANDLE hPipe) {

	BOOL bSTATE = TRUE;
	DWORD dwPid = 0;
	DWORD dwBytesRead = 0;

	if (!ReadFile(hPipe, &dwPid, sizeof(dwPid), &dwBytesRead, NULL) || dwBytesRead != sizeof(dwPid)) {
		printf("[- InjectDLLFromPipeThread] Could not read PID from named pipe: %d", GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	CloseHandle(hPipe);

	printf("[+ InjectDLLFromPipeThread] New process pid: %d\n", dwPid);
	printf("[* InjectDLLFromPipeThread] Injecting in process...\n");

	if (!InjectDLLInProcess(dwPid)) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

_EndOfFunc:

	return bSTATE;

}

BOOL NamedPipeThread() {

	HANDLE hPipe = NULL;
	HANDLE hClientThread = NULL;

	printf("[* NamedPipeThread] Setting up main loop to listen for new processes\n");

	for (;;) {

		printf("[* NamedPipeThread] Creating new named pipe server handle\n");

		// TODO: Set ACL so pipe can be written to any process
		// Yes, it is **not a good idea** to allow any process to force the loading of a DLL into any other process,
		// but without a kernel-mode driver, this is what we have for now
		hPipe = CreateNamedPipeW(NAMED_PIPE_NAME, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES, NAMED_PIPE_BUFSIZE, NAMED_PIPE_BUFSIZE, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("[- NamedPipeThread] Could not set up named pipe server: %d\n", GetLastError());
			break;
		}

		printf("[* NamedPipeThread] Waiting for connection...\n");

		if (ConnectNamedPipe(hPipe, NULL) || (GetLastError() == ERROR_PIPE_CONNECTED)) {

			printf("[* NamedPipeThread] New named pipe client connected\n");
			printf("[* NamedPipeThread] Creating new thread to deal with it...\n");

			hClientThread = CreateThread(NULL, 0, InjectDLLFromPipeThread, hPipe, 0, NULL);
			if (!hClientThread) {

				printf("[- NamedPipeThread] Could not create thread for DLL injection: %d\n", GetLastError());
				CloseHandle(hPipe);
				break;

			}

			printf("[+ NamedPipeThread] New thread created!\n");
			CloseHandle(hClientThread);

		}
		else {

			printf("[- NamedPipeThread] Error in ConnectNamedPipe: %d\n", GetLastError());
			CloseHandle(hPipe);

		}

		printf("[* NamedPipeThread] Exiting this instance of loop\n");

	}

}

BOOL InjectInAllProcessesThread() {

	DWORD i = 0;
	BOOL bSTATE = TRUE;
	DWORD dwThreadCount = 0;
	PHANDLE phThreadHandles = NULL;
	HANDLE hProcessSnap = NULL;
	HANDLE hTempHandle = NULL;
	PROCESSENTRY32W sctPE32 = { 0 };
	sctPE32.dwSize = sizeof(sctPE32);

	printf("[* InjectInAllProcessesThread] Starting thread InjectInAllProcessesThread\n");
	printf("[* InjectInAllProcessesThread] Running CreateToolhelp32Snapshot\n");

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[- InjectInAllProcessesThread] Error in CreateToolhelp32Snapshot: %d\n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	if (!Process32FirstW(hProcessSnap, &sctPE32)) {
		printf("[- InjectInAllProcessesThread] Error in Process32FirstW: %d\n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunc;
	}

	phThreadHandles = LocalAlloc(LPTR, sizeof(HANDLE));

	printf("[* InjectInAllProcessesThread] Entering process loop\n");

	do {

		printf("[* InjectInAllProcessesThread] Creating DLL injection thread for PID %d\n", sctPE32.th32ProcessID);

		hTempHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectDLLInProcess, sctPE32.th32ProcessID, 0, NULL);
		if (hTempHandle) {

			if (phThreadHandles == NULL)
				phThreadHandles = LocalAlloc(LPTR, sizeof(HANDLE));
			else
				phThreadHandles = LocalReAlloc(phThreadHandles, (dwThreadCount + 1) * sizeof(HANDLE), LMEM_MOVEABLE | LMEM_ZEROINIT);

			phThreadHandles[dwThreadCount] = hTempHandle;
			dwThreadCount++;

		}

	} while (Process32NextW(hProcessSnap, &sctPE32));

	printf("[* InjectInAllProcessesThread] Exiting process loop\n");

	WaitForMultipleObjects(dwThreadCount, phThreadHandles, TRUE, INFINITE);

	printf("[* InjectInAllProcessesThread] All DLL injection threads finished, exiting thread\n");

_EndOfFunc:
	for (i = 0; i < dwThreadCount; i++)
		CloseHandle(phThreadHandles[i]);
	if (hProcessSnap != NULL && hProcessSnap != INVALID_HANDLE_VALUE)
		CloseHandle(hProcessSnap);
	if (phThreadHandles)
		LocalFree(phThreadHandles);

	return bSTATE;

}

int main(int argc, char** argv) {

	int iRet = 0;
	DWORD dwTargetPid = 0;
	HANDLE hThreads[2] = { 0 };

	printf("[* main] ToyEDR v 1.3.37\n");


	printf("[* main] Staring named pipe thread\n");
	hThreads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NamedPipeThread, NULL, 0, NULL);
	if (hThreads[0] == NULL) {
		printf("[- main] Could not create named pipe thread: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;
	}
	printf("[+ main] Named pipe thread started\n");


	printf("[* main] Staring process injection thread\n");
	hThreads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectInAllProcessesThread, NULL, 0, NULL);
	if (hThreads[1] == NULL) {
		printf("[- main] Could not create process injection thread: %d\n", GetLastError());
		iRet = -1; goto _EndOfFunc;
	}
	printf("[+ main] Process injection thread started\n");


	WaitForMultipleObjects(2, hThreads, TRUE, INFINITE);

_EndOfFunc:
	if (hThreads[0])
		CloseHandle(hThreads[0]);
	if (hThreads[1])
		CloseHandle(hThreads[1]);

	printf("[* main] Exiting with return code %d...\n", iRet);
	return iRet;

}