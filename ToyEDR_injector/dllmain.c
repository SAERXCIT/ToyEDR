// dllmain.cpp : Defines the entry point for the DLL application.
#include "ToyEDR_injector.h"

#define INJECT_WITH_WINAPI

#ifdef INJECT_WITH_WINAPI

__declspec(dllexport) BOOL InjectDLL(HANDLE hRemoteProcess, LPCSTR szDllPath) {

    BOOL bSTATE = TRUE;
    PVOID pRemoteDllPath = NULL;
    SIZE_T stBytesWritten = 0;
    HANDLE hNewRemoteThread = NULL;
    int iDllPathLength = lstrlenA(szDllPath) + sizeof(CHAR);

    pRemoteDllPath = VirtualAllocEx(hRemoteProcess, NULL, iDllPathLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        printf("[-] Error allocating remote memory: %d\n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!WriteProcessMemory(hRemoteProcess, pRemoteDllPath, szDllPath, iDllPathLength, &stBytesWritten) || stBytesWritten != iDllPathLength) {
        printf("[-] Error writing DLL path to remote memory: %d\n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunc;
    }

    hNewRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(&LoadLibraryA), pRemoteDllPath, 0, NULL);
    if (!hNewRemoteThread) {
        printf("[-] Error creating LoadLibraryA remote thread: %d\n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunc;
    }

    WaitForSingleObject(hNewRemoteThread, INFINITE);

_EndOfFunc:
    if (pRemoteDllPath)
        VirtualFreeEx(hRemoteProcess, pRemoteDllPath, 0, MEM_RELEASE);
    if (hNewRemoteThread)
        CloseHandle(hNewRemoteThread);

    return bSTATE;

}

#endif


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

