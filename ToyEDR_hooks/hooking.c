#include "hooking.h"


BOOL InstallHook(PNTAPI_HOOK psctFunctionHook) {

	DWORD dwOldProtect = 0;
	
#ifdef _WIN64
	BYTE uTrampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
		0x41, 0xFF, 0xE2                                            // jmp r10
	};
#else
	BYTE uTrampoline[] = {
	   0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
	   0xFF, 0xE0                        // jmp eax
};
#endif

	memcpy(&(uTrampoline[PATCH_OFFSET]), &(psctFunctionHook->pJumpDestination), sizeof(PVOID));

	if (!VirtualProtect(psctFunctionHook->pOriginalFunctionAddress, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		printf("[-] Cannot change page protection to PAGE_EXECUTE_READWRITE: %d\n", GetLastError());
		return FALSE;
	}

	psctFunctionHook->dwOldProtection = dwOldProtect;
	memcpy(psctFunctionHook->pOriginalFunctionAddress, uTrampoline, TRAMPOLINE_SIZE);
	psctFunctionHook->bHookInstalled = TRUE;

	VirtualProtect(psctFunctionHook->pOriginalFunctionAddress, TRAMPOLINE_SIZE, psctFunctionHook->dwOldProtection, &dwOldProtect);

	return TRUE;

}

BOOL InstallAllHooks() {

	InstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateUserProcess));
	InstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateProcess));
	InstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateProcessEx));
	InstallHook(&(sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemory));
	InstallHook(&(sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemoryEx));

	return TRUE;

}

BOOL InitializeHookStruct(PNTAPI_HOOK psctFunctionHook, LPCSTR szProcName, PVOID pHookAddress) {

	NTAPI_HOOK sctTempFunctionHook = { 0 };

	PVOID pProcAddress = GetProcAddress(GetModuleHandleA("NTDLL.DLL"), szProcName);
	if (pProcAddress == NULL) {
		printf("[-] Cannot get proc address on function %s: %d\n", szProcName, GetLastError());
		return FALSE;
	}

	sctTempFunctionHook.pOriginalFunctionAddress = pProcAddress;
	sctTempFunctionHook.bHookInstalled = FALSE;
	sctTempFunctionHook.pJumpDestination = pHookAddress;
	memcpy(&(sctTempFunctionHook.uOriginalBytes), pProcAddress, TRAMPOLINE_SIZE);
	sctTempFunctionHook.wSSN = *((PBYTE)pProcAddress + 4);

	*psctFunctionHook = sctTempFunctionHook;

	return TRUE;

}

BOOL BuildHooksStruct() {

	NTAPI_HOOK sctNtapiHook_NtCreateUserProcess = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateUserProcess, "NtCreateUserProcess", &NtCreateUserProcess_hook)) {
		printf("[-] Error initializing NtCreateUserProcess hook\n");
	}
	sctSSN.wNtCreateUserProcess = sctNtapiHook_NtCreateUserProcess.wSSN;
	sctNtapiHooks.sctNtapiHook_NtCreateUserProcess = sctNtapiHook_NtCreateUserProcess;


	NTAPI_HOOK sctNtapiHook_NtCreateProcess = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateProcess, "NtCreateProcess", &NtCreateProcess_hook)) {
		printf("[-] Error initializing NtCreateProcess hook\n");
	}
	sctSSN.wNtCreateProcess = sctNtapiHook_NtCreateProcess.wSSN;
	sctNtapiHooks.sctNtapiHook_NtCreateProcess = sctNtapiHook_NtCreateProcess;


	NTAPI_HOOK sctNtapiHook_NtCreateProcessEx = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateProcessEx, "NtCreateProcessEx", &NtCreateProcessEx_hook)) {
		printf("[-] Error initializing NtCreateProcessEx hook\n");
	}
	sctSSN.wNtCreateProcessEx = sctNtapiHook_NtCreateProcessEx.wSSN;
	sctNtapiHooks.sctNtapiHook_NtCreateProcessEx = sctNtapiHook_NtCreateProcessEx;


	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemory = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtAllocateVirtualMemory, "NtAllocateVirtualMemory", &NtAllocateVirtualMemory_hook)) {
		printf("[-] Error initializing NtAllocateVirtualMemory hook\n");
	}
	sctSSN.wNtAllocateVirtualMemory = sctNtapiHook_NtAllocateVirtualMemory.wSSN;
	sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemory = sctNtapiHook_NtAllocateVirtualMemory;


	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemoryEx = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx", &NtAllocateVirtualMemoryEx_hook)) {
		printf("[-] Error initializing NtAllocateVirtualMemoryEx hook\n");
	}
	sctSSN.wNtAllocateVirtualMemoryEx = sctNtapiHook_NtAllocateVirtualMemoryEx.wSSN;
	sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemoryEx = sctNtapiHook_NtAllocateVirtualMemoryEx;

	return TRUE;

}

BOOL UninstallHook(PNTAPI_HOOK psctFunctionHook) {
	
	DWORD dwOldProtect = 0;

	if (!VirtualProtect(psctFunctionHook->pOriginalFunctionAddress, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		printf("[-] Cannot change page protection to PAGE_EXECUTE_READWRITE: %d\n", GetLastError());
		return FALSE;
	}

	memcpy(psctFunctionHook->pOriginalFunctionAddress, psctFunctionHook->uOriginalBytes, TRAMPOLINE_SIZE);
	psctFunctionHook->bHookInstalled = FALSE;

	VirtualProtect(psctFunctionHook->pOriginalFunctionAddress, TRAMPOLINE_SIZE, psctFunctionHook->dwOldProtection, &dwOldProtect);

	return TRUE;

}

BOOL Cleanup() {

	UninstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateUserProcess));
	UninstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateProcess));
	UninstallHook(&(sctNtapiHooks.sctNtapiHook_NtCreateProcessEx));
	UninstallHook(&(sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemory));
	UninstallHook(&(sctNtapiHooks.sctNtapiHook_NtAllocateVirtualMemoryEx));

	return TRUE;

}