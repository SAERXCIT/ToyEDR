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

BOOL InstallAllHooks(NTAPI_HOOKS sctFunctionHooks) {

	InstallHook(&(sctFunctionHooks.sctNtapiHook_NtCreateUserProcess));
	InstallHook(&(sctFunctionHooks.sctNtapiHook_NtCreateProcess));
	InstallHook(&(sctFunctionHooks.sctNtapiHook_NtCreateProcessEx));
	InstallHook(&(sctFunctionHooks.sctNtapiHook_NtAllocateVirtualMemory));
	InstallHook(&(sctFunctionHooks.sctNtapiHook_NtAllocateVirtualMemoryEx));

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

BOOL BuildHooksStruct(PNTAPI_HOOKS psctFunctionHooks) {

	NTAPI_HOOKS sctTempFunctionHooks = { 0 };

	NTAPI_HOOK sctNtapiHook_NtCreateUserProcess = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateUserProcess, "NtCreateUserProcess", &NtCreateUserProcess_hook)) {
		printf("[-] Error initializing NtCreateUserProcess hook\n");
	}
	sctSSN.wNtCreateUserProcess = sctNtapiHook_NtCreateUserProcess.wSSN;
	sctTempFunctionHooks.sctNtapiHook_NtCreateUserProcess = sctNtapiHook_NtCreateUserProcess;


	NTAPI_HOOK sctNtapiHook_NtCreateProcess = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateProcess, "NtCreateProcess", &NtCreateProcess_hook)) {
		printf("[-] Error initializing NtCreateProcess hook\n");
	}
	sctSSN.wNtCreateProcess = sctNtapiHook_NtCreateProcess.wSSN;
	sctTempFunctionHooks.sctNtapiHook_NtCreateProcess = sctNtapiHook_NtCreateProcess;


	NTAPI_HOOK sctNtapiHook_NtCreateProcessEx = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtCreateProcessEx, "NtCreateProcessEx", &NtCreateProcessEx_hook)) {
		printf("[-] Error initializing NtCreateProcessEx hook\n");
	}
	sctSSN.wNtCreateProcessEx = sctNtapiHook_NtCreateProcessEx.wSSN;
	sctTempFunctionHooks.sctNtapiHook_NtCreateProcessEx = sctNtapiHook_NtCreateProcessEx;


	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemory = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtAllocateVirtualMemory, "NtAllocateVirtualMemory", &NtAllocateVirtualMemory_hook)) {
		printf("[-] Error initializing NtAllocateVirtualMemory hook\n");
	}
	sctSSN.wNtAllocateVirtualMemory = sctNtapiHook_NtAllocateVirtualMemory.wSSN;
	sctTempFunctionHooks.sctNtapiHook_NtAllocateVirtualMemory = sctNtapiHook_NtAllocateVirtualMemory;


	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemoryEx = { 0 };
	if (!InitializeHookStruct(&sctNtapiHook_NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx", &NtAllocateVirtualMemoryEx_hook)) {
		printf("[-] Error initializing NtAllocateVirtualMemoryEx hook\n");
	}
	sctSSN.wNtAllocateVirtualMemoryEx = sctNtapiHook_NtAllocateVirtualMemoryEx.wSSN;
	sctTempFunctionHooks.sctNtapiHook_NtAllocateVirtualMemoryEx = sctNtapiHook_NtAllocateVirtualMemoryEx;

	*psctFunctionHooks = sctTempFunctionHooks;
	
	return TRUE;

}