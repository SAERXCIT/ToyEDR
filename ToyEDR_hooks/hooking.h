#pragma once
#include "common.h"
#include "hooks.h"

#ifdef _WIN64
#define TRAMPOLINE_SIZE 13
#define PATCH_OFFSET 2
#else
#define TRAMPOLINE_SIZE 7
#define PATCH_OFFSET 1
#endif

typedef struct _NTAPI_HOOK {

	PVOID	pOriginalFunctionAddress;
	PVOID	pJumpDestination;
	DWORD	dwOldProtection;
	WORD	wSSN;
	BYTE	uOriginalBytes[TRAMPOLINE_SIZE];
	BOOL	bHookInstalled;

} NTAPI_HOOK, *PNTAPI_HOOK;

typedef struct _NTAPI_HOOKS {
	
	NTAPI_HOOK sctNtapiHook_NtCreateUserProcess;
	NTAPI_HOOK sctNtapiHook_NtCreateProcess;
	NTAPI_HOOK sctNtapiHook_NtCreateProcessEx;
	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemory;
	NTAPI_HOOK sctNtapiHook_NtAllocateVirtualMemoryEx;

} NTAPI_HOOKS, * PNTAPI_HOOKS;

BOOL BuildHooksStruct(PNTAPI_HOOKS psctFunctionHooks);
BOOL InstallAllHooks(NTAPI_HOOKS sctFunctionHooks);