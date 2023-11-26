#include "hooks.h"

NTSTATUS
NTAPI
NtCreateUserProcess_hook(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
) {

    OutputDebugStringA("[*] Entering NtCreateUserProcess\n");

    wSystemCall = sctSSN.wNtCreateUserProcess;
    return CallSyscall(_Out_ ProcessHandle,
        _Out_  ThreadHandle,
        _In_  ProcessDesiredAccess,
        _In_  ThreadDesiredAccess,
        _In_opt_  ProcessObjectAttributes,
        _In_opt_  ThreadObjectAttributes,
        _In_  ProcessFlags,
        _In_  ThreadFlags,
        _In_opt_  ProcessParameters,
        _Inout_  CreateInfo,
        _In_opt_  AttributeList
    );

}

NTSTATUS
NTAPI
NtAllocateVirtualMemory_hook(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
) {

    // Infinite loop in OutputDebugStringA...
    // OutputDebugStringA("[*] Entering NtAllocateVirtualMemory\n");

    if (Protect == PAGE_EXECUTE_READWRITE) {
        OutputDebugStringA("[!] RWX page detected! Terminating process...\n");
        ExitProcess(-1);
    }

    wSystemCall = sctSSN.wNtAllocateVirtualMemory;
    return CallSyscall(_In_ ProcessHandle,
        _Inout_ BaseAddress,
        _In_ ZeroBits,
        _Inout_ RegionSize,
        _In_ AllocationType,
        _In_ Protect);

}

NTSTATUS
NTAPI
NtAllocateVirtualMemoryEx_hook(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
) {

    OutputDebugStringA("[*] Entering NtAllocateVirtualMemoryEx\n");

    wSystemCall = sctSSN.wNtAllocateVirtualMemoryEx;
    return CallSyscall(_In_ ProcessHandle,
        _Inout_ BaseAddress,
        _Inout_ RegionSize,
        _In_ AllocationType,
        _In_ PageProtection,
        _Inout_updates_opt_(ExtendedParameterCount) ExtendedParameters,
        _In_ ExtendedParameterCount);

}