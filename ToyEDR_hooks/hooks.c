#include "hooks.h"

BOOL SendPidToPipe(DWORD dwPid) {

    BOOL bSTATE = TRUE;
    HANDLE hPipe = NULL;
    DWORD dwBytesWritten = 0;

    for (;;) {

        OutputDebugStringA("[*] Trying to connect to named pipe\n");

        hPipe = CreateFileW(NAMED_PIPE_NAME, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        if (GetLastError() != ERROR_PIPE_BUSY) {
            OutputDebugStringA("[-] Error connecting to named pipe\n");
            bSTATE = FALSE; goto _EndOfFunc;
        }

        if (!WaitNamedPipeW(NAMED_PIPE_NAME, 500)) {
            OutputDebugStringA("[-] Pipe stayed busy for 500 ms, exiting\n");
            bSTATE = FALSE; goto _EndOfFunc;
        }

    }

    OutputDebugStringA("[+] Connected to named pipe\n");
    OutputDebugStringA("[*] Sending PID to pipe...\n");

    if (!WriteFile(hPipe, &dwPid, sizeof(DWORD), &dwBytesWritten, NULL) || dwBytesWritten != sizeof(DWORD)) {
        OutputDebugStringA("[-] Error writing PID to pipe\n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    OutputDebugStringA("[+] Success writing PID to pipe\n");

_EndOfFunc:
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    OutputDebugStringA("[*] Exiting thread\n");

    return bSTATE;

}

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
    NTSTATUS STATUS = CallSyscall(_Out_ ProcessHandle,
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

    if (NT_SUCCESS(STATUS)) {

        OutputDebugStringA("[*] Process created successfully\n");
        SendPidToPipe(GetProcessId(*ProcessHandle));

    }

    return STATUS;
}


NTSTATUS
NTAPI
NtCreateProcess_hook(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle
) {

    OutputDebugStringA("[*] Entering NtCreateProcess\n");

    wSystemCall = sctSSN.wNtCreateProcess;
    NTSTATUS STATUS = CallSyscall(
        _Out_ ProcessHandle,
        _In_ DesiredAccess,
        _In_opt_ ObjectAttributes,
        _In_ ParentProcess,
        _In_ InheritObjectTable,
        _In_opt_ SectionHandle,
        _In_opt_ DebugPort,
        _In_opt_ TokenHandle
    );

    if (NT_SUCCESS(STATUS)) {

        OutputDebugStringA("[*] Process created successfully\n");
        SendPidToPipe(GetProcessId(*ProcessHandle));

    }

    return STATUS;
}


NTSTATUS
NTAPI
NtCreateProcessEx_hook(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
) {

    OutputDebugStringA("[*] Entering NtCreateProcessEx\n");

    wSystemCall = sctSSN.wNtCreateProcessEx;
    NTSTATUS STATUS = CallSyscall(
        _Out_ ProcessHandle,
        _In_ DesiredAccess,
        _In_opt_ ObjectAttributes,
        _In_ ParentProcess,
        _In_ Flags, // PROCESS_CREATE_FLAGS_*
        _In_opt_ SectionHandle,
        _In_opt_ DebugPort,
        _In_opt_ TokenHandle,
        _Reserved_ Reserved // JobMemberLevel
    );

    if (NT_SUCCESS(STATUS)) {

        OutputDebugStringA("[*] Process created successfully\n");
        SendPidToPipe(GetProcessId(*ProcessHandle));

    }

    return STATUS;
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