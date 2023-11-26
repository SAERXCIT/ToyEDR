# ToyEDR

A proof-of-concept project implementing various techniques and telemetry sources used by EDRs. Only user-mode sources are available.

Warning: obviously do not use in production, only on a throwaway machine, it will probably catch fire.

Techniques implemented:
    * NTAPI hooking

## ToyEDR

Main binary.

Listens on `\\.\pipe\TOYEDR_COMM` for PIDs of newly created processes in which to inject the hooking DLL.

Warning: You can probably exploit this as a low-priv user !

## ToyEDR_injector

DLL exporting a function loading another DLL in a remote process. For now only CreateRemoteThread(LoadLibraryA) is implemented.

Todo: implement manual PE injection, it's more fun.

## ToyEDR_hooks

DLL implementing various NTAPI hooks.

Hooks:
    * NtCreateUserProcess
    * NtCreateProcess
    * NtCreateProcessEx
    * NtAllocateVirtualMemory
    * NtAllocateVirtualMemoryEx

No detection logic has been implemented yet.

After executing a syscall creating process, sends the newly created PID to the main binary through the named pipe.

There's also a nice `Cleanup()` function that removes the hooks in the current process, for the attacker's convinience.
