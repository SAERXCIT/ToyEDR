// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "hooking.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    NTAPI_HOOKS sctNtapiHooks = { 0 };

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        BuildHooksStruct(&sctNtapiHooks);
        InstallAllHooks(sctNtapiHooks);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

