#pragma once
#include <Windows.h>
#include <stdio.h>

__declspec(dllexport) BOOL InjectDLL(HANDLE hRemoteProcess, LPCSTR szDllPath);