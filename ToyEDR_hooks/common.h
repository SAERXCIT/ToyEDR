#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)