#pragma once
#include <Windows.h>
#include "enum.h"

#undef RtlCopyMemory
#undef RtlFillMemory

BETTER_ENUM(Func, int,
	LoadLibraryA = 0,
	GetProcAddress,
	CreateFileA,
	ReadFile,
	WriteFile,
	CloseHandle,
	GetCurrentProcessId,
	VirtualAlloc,
	VirtualFree,
	RtlCopyMemory,
	RtlFillMemory,
	GetModuleFileNameA
)

BETTER_ENUM(Debug_Info, int,
	FAIL = 0,
	SUCCESS,
	SIGNED_DLL_FAILED_TO_LOAD,
	TARGET_DLL_CAN_NOT_OPEN,
	TARGET_DLL_CAN_NOT_READ,
	TARGET_DLL_BAD_PE_FILE,
	VIRTUALALLOC_FAILED,
	MAP_FIX_IMPORT_FAILED_TO_GET_MODULE,
	MAP_FIX_IMPORT_FAILED_TO_GET_FUNCTION,
	MAP_RLOCATION_FAILED
)

struct MANUAL_MAP_INFORMATION
{
	char CommunicationPath[MAX_PATH]; // 이걸로 통신
	char SignedDllPath[MAX_PATH];
	char TargetDllPath[MAX_PATH];
	char TargetProcessName[MAX_PATH];
	size_t TargetProcNameLength;
	size_t TargetDllFileSize;
	size_t TargetDllImageSize;
	size_t RWXSecitionOffset;
	bool Loaded;
	void* Functions[15];
};


LRESULT CALLBACK HookProcCallback(int code, WPARAM wParam, LPARAM lParam, MANUAL_MAP_INFORMATION* MapInfo);
void SubTract();

#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))