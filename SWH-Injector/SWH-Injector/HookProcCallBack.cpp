#include "HookProcCallBack.h"

#define IMR_RELOFFSET(x) (x & 0xFFF)

#undef RtlCopyMemory
#undef RtlFillMemory

using TypeRtlFillMemory = void  (__stdcall*)(void* dest, SIZE_T length, UCHAR FILL);
using TypeRtlCopyMemory = void  (__stdcall*)(void* dest, void* source, SIZE_T length);

#define DEFINE_FUNCTION(Name) auto Func_##Name = (decltype(Name)*)MapInfo->Functions[Func::Name]; auto Name = Func_##Name;
#define DEFINE_FUNCTION_WITH_TYPE(Name, Type) auto Func_##Name = (Type)MapInfo->Functions[Func::Name]; auto Name = Func_##Name;

#pragma code_seg(push, ".hook$000")
LRESULT CALLBACK HookProcCallback(int code, WPARAM wParam, LPARAM lParam, MANUAL_MAP_INFORMATION* MapInfo)
{
	if (MapInfo->Loaded)
		return 0;

	if (wParam != VK_INSERT)
		return 0;

	/*
	Do not use = {0} -> this calls memset 
	*/

	//check if current process is target process
	DEFINE_FUNCTION(LoadLibraryA);
	DEFINE_FUNCTION(GetProcAddress);
	DEFINE_FUNCTION(CreateFileA);
	DEFINE_FUNCTION(ReadFile);
	DEFINE_FUNCTION(WriteFile);
	DEFINE_FUNCTION(CloseHandle);
	DEFINE_FUNCTION(VirtualAlloc);
	DEFINE_FUNCTION(VirtualFree);
	DEFINE_FUNCTION(GetCurrentProcessId);
	DEFINE_FUNCTION(GetModuleFileNameA);
	DEFINE_FUNCTION_WITH_TYPE(RtlCopyMemory, TypeRtlCopyMemory)
	DEFINE_FUNCTION_WITH_TYPE(RtlFillMemory, TypeRtlFillMemory)

	//check current process == target process
	{
		char buffer[MAX_PATH];
		RtlFillMemory(buffer, MAX_PATH, '\0');

		char find = '\\';

		char* name = nullptr;

		GetModuleFileNameA(NULL, buffer, sizeof(buffer));

		for (int i = 0; buffer[i] != '\0'; ++i)
		{
			if (buffer[i] == find)
			{
				name = buffer + i;
			}
		}
		++name;

		int length = 0;

		while (name[length] != '\0')
			++length;

		if (length != MapInfo->TargetProcNameLength)
			return 0;

		for (int i = 0; i < length; ++i)
		{
			if (name[i] != MapInfo->TargetProcessName[i])
				return 0;
		}
	}

	Debug_Info result = Debug_Info::FAIL;
	HANDLE hTargetDll = INVALID_HANDLE_VALUE;
	DWORD64 pFileBuffer = NULL;
	DWORD64 pMappedImage = NULL;
	DWORD64 BaseAddress = NULL;
	DWORD64 EntryPoint = NULL;

	//Load Signed dll 
	auto SignedDllBaseAddress = LoadLibraryA(MapInfo->SignedDllPath);

	if (!SignedDllBaseAddress)
	{
		result = Debug_Info::SIGNED_DLL_FAILED_TO_LOAD;
		goto CLEAN_UP;
	}

	//Read Target Dll 
	hTargetDll = CreateFileA(MapInfo->TargetDllPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hTargetDll == INVALID_HANDLE_VALUE)
	{
		result = Debug_Info::TARGET_DLL_CAN_NOT_OPEN;
		goto CLEAN_UP;
	}

	pFileBuffer = (DWORD64)VirtualAlloc(NULL, MapInfo->TargetDllFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pMappedImage = (DWORD64)VirtualAlloc(NULL, MapInfo->TargetDllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pFileBuffer || !pMappedImage)
	{
		result = Debug_Info::VIRTUALALLOC_FAILED;
		goto CLEAN_UP;
	}

	if (!ReadFile(hTargetDll, (LPVOID)pFileBuffer, MapInfo->TargetDllFileSize, NULL, NULL))
	{
		result = Debug_Info::TARGET_DLL_CAN_NOT_READ;
		goto CLEAN_UP;
	}

	BaseAddress = (DWORD64)((DWORD64)SignedDllBaseAddress + MapInfo->RWXSecitionOffset);

	//prepare mapped image
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuffer + pDosHeader->e_lfanew);

		EntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint + BaseAddress;

		//Copy header
		RtlCopyMemory((LPVOID)pMappedImage, (LPVOID)pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

		//Copy section
		for (PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNtHeader + 1);
			pSection < (PIMAGE_SECTION_HEADER)(pNtHeader + 1) + pNtHeader->FileHeader.NumberOfSections;
			pSection++)
		{
			RtlCopyMemory((PVOID)(pMappedImage + pSection->VirtualAddress), (PVOID)(pFileBuffer + pSection->PointerToRawData), pSection->SizeOfRawData);
		}
	}

	//Fix imports
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedImage;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pMappedImage + pDosHeader->e_lfanew);

		auto pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pMappedImage);

		for (; pImportDesc->Name; ++pImportDesc)
		{
			const auto moduleName = (const char*)(pImportDesc->Name + pMappedImage);
			const auto moduleBase = LoadLibraryA(moduleName);
			if (!moduleBase)
			{
				result = Debug_Info::MAP_FIX_IMPORT_FAILED_TO_GET_FUNCTION;
				goto CLEAN_UP;
			}

			PIMAGE_THUNK_DATA pThunkData;
			if (pImportDesc->OriginalFirstThunk)
				pThunkData = (PIMAGE_THUNK_DATA)(pImportDesc->OriginalFirstThunk + pMappedImage);
			else
				pThunkData = (PIMAGE_THUNK_DATA)(pImportDesc->FirstThunk + pMappedImage);

			PIMAGE_THUNK_DATA64 pFuncData = (PIMAGE_THUNK_DATA64)(pImportDesc->FirstThunk + pMappedImage);

			for (; pThunkData->u1.AddressOfData; pThunkData++, pFuncData++)
			{
				DWORD64 FunctionAddress = NULL;
				if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal))
				{
					const auto ordinal = static_cast<USHORT>(pThunkData->u1.Ordinal & 0xFFFF);
					FunctionAddress = (DWORD64)GetProcAddress(moduleBase, (LPCSTR)ordinal);
				}
				else
				{
					const auto pImport = (PIMAGE_IMPORT_BY_NAME)(pThunkData->u1.AddressOfData + pMappedImage);
					const auto FuncName = pImport->Name;
					FunctionAddress = (DWORD64)GetProcAddress(moduleBase, FuncName);
				}

				if (!FunctionAddress)
				{
					result = Debug_Info::MAP_FIX_IMPORT_FAILED_TO_GET_FUNCTION;
					goto CLEAN_UP;
				}
				pFuncData->u1.Function = FunctionAddress;
			}
		}
	}

	//Relocate
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedImage;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pMappedImage + pDosHeader->e_lfanew);

		DWORD64 RelocationDelta = BaseAddress - pNtHeader->OptionalHeader.ImageBase;

		if (RelocationDelta)
		{
			ULONG RelocationSize; PIMAGE_SECTION_HEADER pSectionHeader;
			auto pRelocDir = (PIMAGE_BASE_RELOCATION)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + pMappedImage);

			void * relocation_end = reinterpret_cast<BYTE*>(pRelocDir) + RelocationSize;

			while (pRelocDir < relocation_end)
			{
				auto relocation_base = pMappedImage + pRelocDir->VirtualAddress;

				auto num_relocs = (pRelocDir->SizeOfBlock - 8) >> 1;

				auto relocation_data = reinterpret_cast<PWORD>(pRelocDir + 1);

				for (unsigned long i = 0; i < num_relocs; ++i, ++relocation_data)
				{
					//IMAGE_REL_BASED_DIR64
					auto UNALIGNED raw_address = reinterpret_cast<DWORD_PTR UNALIGNED*>(relocation_base + IMR_RELOFFSET(*relocation_data));
					*raw_address += RelocationDelta;
				}

				pRelocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocation_data);
			}
		}
	}

	//Erase Header
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMappedImage;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pMappedImage + pDosHeader->e_lfanew);

		RtlFillMemory((PVOID)pMappedImage, pNtHeader->OptionalHeader.SizeOfHeaders, '\0');
	}

	//Copy and Write image
	RtlCopyMemory((PVOID)BaseAddress, (PVOID)pMappedImage, MapInfo->TargetDllImageSize);

	//Call DllMain
	{
		using DllMainType = BOOL(*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

		auto DllMain = (DllMainType)EntryPoint;

		DllMain((HINSTANCE)BaseAddress, DLL_PROCESS_ATTACH, NULL);

		result = Debug_Info::SUCCESS;
		MapInfo->Loaded = true;
	}

	//Clean resources
CLEAN_UP:
	if (pFileBuffer)
		VirtualFree((LPVOID)pFileBuffer, MapInfo->TargetDllFileSize, MEM_RELEASE);

	if (pMappedImage)
		VirtualFree((LPVOID)pMappedImage, MapInfo->TargetDllFileSize, MEM_RELEASE);

	if (hTargetDll)
		CloseHandle(hTargetDll);

	//Create communication file
	const auto hCommunication = CreateFileA(MapInfo->CommunicationPath, GENERIC_READ | GENERIC_WRITE | FILE_SHARE_READ, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hCommunication)
	{
		WriteFile(hCommunication, &result, sizeof(result), NULL, NULL);
		CloseHandle(hCommunication);
	}

	return 0;
}
#pragma code_seg(pop)

#pragma code_seg(push, ".hook$001")

void SubTract()
{
	;
}

#pragma code_seg(pop)