#include <Windows.h>
#include <iostream>	
#include <TlHelp32.h>
#include <assert.h>
#include <shlobj_core.h>
#include <fstream>
#include <string>
#include <time.h>
#include "PhysicalMemory.h"
#include "HookProcCallBack.h"
#include "QueryModule.h"

using namespace std;

DWORD FindPid(const wchar_t* ProcessName)
{
	HANDLE hSnap;
	DWORD pid = 0;
	PROCESSENTRY32W ProcInfo;
	ProcInfo.dwSize = sizeof(ProcInfo);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32FirstW(hSnap, &ProcInfo);
	do {
		if (!wcscmp(ProcInfo.szExeFile, ProcessName)) {
			pid = (ProcInfo.th32ProcessID);
			break;
		}
	} while (Process32NextW(hSnap, &ProcInfo));
	CloseHandle(hSnap);

	return pid;
}

string GetRandomString(int length)
{
	string str;
	
	srand(time(nullptr));

	for (int i = 0; i < length; ++i)
	{
		auto random = rand();
		char value;

		if (random % 2)
		{
			value = random % 26 + 65;  //string 
		}
		else
		{
			value = random % 10 + 48;  //number 
		}

		str.push_back(value);
	}
	return str;
}

#pragma pack(push, 1)
struct ShellCode
{
	BYTE leaMapInfo[3] = { 0x48, 0x8D, 0x05 }; //  lea    rax,[rip+OffsetToMapInfo]  
	DWORD OffsetToMapInfo = 0;
	BYTE MovR9Rax[3] = { 0x49, 0x89, 0xC1 };   // mov    r9,rax
	BYTE leaCallBackFunction[3] = { 0x48, 0x8D, 0x05 }; //  lea    rax,[rip+OffsetToCallBackFunction]  
	DWORD OffsetToCallBackFunction = 0;
	BYTE JmpRax[2] = { 0xFF, 0xE0 };
};

struct DataToWrite
{
	ShellCode Shell;
	MANUAL_MAP_INFORMATION Information = { 0 };
	BYTE CallBackFunction[4096] = { 0 };
};
#pragma pack(pop)

int main(const int argc, char** argv)
{
	if (argc < 4)
	{
		cout << "[-]Invalid Command" << endl;
		getchar();
		return 0;
	}

	const char* SignedDllName = argv[1];
	const char* TargetDllName = argv[2];
	const char* TargetProcName = argv[3];

	char ShellContainerDllName[] = "ShellContainer.dll";

	cout << "[+]Preparing Injection" << endl;

	DWORD64 ShellContainerModuleBase = (DWORD64)LoadLibraryA(ShellContainerDllName);
	assert(ShellContainerModuleBase);

	SIZE_T Container_RWX_RVA = 0;
	SIZE_T Container_RWX_SIZE = 0;

	//Get container dll section info
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ShellContainerModuleBase;

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD64)ShellContainerModuleBase);
		assert(pNtHeader->Signature == IMAGE_NT_SIGNATURE);

		auto NumberOfSections = pNtHeader->FileHeader.NumberOfSections;

		PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pNtHeader + 1);

		for (int i = 0; i < NumberOfSections; ++i)
		{
			auto pCurrentSectionHeader = pFirstSection + i;

			auto Characteristics = pCurrentSectionHeader->Characteristics;

			bool executable = (Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE;
			bool writable = (Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE;

			if (executable && writable) {
				Container_RWX_RVA = pCurrentSectionHeader->VirtualAddress;
				Container_RWX_SIZE = pCurrentSectionHeader->Misc.VirtualSize;
				assert(Container_RWX_RVA);
				assert(Container_RWX_SIZE);
				break;
			}
		}
	}

	try {
		//Check size of a section for target dll 
		QueryModule SignedDllInfo(SignedDllName);
		QueryModule TargetDllInfo(TargetDllName);

		auto Section = SignedDllInfo.FindSection(true, true, false, false);

		if (Section.SectionSize < TargetDllInfo.ImageSize)
			throw exception("[-]Can not find proper section from proxy driver");

		//Prepare for injection
		DataToWrite DATA;

		//Initialize shellcode data
		DATA.Shell.OffsetToMapInfo = (DWORD64)(&DATA.Information) - (DWORD64)(DATA.Shell.leaMapInfo) - 7; // 7 is for instrucion lengh of rax,[rip+OffsetToMapInfo]
		DATA.Shell.OffsetToCallBackFunction = (DWORD64)(DATA.CallBackFunction) - (DWORD64)(DATA.Shell.leaCallBackFunction) - 7;

		//Copy CallBack Function
		auto HookCallBackSize = (DWORD64)SubTract - (DWORD64)HookProcCallback;
		memcpy(DATA.CallBackFunction, HookProcCallback, HookCallBackSize);

		char CommuniCationPathTemp[MAX_PATH] = { 0 };
		SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, CommuniCationPathTemp);
		string sCommuniCationPath = string(CommuniCationPathTemp) + "\\" + GetRandomString(10);

		//COPY INFO
		strcpy(DATA.Information.CommunicationPath, sCommuniCationPath.c_str());
		strcpy(DATA.Information.TargetProcessName, TargetProcName);
		GetFullPathNameA(SignedDllName, sizeof(DATA.Information.SignedDllPath), DATA.Information.SignedDllPath, NULL);
		GetFullPathNameA(TargetDllName, sizeof(DATA.Information.TargetDllPath), DATA.Information.TargetDllPath, NULL);

		DATA.Information.TargetDllFileSize = TargetDllInfo.FileSize;
		DATA.Information.TargetDllImageSize = TargetDllInfo.ImageSize;
		DATA.Information.RWXSecitionOffset = Section.SectionBaseOffset;
		DATA.Information.Loaded = false;
		DATA.Information.TargetProcNameLength = strlen(TargetProcName);

		auto kerenl32 = GetModuleHandle("kernel32.dll");
		
		for (Func f : Func::_values())
		{
			DATA.Information.Functions[f._to_integral()] = GetProcAddress(kerenl32, f._to_string());
		}

		PVOID RWX_Secion_Address = (PVOID)(ShellContainerModuleBase + Container_RWX_RVA);

		//This is essential
		SIZE_T Min = 0, Max = 0;
		GetProcessWorkingSetSize(GetCurrentProcess(), &Min, &Max);
		SetProcessWorkingSetSize(GetCurrentProcess(), Min + sizeof(DATA), Max + sizeof(DATA));

		if (!VirtualLock(RWX_Secion_Address, sizeof(DATA)))
			throw exception("[-]Locking RWX failed");

		//Initialize physical memory
		PhysicalMemory* PhysicalMem = new PhysicalMemory;
		auto writtenByte = PhysicalMem->WriteVirtualMemoryRaw(RWX_Secion_Address, &DATA, sizeof(DATA));
		delete PhysicalMem; //UnMap PhysicalMemory
		VirtualUnlock(RWX_Secion_Address, sizeof(DATA));

		if (writtenByte != sizeof(DATA))
			throw exception("[-]Writing Data on RWX failed");

		//Prepare for injection

		//Check if communication file exists, if it exists, delete
		auto hFile = CreateFileA(sCommuniCationPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
			DeleteFileA(sCommuniCationPath.c_str());
		}

		auto hHook = SetWindowsHookExA(WH_KEYBOARD, (HOOKPROC)(RWX_Secion_Address), (HMODULE)ShellContainerModuleBase, 0);

		if (!hHook)
		{
			string error = "[-]Setting hook failed : "; error += to_string(GetLastError());
			throw exception(error.c_str());
		}

		cout << "[+]Prepartion is finished, Waiting for " << TargetProcName  << "..." << endl;
		cout << "[+]Press Insert key to inject the dll " << endl;

		Debug_Info result = Debug_Info::FAIL;

		while (true)
		{
			hFile = CreateFileA(sCommuniCationPath.c_str(), GENERIC_READ | FILE_SHARE_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				ReadFile(hFile, &result, sizeof(result), NULL, NULL);
				CloseHandle(hFile);
				DeleteFileA(sCommuniCationPath.c_str());
				break;
			}
			Sleep(100);
		}

		UnhookWindowsHookEx(hHook);

		if (result._to_integral() == Debug_Info::SUCCESS)
			cout << "[+]Injection Succeeded!" << endl;
		else
			cout << "[-]Injection Failed, Reason : " << result._to_string() << endl;
	}
	catch (exception ex)
	{
		cout << "Exception Occured -> " << ex.what() << endl;
	}

	getchar();
	return 0;
}
