#include "PhysicalMemory.h"
#include <memory>
#include <assert.h>
#include <ntstatus.h>
#include <intrin.h>

extern "C" NTSTATUS NTAPI	ZwMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);

extern "C" NTSTATUS NTAPI	ZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

extern "C" NTSTATUS WINAPI NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

template<typename SYS_TYPE>
std::unique_ptr<SYS_TYPE>
QueryInfo(
	__in SYSTEM_INFORMATION_CLASS sysClass
)
{
	size_t size = sizeof(RTL_PROCESS_MODULES) + 0x1000;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	void* info = malloc(size);
	if (!info)
		return std::unique_ptr<SYS_TYPE>(nullptr);

	for (; STATUS_INFO_LENGTH_MISMATCH == status; size *= 2)
	{
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)sysClass,
			info,
			size,
			nullptr);

		info = realloc(info, size * 2);
		if (!info)
			break;
	}

	std::unique_ptr<SYS_TYPE> r_info = std::unique_ptr<SYS_TYPE>(static_cast<SYS_TYPE*>(info));
	return r_info;
}

static DWORD64 UserGetNtBase()
{
	auto module_info = QueryInfo<RTL_PROCESS_MODULES>(SystemModuleInformation);

	if (module_info.get() && module_info->NumberOfModules)
		return reinterpret_cast<size_t>(module_info->Modules[0].ImageBase);
	return 0;
}

static DWORD64 UserGetModuleBase(const char* module)
{
	auto module_info = QueryInfo<RTL_PROCESS_MODULES>(SystemModuleInformation);

	for (size_t i = 0; i < module_info->NumberOfModules; i++)
		if (!strncmp(module, module_info.get()->Modules[i].FullPathName + module_info->Modules[i].OffsetToFileName, strlen(module) + 1))
			return reinterpret_cast<size_t>(module_info->Modules[i].ImageBase);

	return 0;
}

static DWORD64 GetSystemEProcess()
{
	auto handle_info = QueryInfo<SYSTEM_HANDLE_INFORMATION>(SystemHandleInformation);
	if (!handle_info.get())
		return 0;

	for (size_t i = 0; i < handle_info->HandleCount; i++)
		if (4 == handle_info->Handles[i].ProcessId && 7 == handle_info->Handles[i].ObjectTypeNumber)
			return reinterpret_cast<size_t>(handle_info->Handles[i].Object);

	return 0;
}

HANDLE GetPhysicalMemoryHandle();

#define MEM_SIZE_5GB 5368709120;

PhysicalMemoryMapper::PhysicalMemoryMapper()
{
	hPhysMem = NULL;

	hPhysMem = GetPhysicalMemoryHandle();
	assert(hPhysMem);

	ULONGLONG physicalMemorySize;
	GetPhysicallyInstalledSystemMemory(&physicalMemorySize); // kilo bytes
	physicalMemorySize *= 1024; //bytes

	RealPhysicalMemorySize = physicalMemorySize;
	PhysicalMemorySize = physicalMemorySize + MEM_SIZE_5GB; // +5gb
}


PhysicalMemoryMapper::~PhysicalMemoryMapper()
{
	if (hPhysMem)
	{
		CloseHandle(hPhysMem);
		hPhysMem = NULL;
	}

	for (auto address : MappedSections)
	{
		ZwUnmapViewOfSection(GetCurrentProcess(), address);
	}
}

DWORD64 PhysicalMemoryMapper::MapPhysicalMemory(LONGLONG SectionOffset, SIZE_T Size)
{
	if (!hPhysMem)
		return NULL;

	if (PhysicalMemorySize < SectionOffset + Size)
		return NULL;

	NTSTATUS ntStatus = 0;
	LARGE_INTEGER sectionOffset; sectionOffset.QuadPart = SectionOffset;
	PVOID baseAddress = 0; // Initialize to NULL or STATUS_INVALID_PARAMETER IS RETURNED

	ntStatus = ZwMapViewOfSection(hPhysMem, GetCurrentProcess(), &baseAddress, NULL, Size, &sectionOffset, &Size, ViewShare, NULL, PAGE_READWRITE);

	if (ntStatus == STATUS_SUCCESS)
	{
		MappedSections.push_back(baseAddress);
		return (DWORD64)baseAddress;
	}
	else
	{
		return NULL;
	}
}

void PhysicalMemoryMapper::ClosePhysicalMemoryHandle()
{
	if (hPhysMem)
	{
		CloseHandle(hPhysMem);
		hPhysMem = NULL;
	}
}

PhysicalMemory::PhysicalMemory()
{
	PhysicalMemorySize = PhysMemMapper.GetPhysicalMemorySize();
	PhysicalMemoryBegin = (PUCHAR)PhysMemMapper.MapPhysicalMemory(0, PhysicalMemorySize);
	PhysMemMapper.ClosePhysicalMemoryHandle();

	assert(PhysicalMemoryBegin);

	//Windows10 1809
	UniqueProcessIdOffset = 0x02E0;
	DirectoryTableBaseOffset = 0x0028;
	ActiveProcessLinksOffset = 0x2E8;
	BaseAddressOffset = 0x3C0;
	NameOffset = 0x450;

	//These three variables have to be set before calling FindEProcess
	CurrentProcessEProcess = GetSystemEProcess(); // system eprocess
	assert(CurrentProcessEProcess);
	TargetDirectoryBase = CurrentProcessDirectoryBase = GetRandomProcessDirBase();
	assert(CurrentProcessDirectoryBase);

	//Get real values
	CurrentProcessEProcess = FindEProcess(GetCurrentProcessId());
	assert(CurrentProcessEProcess);
	TargetDirectoryBase = CurrentProcessDirectoryBase = ReadVirtualMemory<DWORD64>((PUCHAR)CurrentProcessEProcess + DirectoryTableBaseOffset);
	assert(CurrentProcessEProcess);
}


PhysicalMemory::~PhysicalMemory()
{
}

SIZE_T PhysicalMemory::ReadVirtualMemoryInternal(PVOID Src, PVOID Dst, SIZE_T Size)
{
	PUCHAR It = (PUCHAR)Dst;
	SIZE_T BytesRead = 0;

	this->IterPhysRegion(Src, Size, [&](PVOID Va, uint64_t Pa, SIZE_T Sz)
	{
		if (Pa)
		{
			BytesRead += Sz;
			memcpy(It, PhysicalMemoryBegin + Pa, Sz);
			It += Sz;
		}
	});

	return BytesRead;
}

SIZE_T PhysicalMemory::WriteVirtualMemoryInternal(PVOID Src, PVOID Dst, SIZE_T Size)
{
	PUCHAR It = (PUCHAR)Src;
	SIZE_T BytesRead = 0;

	this->IterPhysRegion(Dst, Size, [&](PVOID Va, uint64_t Pa, SIZE_T Sz)
	{
		if (Pa)
		{
			BytesRead += Sz;
			memcpy(PhysicalMemoryBegin + Pa, It, Sz);
			It += Sz;
		}
	});

	return BytesRead;
}

void PhysicalMemory::IterPhysRegion(PVOID StartVa, SIZE_T Size, std::function<void(PVOID Va, uint64_t, SIZE_T)> Fn)
{
	PUCHAR It = (PUCHAR)StartVa;
	PUCHAR End = It + Size;

	while (It < End)
	{
		SIZE_T Size = (PUCHAR)(((uint64_t)It + 0x1000) & (~0xFFF)) - It;

		if ((It + Size) > End)
			Size = End - It;

		uint64_t Pa = VirtToPhys(It);

		Fn(It, Pa, Size);

		It += Size;
	}
}

uint64_t PhysicalMemory::VirtToPhys(PVOID Va)
{
	auto Info = QueryPageTableInfo(Va);

	if (!Info.Pde)
		return 0;

	uint64_t Pa = 0;

	if (Info.Pde->page_size)
	{
		Pa = PFN_TO_PAGE(Info.Pde->pt_p);
		Pa += (uint64_t)Va & (0x200000 - 1);
	}
	else
	{
		if (!Info.Pte)
			return 0;
		Pa = PFN_TO_PAGE(Info.Pte->page_frame);
		Pa += (uint64_t)Va & (0x1000 - 1);
	}
	return Pa;
}

PageTableInfo PhysicalMemory::QueryPageTableInfo(PVOID Va)
{
	PageTableInfo Pi = { 0,0,0,0 };

	VIRT_ADDR Addr = { (uint64_t)Va };
	PTE_CR3 Cr3 = { TargetDirectoryBase };

	{
		uint64_t a = PFN_TO_PAGE(Cr3.pml4_p) + sizeof(PML4E) * Addr.pml4_index;
		if (a > this->PhysicalMemorySize)
			return Pi;
		PML4E& e = ReadPhysicalMemory<PML4E>(a);
		if (!e.present)
			return Pi;
		Pi.Pml4e = &e;
	}
	{
		uint64_t a = PFN_TO_PAGE(Pi.Pml4e->pdpt_p) + sizeof(PDPTE) * Addr.pdpt_index;
		if (a > this->PhysicalMemorySize)
			return Pi;
		PDPTE& e = ReadPhysicalMemory<PDPTE>(a);
		if (!e.present)
			return Pi;
		Pi.Pdpte = &e;
	}
	{
		uint64_t a = PFN_TO_PAGE(Pi.Pdpte->pd_p) + sizeof(PDE) * Addr.pd_index;
		if (a > this->PhysicalMemorySize)
			return Pi;
		PDE& e = ReadPhysicalMemory<PDE>(a);
		if (!e.present)
			return Pi;
		Pi.Pde = &e;
		if (Pi.Pde->page_size)
			return Pi;
	}
	{
		uint64_t a = PFN_TO_PAGE(Pi.Pde->pt_p) + sizeof(PTE) * Addr.pt_index;
		if (a > this->PhysicalMemorySize)
			return Pi;
		PTE& e = ReadPhysicalMemory<PTE>(a);
		if (!e.present)
			return Pi;
		Pi.Pte = &e;
	}
	return Pi;
}

DWORD64 PhysicalMemory::FindEProcess(DWORD64 Pid)
{
	uint64_t EProcess = this->CurrentProcessEProcess;
	
	do
	{
		if (this->ReadVirtualMemory<uint64_t>((PUCHAR)EProcess + this->UniqueProcessIdOffset) == Pid)
			return EProcess;

		LIST_ENTRY Le = this->ReadVirtualMemory<LIST_ENTRY>((PUCHAR)EProcess + this->ActiveProcessLinksOffset);
		EProcess = (uint64_t)Le.Flink - this->ActiveProcessLinksOffset;
	} while (EProcess != this->CurrentProcessEProcess);

	return 0;
}

//Thank you waryas for this awesome function.
DWORD64 PhysicalMemory::GetRandomProcessDirBase()
{
	auto isAscii = [](int c) -> int
	{
		return ((c >= 'A' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '.' || c == '@' || c == '_' || c == '?');
	};
	auto isPrintable = [&](uint32_t uint32) -> bool
	{
		if ((isAscii((uint32 >> 24) & 0xFF)) && (isAscii((uint32 >> 16) & 0xFF)) && (isAscii((uint32 >> 8) & 0xFF)) &&
			(isAscii((uint32) & 0xFF)))
			return true;
		else
			return false;
	};
	auto ScanPoolTag = [&](const char* tag_char, std::function<bool(uint64_t)> scan_callback) -> bool
	{
		uint32_t tag = (
			tag_char[0] |
			tag_char[1] << 8 |
			tag_char[2] << 16 |
			tag_char[3] << 24
			);


		for (auto i = 0ULL; i < PhysMemMapper.GetRealPhysicalMemorySize(); i += 0x1000) {
			if (PhysMemMapper.GetRealPhysicalMemorySize() < i + 0x1000)
				continue;

			const uint8_t* lpCursor = PhysicalMemoryBegin + i;
			uint32_t previousSize = 0;
			while (true) {
				auto pPoolHeader = (PPOOL_HEADER)lpCursor;
				auto blockSize = (pPoolHeader->BlockSize << 4);
				auto previousBlockSize = (pPoolHeader->PreviousSize << 4);

				if (previousBlockSize != previousSize ||
					blockSize == 0 ||
					blockSize >= 0xFFF ||
					!isPrintable(pPoolHeader->PoolTag & 0x7FFFFFFF))
					break;

				previousSize = blockSize;

				if (tag == pPoolHeader->PoolTag & 0x7FFFFFFF)
					if (scan_callback((uint64_t)(lpCursor - PhysicalMemoryBegin)))
						return true;
				lpCursor += blockSize;
				if ((lpCursor - (PhysicalMemoryBegin + i)) >= 0x1000)
					break;
			}
		}

		return false;
	};

	uint64_t DirBase = 0;

	char EXE[] = ".exe";
	auto length = strlen(EXE);

	//eprocess UCHAR ImageFileName[15];  
	auto FindProcessName = [&](const char* Str) -> const char*
	{
		const char* TempName = nullptr;

		for (int i = 0; i < 15; ++i)
		{
			if (Str[i] == EXE[0])
			{
				int k = 0;
				for (; k < length; ++k)
				{
					if (Str[i + k] != EXE[k])
						break;
				}

				if (k == length)
				{
					TempName = Str + i;
					break;
				}
			}
		}

		if (TempName)
		{
			while (isAscii(*TempName))
				--TempName;

			return ++TempName;
		}

		return nullptr;
	};

	auto result = ScanPoolTag("Proc", [&](uint64_t address) -> bool
	{
		bool found = false;
		char buffer[0xFFFF];

		uint64_t PhysicalEprocess = 0;

		ReadPhysicalMemoryRaw(address, buffer, sizeof(buffer));

		for (char* ptr = buffer; (uint64_t)ptr - (uint64_t)buffer <= sizeof(buffer); ptr++)
		{
			const char* nameptr = nullptr;
			if (nameptr = FindProcessName(ptr))
			{
				PhysicalEprocess = address + (uint64_t)nameptr - (uint64_t)buffer - NameOffset;
				found = true;
				break;
			}
		}

		if (found)
		{
			uint64_t pid = ReadPhysicalMemory<uint64_t>(PhysicalEprocess + UniqueProcessIdOffset);

			if (pid)
			{
				DirBase = ReadPhysicalMemory<uint64_t>(PhysicalEprocess + DirectoryTableBaseOffset);
				return true;
			}
		}

		return false;
	});

	if (result)
		return DirBase;

	return 0;
}
