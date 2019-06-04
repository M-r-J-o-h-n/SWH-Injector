#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <vector>

#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_CASE_INSENSITIVE                0x00000040L

struct PageTableInfo;

class PhysicalMemoryMapper
{
public:
	PhysicalMemoryMapper();
	~PhysicalMemoryMapper();

	DWORD64 MapPhysicalMemory(LONGLONG SectionOffset, SIZE_T Size);
	ULONGLONG GetPhysicalMemorySize() { return PhysicalMemorySize; }
	ULONGLONG GetRealPhysicalMemorySize() { return RealPhysicalMemorySize; }
	void ClosePhysicalMemoryHandle();
private:
	HANDLE hPhysMem = NULL;
	ULONGLONG PhysicalMemorySize;
	ULONGLONG RealPhysicalMemorySize;
	std::vector<PVOID> MappedSections;
};

class PhysicalMemory
{
public:
	PhysicalMemory();
	~PhysicalMemory();

	void AttachTo(DWORD pid)
	{
		auto EProcess = FindEProcess(pid);
		this->TargetDirectoryBase = this->ReadVirtualMemory<DWORD64>((PUCHAR)EProcess + this->DirectoryTableBaseOffset);
	}

	void Detach()
	{
		this->TargetDirectoryBase = this->CurrentProcessDirectoryBase;
	}

	void ReadPhysicalMemoryRaw(DWORD64 Pa, PVOID Dest, SIZE_T size)
	{
		memcpy(Dest, PhysicalMemoryBegin + Pa, size);
	}

	template<typename T>
	T& ReadPhysicalMemory(DWORD64 Pa)
	{
		return *(T*)(PhysicalMemoryBegin + Pa);
	}

	template<typename T>
	T ReadVirtualMemory(PVOID From)
	{
		char Buffer[sizeof(T)];
		this->ReadVirtualMemoryInternal(From, Buffer, sizeof(T));
		return *(T*)(Buffer);
	}

	template<typename T>
	void WriteVirtualMemory(PVOID To, const T& Data)
	{
		this->WriteVirtualMemoryInternal((PVOID)&Data, To, sizeof(T));
	}

	SIZE_T WriteVirtualMemoryRaw(PVOID To, PVOID Data, SIZE_T size)
	{
		return this->WriteVirtualMemoryInternal(Data, To, size);
	}

private:
	PhysicalMemoryMapper PhysMemMapper;

	PVOID MappedBase;

	PUCHAR PhysicalMemoryBegin;
	ULONGLONG PhysicalMemorySize;

	DWORD64 TargetDirectoryBase;

	DWORD64 CurrentProcessDirectoryBase;
	DWORD64 CurrentProcessEProcess;

	SIZE_T UniqueProcessIdOffset;
	SIZE_T DirectoryTableBaseOffset;
	SIZE_T ActiveProcessLinksOffset;
	SIZE_T BaseAddressOffset;
	SIZE_T NameOffset;

	NTSTATUS CreationStatus;

	SIZE_T ReadVirtualMemoryInternal(PVOID Src, PVOID Dst, SIZE_T Size);
	SIZE_T WriteVirtualMemoryInternal(PVOID Src, PVOID Dst, SIZE_T Size);
	void IterPhysRegion(PVOID StartVa, SIZE_T Size, std::function<void(PVOID Va, uint64_t, SIZE_T)> Fn);
	uint64_t VirtToPhys(PVOID Va);
	PageTableInfo QueryPageTableInfo(PVOID Va);
	DWORD64 FindEProcess(DWORD64 Pid);
	DWORD64 GetRandomProcessDirBase();
};

#pragma pack(push, 1)
typedef union CR3_
{
	uint64_t value;
	struct
	{
		uint64_t ignored_1 : 3;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t ignored_2 : 7;
		uint64_t pml4_p : 40;
		uint64_t reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	uint64_t value;
	void *pointer;
	struct
	{
		uint64_t offset : 12;
		uint64_t pt_index : 9;
		uint64_t pd_index : 9;
		uint64_t pdpt_index : 9;
		uint64_t pml4_index : 9;
		uint64_t reserved : 16;
	};
} VIRT_ADDR;

typedef uint64_t PHYS_ADDR;

typedef union PML4E_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t ignored_1 : 1;
		uint64_t reserved_1 : 1;
		uint64_t ignored_2 : 4;
		uint64_t pdpt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pd_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	uint64_t value;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t page_size : 1;
		uint64_t ignored_2 : 4;
		uint64_t pt_p : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PDE;

typedef union PTE_
{
	uint64_t value;
	VIRT_ADDR vaddr;
	struct
	{
		uint64_t present : 1;
		uint64_t rw : 1;
		uint64_t user : 1;
		uint64_t write_through : 1;
		uint64_t cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t pat : 1;
		uint64_t global : 1;
		uint64_t ignored_1 : 3;
		uint64_t page_frame : 40;
		uint64_t ignored_3 : 11;
		uint64_t xd : 1;
	};
} PTE;

#pragma pack(pop)

struct PageTableInfo
{
	PML4E* Pml4e;
	PDPTE* Pdpte;
	PDE* Pde;
	PTE* Pte;
};


struct RTL_PROCESS_MODULE_INFORMATION
{
	unsigned int Section;
	void* MappedBase;
	void* ImageBase;
	unsigned int ImageSize;
	unsigned int Flags;
	unsigned short LoadOrderIndex;
	unsigned short InitOrderIndex;
	unsigned short LoadCount;
	unsigned short OffsetToFileName;
	char FullPathName[256];
};

struct RTL_PROCESS_MODULES
{
	unsigned int NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[0];
};

struct SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[0];
};


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,  // used to be SystemLoadAndCallImage
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformationNative,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation,
	SystemLoadGdiDriverInSystemSpaceInformation,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHanfleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchDogTimerHandler,
	SystemWatchDogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWo64SharedInformationObosolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPathInformation,
	SystemVerifierFaultsInformation,
	MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _POOL_HEADER
{
	union
	{
		struct
		{
#if defined(_AMD64_)
			ULONG	PreviousSize : 8;
			ULONG	PoolIndex : 8;
			ULONG	BlockSize : 8;
			ULONG	PoolType : 8;
#else
			USHORT	PreviousSize : 9;
			USHORT	PoolIndex : 7;
			USHORT	BlockSize : 9;
			USHORT	PoolType : 7;
#endif
		};
		ULONG	Ulong1;
	};
#if defined(_WIN64)
	ULONG	PoolTag;
#endif
	union
	{
#if defined(_WIN64)
		void	*ProcessBilled;
#else
		ULONG	PoolTag;
#endif
		struct
		{
			USHORT	AllocatorBackTraceIndex;
			USHORT	PoolTagHash;
		};
	};
} POOL_HEADER, *PPOOL_HEADER;