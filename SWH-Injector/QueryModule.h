#pragma once
#include <Windows.h>
#include <vector>


class QueryModule
{
public:
	struct SECTION_INFO
	{
		DWORD64 SectionBaseOffset;
		SIZE_T SectionSize;
		bool writable;
		bool executable;
		bool discardable;
		bool non_pagable;
	};


	QueryModule(const char* ModuleName);
	~QueryModule();

	size_t FileSize;
	size_t ImageSize;

	SECTION_INFO FindSection(bool writable, bool executable, bool non_pagable, bool discardable);
private:
	std::vector<SECTION_INFO> SectionInfo;
};

