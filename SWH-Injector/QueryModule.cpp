#include "QueryModule.h"
#include <assert.h>
#include <fstream>
#include <string>

using namespace std;

QueryModule::QueryModule(const char * ModuleName)
{
	ifstream file(ModuleName, ios::binary | ios::in);

	if (!file.is_open())
	{
		string message = string("can not open file : ") + ModuleName;
		throw exception(message.c_str());
	}

	file.seekg(0, ios::end);

	const auto fileSize = file.tellg();
	file.seekg(0, ios::beg);

	auto pFileBuffer = new BYTE[fileSize];
	file.read((char*)pFileBuffer, fileSize);
	
	file.close();

	//Getting section info
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		string message = string(ModuleName) + "is a bad PE file";
		throw exception(message.c_str());
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD64)pFileBuffer);
	assert(pNtHeader->Signature == IMAGE_NT_SIGNATURE);

	ImageSize = pNtHeader->OptionalHeader.SizeOfImage;
	FileSize = fileSize;

	auto NumberOfSections = pNtHeader->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pNtHeader + 1);

	SECTION_INFO sectionInfo = { 0 };

	for (int i = 0; i < NumberOfSections; ++i)
	{
		auto pCurrentSectionHeader = pFirstSection + i;

		auto Characteristics = pCurrentSectionHeader->Characteristics;

		bool executable = (Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE;
		bool writable = (Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE;
		bool discardable = (Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE;
		bool non_pagable = (Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == IMAGE_SCN_MEM_NOT_PAGED;

		SECTION_INFO section = { 0 };

		section.discardable = discardable;
		section.writable = writable;
		section.non_pagable = non_pagable;
		section.executable = executable;
		section.SectionBaseOffset = pCurrentSectionHeader->VirtualAddress;
		section.SectionSize = pCurrentSectionHeader->Misc.VirtualSize;

		SectionInfo.push_back(section);
	}

	delete[] pFileBuffer;
}

QueryModule::~QueryModule()
{
}


QueryModule::SECTION_INFO QueryModule::FindSection(bool writable, bool executable, bool non_pagable, bool discardable)
{
	size_t BiggestSize = 0;
	const SECTION_INFO* SelectedSection = nullptr;

	for (const auto& section : SectionInfo)
	{
		if (section.writable == writable && section.executable == executable && section.non_pagable == non_pagable && section.discardable == discardable)
		{
			if (BiggestSize < section.SectionSize)
			{
				SelectedSection = &section;
				BiggestSize = section.SectionSize;
			}
		}
	}

	if (SelectedSection)
		return *SelectedSection;
	else
		return SECTION_INFO{ 0 };
}