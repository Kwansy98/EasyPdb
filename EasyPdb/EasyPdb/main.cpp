#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "EzPdb.h"


int main()
{
	std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
	std::string pdbPath = EzPdbDownload(kernel);

	if (pdbPath.empty())
	{
		std::cout << "download pdb failed " << GetLastError() << std::endl;;
		return 1;
	}

	EZPDB pdb;
	if (!EzPdbLoad(pdbPath, &pdb))
	{
		std::cout << "load pdb failed " << GetLastError() << std::endl;
		return 1;
	}

	ULONG rva = EzPdbGetRva(&pdb, "NtTerminateThread");
	ULONG offset = EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"PreviousMode");
	printf("%x %x\n", rva, offset);

	EzPdbUnload(&pdb);


	return 0;
}
