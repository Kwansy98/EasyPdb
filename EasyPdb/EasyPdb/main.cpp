#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "EzPdb.h"

int test_ntoskrnl_pdb()
{
	EZPDB pdb = { 0 };

#ifndef _AMD64_
	PVOID OldValue = NULL;
	Wow64DisableWow64FsRedirection(&OldValue);
#endif

	// "http://msdl.blackint3.com:88/download/symbols/"
	DWORD dwError = EzInitPdbFromSymbolServer(&pdb, "C:\\Windows\\System32\\ntoskrnl.exe",NULL, NULL);

#ifndef _AMD64_
	Wow64RevertWow64FsRedirection(&OldValue);
#endif

	if (dwError != 0)
	{
		printf("init pdb error: %x\n", dwError);
		return dwError;
	}

	dwError = EzLoadPdb(&pdb);
	if (dwError != 0)
	{
		printf("load pdb error: %x\n", dwError);
		return dwError;
	}
	DWORD rva = 0;
	DWORD Offset = 0;
	if (EzGetRva(&pdb, "KeServiceDescriptorTable", &rva))
	{
		printf("KeServiceDescriptorTable: %x\n", rva);
	}

	if (EzGetRva(&pdb, "PspTerminateThreadByPointer", &rva))
	{
		printf("PspTerminateThreadByPointer: %x\n", rva);
	}

	if (EzGetOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks", &Offset))
	{
		printf("_EPROCESS.ActiveProcessLinks: %x\n", Offset);
	}
	if (EzGetOffset(&pdb, "_ETHREAD", L"ThreadListEntry", &Offset))
	{
		printf("_ETHREAD.ThreadListEntry: %x\n", Offset);
	}

	EzPdbUnload(&pdb);

	return 0;
}

int test_my_pdb()
{
	EZPDB pdb = { 0 };

#ifndef _AMD64_
	PVOID OldValue = NULL;
	Wow64DisableWow64FsRedirection(&OldValue);
#endif

	// "http://msdl.blackint3.com:88/download/symbols/"
	DWORD dwError = EzInitLocalPdb(&pdb, "C:\\Users\\dev\\Desktop\\EasyArk.sys","C:\\Users\\dev\\Desktop\\EasyArk.pdb");

#ifndef _AMD64_
	Wow64RevertWow64FsRedirection(&OldValue);
#endif

	if (dwError != 0)
	{
		printf("init pdb error: %x\n", dwError);
		return dwError;
	}

	dwError = EzLoadPdb(&pdb);
	if (dwError != 0)
	{
		printf("load pdb error: %x\n", dwError);
		return dwError;
	}
	DWORD rva = 0;
	DWORD Offset = 0;
	if (EzGetRva(&pdb, "EzEnumProcessUsingPid", &rva))
	{
		printf("EzEnumProcessUsingPid: %x\n", rva);
	}
	if (EzGetOffset(&pdb, "_EZCMD", L"InputBuffer", &Offset))
	{
		printf("_EZCMD.InputBuffer: %x\n", Offset);
	}

	EzPdbUnload(&pdb);

	return 0;
}

int main()
{
	test_my_pdb();
	printf("\n\n");
	test_ntoskrnl_pdb();
	system("pause");

	return 0;
}
