#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "ezpdb.hpp"


int main()
{
	std::string ntos_path = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
	ez::pdb ntos_pdb = ez::pdb(ntos_path, "https://msdl.szdyg.cn/download/symbols");
	if (ntos_pdb.init())
	{
		int rva_ntclose = ntos_pdb.get_rva("NtClose");
		printf("nt!NtClose = %x\n", rva_ntclose);
	}

	std::string ntdll_path = std::string(std::getenv("systemroot")) + "\\System32\\ntdll.dll";
	ez::pdb ntdll_pdb = ez::pdb(ntdll_path, "https://msdl.szdyg.cn/download/symbols");
	if (ntdll_pdb.init())
	{
		int rva_ntclose = ntdll_pdb.get_rva("NtClose");
		printf("ntdll!NtClose = %x\n", rva_ntclose);
	}

	system("pause");

	return 0;
}
