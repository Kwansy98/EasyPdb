#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")


//Thanks mambda
//https://bitbucket.org/mambda/pdb-parser/src/master/
struct PDBHeader7
{
	char signature[0x20];
	int page_size;
	int allocation_table_pointer;
	int file_page_count;
	int root_stream_size;
	int reserved;
	int root_stream_page_number_list_number;
};

struct RootStream7
{
	int num_streams;
	int stream_sizes[1]; //num_streams
};

struct GUID_StreamData
{
	int ver;
	int date;
	int age;
	GUID guid;
};

struct PdbInfo
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age;
	char	PdbFileName[1];
};

#define EZ_PDB_BASE_OF_DLL (DWORD64)0x10000000

typedef struct _EZPDB
{
	char szModulePath[MAX_PATH];
	char szModuleName[MAX_PATH];
	char szSymbolServerUrl[1024];

	char szPdbPath[MAX_PATH];
	char szDllFile[MAX_PATH];
	BOOL ReDownload;
	DWORD64 SymbolTable;
	DWORD Filesize;
	HANDLE hProcess;
	HANDLE hPdbFile;
}EZPDB, * PEZPDB;




DWORD EzInitPdb(
	OUT PEZPDB Pdb,
	IN LPCSTR szModulePath,
	IN LPCSTR szModuleName,
	IN BOOL Download,
	IN OPTIONAL LPCSTR szSymbolServerUrl,
	IN OPTIONAL LPCSTR szPdbDownloadDirectory
);

DWORD EzLoadPdb(PEZPDB Pdb);

BOOL EzGetRva(PEZPDB Pdb, LPCSTR SymName, DWORD* Rva);
BOOL EzGetOffset(PEZPDB Pdb, LPCSTR StructName, LPCWSTR PropertyName, DWORD* OffsetOut);

VOID EzPdbUnload(PEZPDB Pdb);