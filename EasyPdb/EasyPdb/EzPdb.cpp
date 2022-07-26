#include "EzPdb.h"

SIZE_T EzFileToMemory(LPCSTR lpszFile, PBYTE* pFileBuffer)
{
	FILE* pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = (PBYTE)malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{
		fclose(pFile);
		return 0;
	}
	SIZE_T nRead = fread(*pFileBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	if (nRead != dwFileSize)
	{
		free(*pFileBuffer);
		return 0;
	}
	return nRead;
}

const char* GetBaseName(const char* path)
{
	if (NULL == strchr(path, '\\'))
	{
		return path; // already base name
	}
	size_t len = strlen(path);
	for (size_t i = len - 1; ; i--)
	{
		if (path[i] == '\\')
		{
			return path + i + 1;
		}
	}
	return path; // make compiler happy
}

// init pdb if the pdb file exists on disk.
// if szPdbFullPath is NULL, try to get the full path from pe debug info directory.
DWORD EzInitLocalPdb(OUT PEZPDB Pdb, IN LPCSTR szDllFullPath, IN OPTIONAL LPCSTR szPdbFullPath)
{
	strcpy(Pdb->szDllBaseName, GetBaseName(szDllFullPath));
	strcpy(Pdb->szDllDir, szDllFullPath);
	Pdb->szDllDir[GetBaseName(szDllFullPath) - szDllFullPath] = NULL;
	strcpy(Pdb->szDllFullPath, szDllFullPath);
	if (szPdbFullPath)
	{
		WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
		if (GetFileAttributesExA(szPdbFullPath, GetFileExInfoStandard, &file_attr_data))
		{
			Pdb->Filesize = file_attr_data.nFileSizeLow;
			if (Pdb->Filesize)
			{
				strcpy(Pdb->szPdbPath, szPdbFullPath);
				return 0;
			}
		}
	}

	// not specify pdb full path or pdb not exists...
	// 
	// get pdb info from debug info directory

	PBYTE FileBuffer = NULL;
	SIZE_T nByte = EzFileToMemory(Pdb->szDllFullPath, &FileBuffer);
	if (nByte == 0)
	{
		return ERROR_ACCESS_DENIED;
	}
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)FileBuffer;
	IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(FileBuffer + pDos->e_lfanew);
	IMAGE_FILE_HEADER* pFile = &pNT->FileHeader;
	IMAGE_OPTIONAL_HEADER64* pOpt64 = NULL;
	IMAGE_OPTIONAL_HEADER32* pOpt32 = NULL;
	BOOL x86 = FALSE;
	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = (IMAGE_OPTIONAL_HEADER64*)(&pNT->OptionalHeader);
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = (IMAGE_OPTIONAL_HEADER32*)(&pNT->OptionalHeader);
		x86 = TRUE;
	}
	else
	{
		// neither x64 or x86
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}
	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	PBYTE ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer)
	{
		free(FileBuffer);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	memcpy(ImageBuffer, FileBuffer, x86 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);
	IMAGE_SECTION_HEADER* pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(ImageBuffer + pCurrentSectionHeader->VirtualAddress, FileBuffer + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}
	IMAGE_DATA_DIRECTORY* pDataDir = nullptr;
	if (x86)
	{
		pDataDir = &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(ImageBuffer + pDataDir->VirtualAddress);
	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		// invalid debug dir
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}
	PdbInfo* pdb_info = (PdbInfo*)(ImageBuffer + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		// invalid debug dir
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}

	strcat(Pdb->szPdbPath, pdb_info->PdbFileName);

	free(ImageBuffer);
	free(FileBuffer);

	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (!GetFileAttributesExA(Pdb->szPdbPath, GetFileExInfoStandard, &file_attr_data))
	{
		return GetLastError();
	}
	Pdb->Filesize = file_attr_data.nFileSizeLow;
	return 0;
}

// download pdb file from symbol server
// symbol server url is optional, default is https://msdl.microsoft.com/download/symbols/
// szPdbDownloadDirectory is optional too, if it it NULL, pdb will download to current directory.
// return 0 if success, or return error code if failed.
DWORD EzInitPdbFromSymbolServer(OUT PEZPDB Pdb, IN LPCSTR szDllFullPath, IN OPTIONAL LPCSTR szSymbolServerUrl, IN OPTIONAL LPCSTR szPdbDownloadDirectory)
{
	strcpy(Pdb->szDllBaseName, GetBaseName(szDllFullPath));
	strcpy(Pdb->szDllDir, szDllFullPath);
	Pdb->szDllDir[GetBaseName(szDllFullPath) - szDllFullPath] = NULL;
	if (szSymbolServerUrl)
	{
		strcpy(Pdb->szSymbolServerUrl, szSymbolServerUrl);
	}
	else
	{
		strcpy(Pdb->szSymbolServerUrl, "https://msdl.microsoft.com/download/symbols/");
	}
	strcpy(Pdb->szDllFullPath, szDllFullPath);

	// pdb download directory
	// if not specify, then pdb will download to current directory
	char szDownloadDir[MAX_PATH] = { 0 };
	if (szPdbDownloadDirectory)
	{
		strcat(szDownloadDir, szPdbDownloadDirectory);
	}
	else
	{
		if (!GetCurrentDirectoryA(sizeof(szDownloadDir), szDownloadDir))
		{
			return GetLastError();
		}
	}
	strcpy(Pdb->szPdbPath, szDownloadDir);
	if (Pdb->szPdbPath[strlen(Pdb->szPdbPath) - 1] != '\\')
	{
		strcat(Pdb->szPdbPath, "\\");
	}
	if (!CreateDirectoryA(Pdb->szPdbPath, NULL))
	{
		DWORD dwError = GetLastError();
		if (dwError != ERROR_ALREADY_EXISTS)
		{
			return dwError;
		}
	}

	// get pdb info from debug info directory
	PBYTE FileBuffer = NULL;
	SIZE_T nByte = EzFileToMemory(Pdb->szDllFullPath, &FileBuffer);
	if (nByte == 0)
	{
		return ERROR_ACCESS_DENIED;
	}
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)FileBuffer;
	IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(FileBuffer + pDos->e_lfanew);
	IMAGE_FILE_HEADER* pFile = &pNT->FileHeader;
	IMAGE_OPTIONAL_HEADER64* pOpt64 = NULL;
	IMAGE_OPTIONAL_HEADER32* pOpt32 = NULL;
	BOOL x86 = FALSE;
	if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		pOpt64 = (IMAGE_OPTIONAL_HEADER64*)(&pNT->OptionalHeader);
	}
	else if (pFile->Machine == IMAGE_FILE_MACHINE_I386)
	{
		pOpt32 = (IMAGE_OPTIONAL_HEADER32*)(&pNT->OptionalHeader);
		x86 = TRUE;
	}
	else
	{
		// neither x64 or x86
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}
	DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
	PBYTE ImageBuffer = (PBYTE)malloc(ImageSize);
	if (!ImageBuffer)
	{
		free(FileBuffer);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	memcpy(ImageBuffer, FileBuffer, x86 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);
	IMAGE_SECTION_HEADER* pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
	for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader)
	{
		if (pCurrentSectionHeader->SizeOfRawData)
		{
			memcpy(ImageBuffer + pCurrentSectionHeader->VirtualAddress, FileBuffer + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
		}
	}
	IMAGE_DATA_DIRECTORY* pDataDir = nullptr;
	if (x86)
	{
		pDataDir = &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		pDataDir = &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(ImageBuffer + pDataDir->VirtualAddress);
	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		// invalid debug dir
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}
	PdbInfo* pdb_info = (PdbInfo*)(ImageBuffer + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		// invalid debug dir
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}

	// sometimes pdb_info->PdbFileName is a abs path, sometimes is just a base name.
	// In first case, we have to calc its base name.
	strcat(Pdb->szPdbPath, GetBaseName(pdb_info->PdbFileName));

	// download pdb
	DeleteFileA(Pdb->szPdbPath);
	wchar_t w_GUID[100] = { 0 };
	if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100))
	{
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}
	char a_GUID[100]{ 0 };
	size_t l_GUID = 0;
	if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID)
	{
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NOT_SUPPORTED;
	}

	char guid_filtered[256] = { 0 };
	for (UINT i = 0; i != l_GUID; ++i)
	{
		if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') || (a_GUID[i] >= 'a' && a_GUID[i] <= 'f'))
		{
			guid_filtered[strlen(guid_filtered)] = a_GUID[i];
		}
	}

	char age[3] = { 0 };
	_itoa_s(pdb_info->Age, age, 10);

	// url
	char url[1024] = { 0 };
	strcpy(url, Pdb->szSymbolServerUrl);
	strcat(url, pdb_info->PdbFileName);
	url[strlen(url)] = '/';
	strcat(url, guid_filtered);
	strcat(url, age);
	url[strlen(url)] = '/';
	strcat(url, pdb_info->PdbFileName);

	// download
	HRESULT hr = URLDownloadToFileA(NULL, url, Pdb->szPdbPath, NULL, NULL);
	if (FAILED(hr))
	{
		free(ImageBuffer);
		free(FileBuffer);
		return ERROR_NETWORK_ACCESS_DENIED;
	}

	free(ImageBuffer);
	free(FileBuffer);
	return 0;
}

DWORD EzLoadPdb(PEZPDB Pdb)
{
	// get pdb file size
	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };
	if (!GetFileAttributesExA(Pdb->szPdbPath, GetFileExInfoStandard, &file_attr_data))
	{
		return GetLastError();
	}
	Pdb->Filesize = file_attr_data.nFileSizeLow;

	// open pdb file
	Pdb->hPdbFile = CreateFileA(Pdb->szPdbPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (Pdb->hPdbFile == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}

	// open current process
	Pdb->hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
	if (!Pdb->hProcess)
	{
		CloseHandle(Pdb->hPdbFile);
		return GetLastError();
	}

	// Initializes the symbol handler for a process
	if (!SymInitialize(Pdb->hProcess, Pdb->szPdbPath, FALSE))
	{
		CloseHandle(Pdb->hProcess);
		CloseHandle(Pdb->hPdbFile);
		return GetLastError();
	}

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING);
	//SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_LOAD_ANYTHING);

	Pdb->SymbolTable = SymLoadModuleEx(Pdb->hProcess, NULL, Pdb->szPdbPath, NULL, EZ_PDB_BASE_OF_DLL, Pdb->Filesize, NULL, NULL);
	if (!Pdb->SymbolTable)
	{
		SymCleanup(Pdb->hProcess);
		CloseHandle(Pdb->hProcess);
		CloseHandle(Pdb->hPdbFile);
		return GetLastError();
	}
	return 0;
}

BOOL EzGetRva(PEZPDB Pdb, LPCSTR SymName, DWORD* Rva)
{
	// 获取全局变量，函数的RVA

	SYMBOL_INFO si = { 0 };
	si.SizeOfStruct = sizeof(SYMBOL_INFO);
	if (!SymFromName(Pdb->hProcess, SymName, &si))
	{
		return FALSE;
	}
	*Rva = (DWORD)(si.Address - si.ModBase);
	return TRUE;
}

BOOL EzGetOffset(PEZPDB Pdb, LPCSTR StructName, LPCWSTR PropertyName, DWORD* OffsetOut)
{
	ULONG SymInfoSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
	SYMBOL_INFO* SymInfo = (SYMBOL_INFO*)malloc(SymInfoSize);
	if (!SymInfo)
	{
		return FALSE;
	}
	ZeroMemory(SymInfo, SymInfoSize);
	SymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	SymInfo->MaxNameLen = MAX_SYM_NAME;
	if (!SymGetTypeFromName(Pdb->hProcess, EZ_PDB_BASE_OF_DLL, StructName, SymInfo))
	{
		return FALSE;
	}

	TI_FINDCHILDREN_PARAMS TempFp = { 0 };
	if (!SymGetTypeInfo(Pdb->hProcess, EZ_PDB_BASE_OF_DLL, SymInfo->TypeIndex, TI_GET_CHILDRENCOUNT, &TempFp))
	{
		free(SymInfo);
		return FALSE;
	}

	ULONG ChildParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + TempFp.Count * sizeof(ULONG);
	TI_FINDCHILDREN_PARAMS* ChildParams = (TI_FINDCHILDREN_PARAMS*)malloc(ChildParamsSize);
	if (ChildParams == NULL)
	{
		free(SymInfo);
		return FALSE;
	}
	ZeroMemory(ChildParams, ChildParamsSize);
	memcpy(ChildParams, &TempFp, sizeof(TI_FINDCHILDREN_PARAMS));
	if (!SymGetTypeInfo(Pdb->hProcess, EZ_PDB_BASE_OF_DLL, SymInfo->TypeIndex, TI_FINDCHILDREN, ChildParams))
	{
		goto failed;
	}
	for (ULONG i = ChildParams->Start; i < ChildParams->Count; i++)
	{
		WCHAR* pSymName = NULL;
		DWORD Offset = 0;
		if (!SymGetTypeInfo(Pdb->hProcess, EZ_PDB_BASE_OF_DLL, ChildParams->ChildId[i], TI_GET_OFFSET, &Offset))
		{
			goto failed;
		}
		if (!SymGetTypeInfo(Pdb->hProcess, EZ_PDB_BASE_OF_DLL, ChildParams->ChildId[i], TI_GET_SYMNAME, &pSymName))
		{
			goto failed;
		}
		if (pSymName)
		{
			//wprintf(L"%x %s\n", Offset, pSymName);
			if (wcscmp(pSymName, PropertyName) == 0)
			{
				LocalFree(pSymName);
				*OffsetOut = Offset;
				free(ChildParams);
				free(SymInfo);
				return TRUE;
			}
		}
	}
failed:
	free(ChildParams);
	free(SymInfo);
	return FALSE;
}

VOID EzPdbUnload(PEZPDB Pdb)
{
	// 清理工作
	SymUnloadModule64(Pdb->hProcess, EZ_PDB_BASE_OF_DLL);
	SymCleanup(Pdb->hProcess);
	CloseHandle(Pdb->hProcess);
	CloseHandle(Pdb->hPdbFile);
}
