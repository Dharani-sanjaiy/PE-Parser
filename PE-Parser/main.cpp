#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

BOOL ReadPEFile(LPCSTR lpFileName, PBYTE* pPE, SIZE_T* sPE) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pBuff = NULL;
	DWORD dwFileSize = 0;
	DWORD dwNumberOfBytes = 0;

	printf("[*] Reading %s..\n", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileA failed with error: %ld\n", GetLastError());
		return FALSE;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0) {
		printf("[-] GetFileSize failed with error: %ld\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("[-] HeapAlloc Failed with error: %ld\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytes, NULL) || dwFileSize != dwNumberOfBytes) {
		printf("[!] ReadFile() Failed with error: %ld\n", GetLastError());
		printf("[i] Bytes Read: %d out of %d\n", dwNumberOfBytes, dwFileSize);
		HeapFree(GetProcessHeap(), 0, pBuff);
		CloseHandle(hFile);
		return FALSE;
	}

	printf("[*] Done\n");

	*pPE = pBuff;
	*sPE = dwFileSize;

	CloseHandle(hFile);
	return TRUE;
}


void ParsePE(PBYTE pPE) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}

	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	printf("\n\t---------------[FILE HEADERS]---------------\n\n");

	IMAGE_FILE_HEADER ImageFileHdr = pImgNtHdr->FileHeader;
	if (ImageFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("[i] Executable file identifies as : ");

		if (ImageFileHdr.Characteristics & IMAGE_FILE_DLL)
			printf("DLL\n");
		else if (ImageFileHdr.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS\n");
		else
			printf("EXE\n");
	}

	printf("[i] File Architechture: %s\n", ImageFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("[i] Number of Sections: %d\n", ImageFileHdr.NumberOfSections);
	printf("[i] Size of the Optional Header: %d\n", ImageFileHdr.SizeOfOptionalHeader);

	printf("\n\t---------------[OPTIONAL HEADERS]---------------\n\n");

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return;
	}

	printf("[i] Size of the code section: %d\n", ImgOptHdr.SizeOfCode);
	printf("[i] Address of Code Section: 0x%p\n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);
	printf("[i] Size of Initialized Data : %d\n", ImgOptHdr.SizeOfInitializedData);
	printf("[i] Size of UnInitialized Data: %d\n", ImgOptHdr.SizeOfUninitializedData);
	printf("[i] Preferable Mapping Address: 0x%p\n", (PVOID)ImgOptHdr.ImageBase);
	printf("[i] Required Version: %d.%d\n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
	printf("[i] Address of Entry Point: 0x%p\n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
	printf("[i] Size of the image: %d\n", ImgOptHdr.SizeOfImage);
	printf("[i] File Checksum: 0x%0.8X\n", ImgOptHdr.CheckSum);
	printf("[i] Number of entries in the Data Directory array: %d\n", ImgOptHdr.NumberOfRvaAndSizes);

	printf("\n\t---------------[DIRECTORES]---------------\n\t");

	printf("\n[*] Export directory at 0x%p of Size: %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("[i] Import Directory at 0x%p of Size : %d\n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("[*] Base Relocation Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("[*] Import Address Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

	printf("\n\t---------------[SECTIONS]---------------\n\t");

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdr) + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < pImgNtHdr->FileHeader.NumberOfSections; i++) {
		printf("\n\n[#] %s : \n", (CHAR*)pImgSectionHdr->Name);
		printf("\tSize : %d\n", pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X\n", pImgSectionHdr->VirtualAddress);
		printf("\tRelocations : %d\n", pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgSectionHdr) + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	} 

}



int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("\n[!] Usage: PE-Parser.exe <FileName>\n[-] No file specified for parsing..\n");
		return EXIT_FAILURE;
	}

	printf("[*] Attempting to parse %s\n", argv[1]);

	PBYTE	pPE = NULL;
	size_t  sPE = NULL;

	if (!ReadPEFile(argv[1], &pPE, &sPE)) {
		printf("[!] Cannot read the file. Exiting with error: %ld\n",GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] Analyzing %s at 0x%p of size 0x%d\n", argv[1], pPE, sPE);

	ParsePE(pPE);

	//printf("[i] Press <Enter> to Quit..\n");
	//getchar();
	printf("[+] File parsed successfully kawkawww!!!!!!!\n");

	HeapFree(GetProcessHeap(), NULL, pPE);
	return 0;
}
