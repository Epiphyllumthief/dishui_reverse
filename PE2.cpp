#pragma warning(disable:4996)
#include<iostream>
#include<windows.h>
#include<winnt.h> 

int Fsize(FILE *fp){
	fseek(fp,0,SEEK_END);
	int size = ftell(fp);
	fseek(fp,0,SEEK_SET);
	return size;
}

LPVOID Get_PE(){
	FILE* fp;
	LPVOID pFileBuffer = NULL;
	//fp = fopen("C://Windows//notepad.exe","rb");
	fp =  fopen("F://notepad.exe","rb");
    int F_size = Fsize(fp);
	pFileBuffer = malloc(F_size);
	if(!pFileBuffer){
		printf("分配内存空间失败!\n");
		fclose(fp); 
		exit(0);
	}
	
	size_t read = fread(pFileBuffer,F_size,1,fp);
	if(!read){
		printf("读取文件失败\n"); 
		fclose(fp);
		exit(0);
    }
//	printf("e_magic : 0x%x\n",pDos_Header->e_magic);
//	printf("e_lfanew : 0x%x\n",pDos_Header->e_lfanew);}
	
	fclose(fp);
	return pFileBuffer;
}

int main(){
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDos_Header = NULL;
	PIMAGE_NT_HEADERS pNt_Header = NULL;
	PIMAGE_FILE_HEADER pFile_Header = NULL;

	PIMAGE_SECTION_HEADER pSection_Header = NULL; 
	
	pFileBuffer = Get_PE();
	
	pDos_Header = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	if(pDos_Header->e_magic != IMAGE_DOS_SIGNATURE){
		printf("Error,不是有效的PE文件！\n");
		free(pFileBuffer);
		exit(0);
	}
	printf("----------DOS HEADER----------\n");
	printf("e_magic : 0x%04X\n", pDos_Header->e_magic);
    printf("e_cblp : 0x%04X\n", pDos_Header->e_cblp);
    printf("e_cp : 0x%04X\n", pDos_Header->e_cp);
    printf("e_crlc : 0x%04X\n", pDos_Header->e_crlc);
    printf("e_cparhdr : 0x%04X\n", pDos_Header->e_cparhdr);
    printf("e_minalloc : 0x%04X\n", pDos_Header->e_minalloc);
    printf("e_maxalloc : 0x%04X\n", pDos_Header->e_maxalloc);
    printf("e_ss : 0x%04X\n", pDos_Header->e_ss);
    printf("e_sp : 0x%04X\n", pDos_Header->e_sp);
    printf("e_csum : 0x%04X\n", pDos_Header->e_csum);
    printf("e_ip : 0x%04X\n", pDos_Header->e_ip);
    printf("e_cs : 0x%04X\n", pDos_Header->e_cs);
    printf("e_lfarlc : 0x%04X\n", pDos_Header->e_lfarlc);
    printf("e_ovno : 0x%04X\n", pDos_Header->e_ovno);
    printf("e_res : ");
    for (int i = 0; i < 4; i++) {
        printf("0x%04X ", pDos_Header->e_res[i]);
    }printf("\n");
    printf("e_oemid : 0x%04X\n", pDos_Header->e_oemid);
    printf("e_oeminfo : 0x%04X\n", pDos_Header->e_oeminfo);
    printf("e_res2 : ");
    for (int i = 0; i < 10; i++) {
        printf("0x%04X ", pDos_Header->e_res2[i]);
    }    printf("\n");
    printf("e_lfanew : 0x%08X\n", pDos_Header->e_lfanew);
    printf("\n");
	
	
	pNt_Header = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDos_Header->e_lfanew);
	
	if(pNt_Header->Signature != IMAGE_NT_SIGNATURE){
		printf("Error,不是有效的PE文件！\n");
		free(pFileBuffer);
		exit(0); 
	}
	
	printf("----------NT HEADER----------\n");
	printf("Signature : 0x%X\n",pNt_Header->Signature);
	
	printf("----------PE HEADER----------\n");
	pFile_Header = (PIMAGE_FILE_HEADER)((DWORD)pNt_Header+0x4);
	printf("Machine : 0x%04X\n", pFile_Header->Machine);
    printf("NumberOfSections : 0x%04X\n", pFile_Header->NumberOfSections);
    printf("TimeDateStamp : 0x%08X\n", pFile_Header->TimeDateStamp);
    printf("PointerToSymbolTable : 0x%08X\n", pFile_Header->PointerToSymbolTable);
    printf("NumberOfSymbols : 0x%08X\n", pFile_Header->NumberOfSymbols);
    printf("SizeOfOptionalHeader : 0x%04X\n", pFile_Header->SizeOfOptionalHeader);
    printf("Characteristics : 0x%04X\n", pFile_Header->Characteristics);
	free(pFileBuffer);


 
    if(pFile_Header->SizeOfOptionalHeader == 0xE0){
        PIMAGE_OPTIONAL_HEADER32 pOption_Header=NULL;
        pOption_Header= (PIMAGE_OPTIONAL_HEADER32) ((DWORD)pFile_Header+IMAGE_SIZEOF_FILE_HEADER);
        printf("-----------PE32 OPTIONAL HEADER----------\n");
        printf("Magic : 0x%04X\n", pOption_Header->Magic);
        printf("MajorLinkerVersion : 0x%02X\n", pOption_Header->MajorLinkerVersion);
        printf("MinorLinkerVersion : 0x%02X\n", pOption_Header->MinorLinkerVersion);
        printf("SizeOfCode : 0x%08X\n", pOption_Header->SizeOfCode);
        printf("SizeOfInitializedData : 0x%08X\n", pOption_Header->SizeOfInitializedData);
        printf("SizeOfUninitializedData : 0x%08X\n", pOption_Header->SizeOfUninitializedData);
        printf("AddressOfEntryPoint : 0x%08X\n", pOption_Header->AddressOfEntryPoint);
        printf("BaseOfCode : 0x%08X\n", pOption_Header->BaseOfCode);
        printf("ImageBase : 0x%08X\n", pOption_Header->ImageBase);
        printf("SectionAlignment : 0x%08X\n", pOption_Header->SectionAlignment);
        printf("FileAlignment : 0x%08X\n", pOption_Header->FileAlignment);
        printf("MajorOperatingSystemVersion : 0x%04X\n", pOption_Header->MajorOperatingSystemVersion);
        printf("MinorOperatingSystemVersion : 0x%04X\n", pOption_Header->MinorOperatingSystemVersion);
        printf("MajorImageVersion : 0x%04X\n", pOption_Header->MajorImageVersion);
        printf("MinorImageVersion : 0x%04X\n", pOption_Header->MinorImageVersion);
        printf("MajorSubsystemVersion : 0x%04X\n", pOption_Header->MajorSubsystemVersion);
        printf("MinorSubsystemVersion : 0x%04X\n", pOption_Header->MinorSubsystemVersion);
        printf("Win32VersionValue : 0x%08X\n", pOption_Header->Win32VersionValue);
        printf("SizeOfImage : 0x%08X\n", pOption_Header->SizeOfImage);
        printf("SizeOfHeaders : 0x%08X\n", pOption_Header->SizeOfHeaders);
        printf("CheckSum : 0x%08X\n", pOption_Header->CheckSum);
        printf("Subsystem : 0x%04X\n", pOption_Header->Subsystem);
        printf("DllCharacteristics : 0x%04X\n", pOption_Header->DllCharacteristics);
        printf("SizeOfStackReserve : 0x%08X\n", pOption_Header->SizeOfStackReserve);
        printf("SizeOfStackCommit : 0x%08X\n", pOption_Header->SizeOfStackCommit);
        printf("SizeOfHeapReserve : 0x%08X\n", pOption_Header->SizeOfHeapReserve);
        printf("SizeOfHeapCommit : 0x%08X\n", pOption_Header->SizeOfHeapCommit);
        printf("LoaderFlags : 0x%08X\n", pOption_Header->LoaderFlags);
        printf("NumberOfRvaAndSizes : 0x%08X\n", pOption_Header->NumberOfRvaAndSizes);
    }else if(pFile_Header->SizeOfOptionalHeader == 0xF0){
        PIMAGE_OPTIONAL_HEADER64 pOption_Header=NULL;
        pOption_Header= (PIMAGE_OPTIONAL_HEADER64) ((DWORD)pFile_Header+IMAGE_SIZEOF_FILE_HEADER);
        printf("----------PE64 OPTIONAL HEDAER----------\n");
        printf("Magic : 0x%04X\n", pOption_Header->Magic);
        printf("MajorLinkerVersion : 0x%02X\n", pOption_Header->MajorLinkerVersion);
        printf("MinorLinkerVersion : 0x%02X\n", pOption_Header->MinorLinkerVersion);
        printf("SizeOfCode : 0x%08X\n", pOption_Header->SizeOfCode);
        printf("SizeOfInitializedData : 0x%08X\n", pOption_Header->SizeOfInitializedData);
        printf("SizeOfUninitializedData : 0x%08X\n", pOption_Header->SizeOfUninitializedData);
        printf("AddressOfEntryPoint : 0x%08X\n", pOption_Header->AddressOfEntryPoint);
        printf("BaseOfCode : 0x%08X\n", pOption_Header->BaseOfCode);
        printf("ImageBase : 0x%016llX\n", pOption_Header->ImageBase);
        printf("SectionAlignment : 0x%08X\n", pOption_Header->SectionAlignment);
        printf("FileAlignment : 0x%08X\n", pOption_Header->FileAlignment);
        printf("MajorOperatingSystemVersion : 0x%04X\n", pOption_Header->MajorOperatingSystemVersion);
        printf("MinorOperatingSystemVersion : 0x%04X\n", pOption_Header->MinorOperatingSystemVersion);
        printf("MajorImageVersion : 0x%04X\n", pOption_Header->MajorImageVersion);
        printf("MinorImageVersion : 0x%04X\n", pOption_Header->MinorImageVersion);
        printf("MajorSubsystemVersion : 0x%04X\n", pOption_Header->MajorSubsystemVersion);
        printf("MinorSubsystemVersion : 0x%04X\n", pOption_Header->MinorSubsystemVersion);
        printf("Win32VersionValue : 0x%08X\n", pOption_Header->Win32VersionValue);
        printf("SizeOfImage : 0x%08X\n", pOption_Header->SizeOfImage);
        printf("SizeOfHeaders : 0x%08X\n", pOption_Header->SizeOfHeaders);
        printf("CheckSum : 0x%08X\n", pOption_Header->CheckSum);
        printf("Subsystem : 0x%04X\n", pOption_Header->Subsystem);
        printf("DllCharacteristics : 0x%04X\n", pOption_Header->DllCharacteristics);
        printf("SizeOfStackReserve : 0x%016llX\n", pOption_Header->SizeOfStackReserve);
        printf("SizeOfStackCommit : 0x%016llX\n", pOption_Header->SizeOfStackCommit);
        printf("SizeOfHeapReserve : 0x%016llX\n", pOption_Header->SizeOfHeapReserve);
        printf("SizeOfHeapCommit : 0x%016llX\n", pOption_Header->SizeOfHeapCommit);
        printf("LoaderFlags : 0x%08X\n", pOption_Header->LoaderFlags);
        printf("NumberOfRvaAndSizes : 0x%08X\n", pOption_Header->NumberOfRvaAndSizes);
    }
        
    pSection_Header = (PIMAGE_SECTION_HEADER) ((DWORD)pFile_Header+pFile_Header->SizeOfOptionalHeader+0x14);
    for(int i=1;i<=pFile_Header->NumberOfSections;i++){
        printf("----------SECTION:%d HEADER----------\n",i);
        printf("name : 0x%08X   %s\n",pSection_Header->Name,pSection_Header->Name);
        printf("VirtualSize: 0x%08X\n", pSection_Header->Misc.VirtualSize);
        printf("VirtualAddress: 0x%08X\n", pSection_Header->VirtualAddress);
        printf("SizeOfRawData: 0x%08X\n", pSection_Header->SizeOfRawData);
        printf("PointerToRawData: 0x%08X\n", pSection_Header->PointerToRawData);
        printf("PointerToRelocations: 0x%08X\n", pSection_Header->PointerToRelocations);
        printf("PointerToLinenumbers: 0x%08X\n", pSection_Header->PointerToLinenumbers);
        printf("NumberOfRelocations: 0x%04X\n", pSection_Header->NumberOfRelocations);
        printf("NumberOfLinenumbers: 0x%04X\n", pSection_Header->NumberOfLinenumbers);
        printf("Characteristics: 0x%08X\n", pSection_Header->Characteristics);
        pSection_Header=(PIMAGE_SECTION_HEADER)((DWORD)pSection_Header+0x28);
    }
    return 0; 
} 